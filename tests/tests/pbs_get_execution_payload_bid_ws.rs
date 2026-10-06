use std::{sync::Arc, time::Duration};

use alloy::primitives::B256;
use base64::{Engine, prelude::BASE64_STANDARD};
use cb_common::{
    pbs::GetExecutionPayloadBidResponse, signer::random_secret, types::Chain, wire::EncodingType,
};
use cb_tests::{
    mock_relay::MockRelayState,
    mock_validator::MockValidator,
    mock_ws_relay::{MockWsRelayState, start_mock_dual_relay},
    utils::{API_KEY, TEST_AUTH_DATA, opaque_auth, setup_pbs},
};
use eyre::Result;
use reqwest::StatusCode;
use ssz::Encode;
use tokio::time::Instant;

const TEST_SLOT: u64 = 255;
const PARENT_ROOT: B256 = B256::repeat_byte(1);
const BUDGET_MS: u64 = 1_000;

/// A relay bidding `http` gwei over HTTP and streaming `stream_bids`, each a
/// `(value, execution_payment)` in gwei
fn relay_states(http: u64, stream_bids: Vec<(u64, u64)>) -> (MockRelayState, MockWsRelayState) {
    let signer = random_secret();
    let http_state =
        MockRelayState::new(Chain::Hoodi, signer.clone()).with_trustless_bid_gwei(http);
    (http_state, MockWsRelayState::new(Chain::Hoodi, signer).with_epbs_bids(stream_bids))
}

/// PBS in front of one stream-mode relay serving both states on one port
async fn start_race(
    (http_state, ws_state): (MockRelayState, MockWsRelayState),
) -> Result<(MockValidator, Arc<MockRelayState>, Arc<MockWsRelayState>)> {
    let (http_state, ws_state, relay) = start_mock_dual_relay(http_state, ws_state).await?;
    let validator = setup_pbs(Chain::Hoodi, vec![relay], |_| {}).await?;
    Ok((validator, http_state, ws_state))
}

async fn get_bid(
    validator: &MockValidator,
) -> Result<(StatusCode, Option<GetExecutionPayloadBidResponse>)> {
    let res = validator
        .do_get_execution_payload_bid_with_timeout(
            TEST_SLOT,
            B256::ZERO,
            PARENT_ROOT,
            None,
            Some(&opaque_auth(TEST_AUTH_DATA, TEST_SLOT)),
            vec![EncodingType::Json],
            BUDGET_MS,
        )
        .await?;
    let code = res.status();
    if code != StatusCode::OK {
        return Ok((code, None));
    }
    Ok((code, Some(serde_json::from_slice(&res.bytes().await?)?)))
}

fn assert_bid(res: Option<GetExecutionPayloadBidResponse>, value: u64, execution_payment: u64) {
    let res = res.expect("a bid");
    let bid = &res.data.message;
    assert_eq!((bid.value, bid.execution_payment), (value, execution_payment));
}

/// A relay that streams get_header but not the ePBS bid answers the handshake
/// with 404, and the HTTP request raced alongside it supplies the bid.
#[tokio::test]
async fn test_get_execution_payload_bid_ws_no_stream_route_http_bid_serves() -> Result<()> {
    let (http_state, ws_state) = relay_states(42, vec![(90, 0)]);
    let (validator, http_state, ws_state) =
        start_race((http_state, ws_state.without_epbs_stream())).await?;

    let (code, res) = get_bid(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert_bid(res, 42, 0);
    assert_eq!(http_state.received_execution_payload_bid(), 1);
    assert_eq!(ws_state.handshake_attempts(), 1);
    assert_eq!(ws_state.received_connections(), 0, "the handshake never completed");
    Ok(())
}

/// With no bid from the stream, the builder's HTTP 401 reaches the beacon node.
#[tokio::test]
async fn test_get_execution_payload_bid_ws_no_stream_bid_http_rejection_passes() -> Result<()> {
    let (http_state, ws_state) = relay_states(10, vec![(50, 0)]);
    let (validator, http_state, _) =
        start_race((http_state, ws_state.without_epbs_stream())).await?;
    http_state.set_response_override(StatusCode::UNAUTHORIZED);

    let (code, _) = get_bid(&validator).await?;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    Ok(())
}

/// The builder's HTTP 401 does not displace the stream's bid.
#[tokio::test]
async fn test_get_execution_payload_bid_ws_http_rejection_stream_bid_serves() -> Result<()> {
    let (validator, http_state, _) = start_race(relay_states(10, vec![(50, 0)])).await?;
    http_state.set_response_override(StatusCode::UNAUTHORIZED);

    let (code, res) = get_bid(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert_bid(res, 50, 0);
    assert_eq!(http_state.received_execution_payload_bid(), 1);
    Ok(())
}

/// An HTTP request that runs out the window does not displace the stream's bid.
#[tokio::test]
async fn test_get_execution_payload_bid_ws_http_timeout_stream_bid_serves() -> Result<()> {
    let (http_state, ws_state) = relay_states(10, vec![(50, 0)]);
    let (validator, ..) = start_race((http_state.with_bid_delay_ms(BUDGET_MS), ws_state)).await?;

    let (code, res) = get_bid(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert_bid(res, 50, 0);
    Ok(())
}

/// The stream and the HTTP request are separate candidates: the higher value +
/// execution_payment wins, the stream's bid on a tie, and the stream's
/// candidate is its latest bid, not its highest.
#[tokio::test]
async fn test_get_execution_payload_bid_ws_higher_total_wins() -> Result<()> {
    for (http, stream_bids, served) in
        [(60, vec![(70, 0), (50, 0)], (60, 0)), (50, vec![(10, 40)], (10, 40))]
    {
        let (validator, http_state, ws_state) =
            start_race(relay_states(http, stream_bids.clone())).await?;

        let (code, res) = get_bid(&validator).await?;
        assert_eq!(code, StatusCode::OK, "http {http}, stream {stream_bids:?}");
        assert_bid(res, served.0, served.1);
        assert_eq!(http_state.received_execution_payload_bid(), 1);
        assert_eq!(ws_state.received_connections(), 1);
    }
    Ok(())
}

/// A later streamed bid that fails to decode does not displace the valid bid
/// (50) before it.
#[tokio::test]
async fn test_get_execution_payload_bid_ws_skips_invalid_bid() -> Result<()> {
    let (http_state, ws_state) = relay_states(10, vec![(50, 0), (90, 0)]);
    let (validator, ..) = start_race((http_state, ws_state.with_invalid_last_bids(1))).await?;

    let (code, res) = get_bid(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert_bid(res, 50, 0);
    Ok(())
}

/// The handshake carries the auth as padded standard base64 of its SSZ, the
/// fork and a timeout that leaves the buffer; the bid lands within the budget.
#[tokio::test]
async fn test_get_execution_payload_bid_ws_handshake_and_deadline() -> Result<()> {
    const BUFFER_MS: u64 = 200;
    let (http_state, ws_state) = relay_states(10, vec![(20, 0)]);
    let (_, ws_state, relay) =
        start_mock_dual_relay(http_state.with_bid_delay_ms(400), ws_state.hold_open()).await?;
    let validator = setup_pbs(Chain::Hoodi, vec![relay], |pbs_config| {
        pbs_config.proposer_deadline_buffer_ms = BUFFER_MS
    })
    .await?;

    let start = Instant::now();
    let (code, _) = get_bid(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert!(start.elapsed() < Duration::from_millis(BUDGET_MS), "{:?}", start.elapsed());

    let request = ws_state.last_request().expect("a handshake");
    // 119 bytes of SSZ need padding, and slot 255 puts a '/' in the base64,
    // which the URL-safe alphabet would write as '_'
    let expected_auth =
        BASE64_STANDARD.encode(opaque_auth(TEST_AUTH_DATA, TEST_SLOT).as_ssz_bytes());
    assert!(expected_auth.ends_with('=') && expected_auth.contains('/'));
    assert_eq!(request.request_auth, Some(expected_auth));

    assert_eq!(request.slot, TEST_SLOT);
    assert_eq!(request.parent_root, Some(PARENT_ROOT));
    assert_eq!(request.consensus_version.as_deref(), Some("gloas"));
    let relay_timeout_ms = request.timeout_ms.expect("missing timeout header");
    assert!(
        (BUDGET_MS - BUFFER_MS - 100..=BUDGET_MS - BUFFER_MS).contains(&relay_timeout_ms),
        "timeout header {relay_timeout_ms}ms"
    );
    assert_eq!(request.api_key.as_deref(), Some(API_KEY));
    assert!(request.user_agent.is_some_and(|ua| ua.contains("commit-boost")));
    Ok(())
}
