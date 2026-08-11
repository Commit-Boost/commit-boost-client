use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::primitives::{B256, U256};
use cb_common::{
    pbs::{GetHeaderResponse, HEADER_VERSION_VALUE},
    signature::sign_builder_root,
    signer::random_secret,
    types::{BlsPublicKeyBytes, BlsSecretKey, Chain, KnownChain},
    utils::timestamp_of_slot_start_sec,
    wire::EncodingType,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::MockValidator,
    mock_ws_relay::{MockWsRelayState, start_mock_ws_relay_service},
    utils::{
        API_KEY, generate_mock_relay, generate_mock_stream_relay,
        generate_mock_stream_relay_with_timing_games, get_free_listener, get_pbs_config,
        setup_test_env, to_pbs_config,
    },
};
use eyre::Result;
use lh_types::ForkName;
use reqwest::StatusCode;
use tree_hash::TreeHash;

fn request_slot() -> u64 {
    KnownChain::Hoodi.fulu_fork_slot() + 1
}

/// Start a streaming relay on a free port and return the client PBS should use
/// plus the mock state.
async fn start_stream_relay(
    state: MockWsRelayState,
    pubkey: cb_common::types::BlsPublicKey,
) -> Result<(Arc<MockWsRelayState>, cb_common::pbs::RelayClient)> {
    let listener = get_free_listener().await;
    let port = listener.local_addr()?.port();
    let state = Arc::new(state);
    tokio::spawn(start_mock_ws_relay_service(state.clone(), listener));

    Ok((state, generate_mock_stream_relay(port, pubkey)?))
}

/// Boot PBS on a free port with the given relays and header timeout.
async fn start_pbs(
    chain: Chain,
    relays: Vec<cb_common::pbs::RelayClient>,
    timeout_get_header_ms: u64,
) -> Result<MockValidator> {
    let listener = get_free_listener().await;
    let port = listener.local_addr()?.port();

    let mut pbs_config = get_pbs_config(port);
    pbs_config.timeout_get_header_ms = timeout_get_header_ms;

    let config = to_pbs_config(chain, pbs_config, relays);
    let state = PbsState::new(config, PathBuf::new());
    drop(listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    MockValidator::new(port)
}

async fn get_header_json(
    validator: &MockValidator,
) -> Result<(StatusCode, Option<GetHeaderResponse>)> {
    let res = validator.do_get_header(None, vec![EncodingType::Json], ForkName::Fulu).await?;
    let code = res.status();
    if code != StatusCode::OK {
        return Ok((code, None));
    }

    Ok((code, Some(serde_json::from_slice(&res.bytes().await?)?)))
}

fn assert_bid(res: &GetHeaderResponse, chain: Chain, signer: &BlsSecretKey, value: U256) {
    assert_eq!(*res.data.message.value(), value);
    assert_eq!(res.data.message.header().parent_hash().0, B256::ZERO);
    assert_eq!(res.data.message.header().block_hash().0[0], 1);
    assert_eq!(*res.data.message.pubkey(), BlsPublicKeyBytes::from(signer.public_key()));
    assert_eq!(
        res.data.message.header().timestamp(),
        timestamp_of_slot_start_sec(request_slot(), chain)
    );
    assert_eq!(
        res.data.signature,
        sign_builder_root(chain, signer, &res.data.message.tree_hash_root())
    );
}

/// The relay's last word wins, even when an earlier update paid more, and a
/// close from the relay ends the wait before the deadline.
#[tokio::test]
async fn test_get_header_ws_returns_latest_bid() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;
    let timeout_ms = 1_000;

    let (relay_state, relay) = start_stream_relay(
        MockWsRelayState::new(chain, signer.clone()).with_bid_values(vec![
            U256::from(30),
            U256::from(20),
            U256::from(10),
        ]),
        pubkey,
    )
    .await?;

    let validator = start_pbs(chain, vec![relay], timeout_ms).await?;

    let started = Instant::now();
    let (code, res) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    // The relay closed, so PBS must not have sat on the deadline
    assert!(started.elapsed() < Duration::from_millis(timeout_ms));

    // Last update, not the highest one
    assert_bid(&res.unwrap(), chain, &signer, U256::from(10));

    assert_eq!(relay_state.received_connections(), 1);
    Ok(())
}

/// Frames PBS can't parse are skipped, not treated as the end of the stream:
/// the updates after them still count.
#[tokio::test]
async fn test_get_header_ws_skips_unknown_frames() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;

    let (_relay_state, relay) = start_stream_relay(
        MockWsRelayState::new(chain, signer.clone())
            .with_bid_values(vec![U256::from(10), U256::from(20)])
            .with_unknown_frames(),
        pubkey,
    )
    .await?;

    let validator = start_pbs(chain, vec![relay], 1_000).await?;

    let (code, res) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert_bid(&res.unwrap(), chain, &signer, U256::from(20));
    Ok(())
}

#[tokio::test]
async fn test_get_header_ws_sends_api_key() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;

    let listener = get_free_listener().await;
    let port = listener.local_addr()?.port();
    let relay_state = Arc::new(MockWsRelayState::new(chain, signer));
    tokio::spawn(start_mock_ws_relay_service(relay_state.clone(), listener));

    let relay = generate_mock_stream_relay(port, pubkey)?;

    let validator = start_pbs(chain, vec![relay], 1_000).await?;

    let (code, _) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::OK);

    let request = relay_state.last_request().expect("relay saw no request");
    assert_eq!(request.api_key.as_deref(), Some(API_KEY));
    Ok(())
}

/// The handshake carries the same request data as the HTTP call
#[tokio::test]
async fn test_get_header_ws_handshake_carries_request() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;
    let timeout_ms = 1_000;

    let (relay_state, relay) =
        start_stream_relay(MockWsRelayState::new(chain, signer.clone()), pubkey).await?;
    let validator = start_pbs(chain, vec![relay], timeout_ms).await?;

    let sent_at = cb_common::utils::utcnow_ms();
    let (code, _) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::OK);

    let request = relay_state.last_request().expect("relay saw no request");
    assert_eq!(request.slot, request_slot());
    assert_eq!(request.parent_hash, B256::ZERO);
    assert!(request.validator_pubkey.starts_with("0x"));

    // No timeout header from the caller, so PBS passes its own budget through
    assert_eq!(request.timeout_ms, Some(timeout_ms));
    let start_time_ms = request.start_time_ms.expect("missing start time header");
    assert!((sent_at..sent_at + timeout_ms).contains(&start_time_ms));

    assert!(request.user_agent.is_some_and(|ua| ua.contains("commit-boost")));
    assert_eq!(request.cb_version.as_deref(), Some(HEADER_VERSION_VALUE));
    Ok(())
}

/// A relay that keeps the stream open is cut off at the PBS deadline, and the
/// last update received up to that point is the one returned.
#[tokio::test]
async fn test_get_header_ws_returns_at_deadline() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;
    let timeout_ms = 400;

    let (_relay_state, relay) = start_stream_relay(
        MockWsRelayState::new(chain, signer.clone())
            .with_bid_values(vec![U256::from(10), U256::from(20)])
            .with_update_interval(Duration::from_millis(50))
            .hold_open(),
        pubkey,
    )
    .await?;

    let validator = start_pbs(chain, vec![relay], timeout_ms).await?;

    let started = Instant::now();
    let (code, res) = get_header_json(&validator).await?;
    let elapsed = started.elapsed();

    assert_eq!(code, StatusCode::OK);
    assert_bid(&res.unwrap(), chain, &signer, U256::from(20));

    // Held open, so PBS waited out its full budget and no longer
    assert!(elapsed >= Duration::from_millis(timeout_ms), "returned early: {elapsed:?}");
    assert!(elapsed < Duration::from_millis(2 * timeout_ms), "returned late: {elapsed:?}");
    Ok(())
}

/// A stream that never delivers a bid is a 204, same as an HTTP relay with no
/// header for the slot.
#[tokio::test]
async fn test_get_header_ws_no_bid_returns_204() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;

    let (relay_state, relay) = start_stream_relay(
        MockWsRelayState::new(chain, signer).with_bid_values(vec![]).hold_open(),
        pubkey,
    )
    .await?;

    let validator = start_pbs(chain, vec![relay], 300).await?;

    let (code, _) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::NO_CONTENT);
    assert_eq!(relay_state.received_connections(), 1);
    Ok(())
}

/// An unreachable stream relay fails that relay only, it doesn't fail the call
#[tokio::test]
async fn test_get_header_ws_unreachable_relay_returns_204() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;

    // Take a port and immediately give it back, so nothing is listening
    let listener = get_free_listener().await;
    let port = listener.local_addr()?.port();
    drop(listener);

    let relay = generate_mock_stream_relay(port, pubkey)?;
    let validator = start_pbs(chain, vec![relay], 300).await?;

    let (code, _) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::NO_CONTENT);
    Ok(())
}

/// A relay configured to stream that rejects the handshake — here by not
/// serving the stream route at all — is still asked over HTTP, so its bid stays
/// in the auction instead of the relay silently dropping out.
#[tokio::test]
async fn test_get_header_ws_falls_back_to_http() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;

    let listener = get_free_listener().await;
    let port = listener.local_addr()?.port();
    let relay_state =
        Arc::new(MockRelayState::new(chain, signer.clone()).with_bid_value(U256::from(42)));
    tokio::spawn(start_mock_relay_service_with_listener(relay_state.clone(), listener));

    let relay = generate_mock_stream_relay(port, pubkey)?;
    let validator = start_pbs(chain, vec![relay], 1_000).await?;

    let (code, res) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert_bid(&res.unwrap(), chain, &signer, U256::from(42));

    // Timing games are off for this relay, so the fallback is a single request
    assert_eq!(relay_state.received_get_header(), 1);
    Ok(())
}

/// The handshake can fail early in the slot, so the fallback is a normal http
/// get_header and still plays this relay's timing games.
#[tokio::test]
async fn test_get_header_ws_fallback_runs_timing_games() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;

    let listener = get_free_listener().await;
    let port = listener.local_addr()?.port();
    let relay_state = Arc::new(MockRelayState::new(chain, signer.clone()));
    tokio::spawn(start_mock_relay_service_with_listener(relay_state.clone(), listener));

    // Target is already behind us, so no wait, then one request per 200ms of
    // what is left of the budget
    let relay = generate_mock_stream_relay_with_timing_games(port, pubkey, 0, 200)?;
    let validator = start_pbs(chain, vec![relay], 1_000).await?;

    let (code, res) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert_bid(&res.unwrap(), chain, &signer, U256::from(10));

    let n_requests = relay_state.received_get_header();
    assert!(n_requests > 1, "fallback skipped the timing games loop: {n_requests} requests");
    Ok(())
}

/// A streamed bid competes in the same auction as an HTTP one
#[tokio::test]
async fn test_get_header_ws_wins_auction_against_http() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;

    let http_listener = get_free_listener().await;
    let http_port = http_listener.local_addr()?.port();
    let http_state =
        Arc::new(MockRelayState::new(chain, signer.clone()).with_bid_value(U256::from(10)));
    let http_relay = generate_mock_relay(http_port, pubkey.clone())?;
    tokio::spawn(start_mock_relay_service_with_listener(http_state.clone(), http_listener));

    let (stream_state, stream_relay) = start_stream_relay(
        MockWsRelayState::new(chain, signer.clone()).with_bid_values(vec![U256::from(50)]),
        pubkey,
    )
    .await?;

    let validator = start_pbs(chain, vec![http_relay, stream_relay], 1_000).await?;

    let (code, res) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert_bid(&res.unwrap(), chain, &signer, U256::from(50));

    // Both transports were actually queried
    assert_eq!(http_state.received_get_header(), 1);
    assert_eq!(stream_state.received_connections(), 1);
    Ok(())
}
