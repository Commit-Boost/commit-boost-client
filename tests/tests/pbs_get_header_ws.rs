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
    utils::{timestamp_of_slot_start_sec, utcnow_ms},
    wire::EncodingType,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::MockValidator,
    mock_ws_relay::{
        MockWsRelayState, start_mock_dual_relay, start_mock_ws_relay_service,
        start_mock_ws_relay_with_full_backlog,
    },
    utils::{
        API_KEY, generate_mock_relay, generate_mock_stream_relay,
        generate_mock_stream_relay_with_timing_games, get_free_listener, get_pbs_config,
        setup_test_env, to_pbs_config,
    },
};
use eyre::Result;
use lh_types::ForkName;
use reqwest::StatusCode;
use tokio::sync::oneshot;
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
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, listener));

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

/// Bids that fail validation do not displace the valid one before them, while
/// it is among the newest 8 the stream holds
#[tokio::test]
async fn test_get_header_ws_returns_latest_valid_bid() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let chain = Chain::Hoodi;

    for (invalid_bids, served) in [(7, Some(50)), (8, None)] {
        let mut bid_values = vec![U256::from(50)];
        bid_values.resize(invalid_bids + 1, U256::from(60));
        let (_relay_state, relay) = start_stream_relay(
            MockWsRelayState::new(chain, signer.clone())
                .with_bid_values(bid_values)
                .with_invalid_last_bids(invalid_bids),
            signer.public_key(),
        )
        .await?;

        let validator = start_pbs(chain, vec![relay], 1_000).await?;

        let (code, res) = get_header_json(&validator).await?;
        match served {
            Some(value) => {
                assert_eq!(code, StatusCode::OK, "{invalid_bids} invalid bids");
                assert_bid(&res.unwrap(), chain, &signer, U256::from(value));
            }
            None => assert_eq!(code, StatusCode::NO_CONTENT, "{invalid_bids} invalid bids"),
        }
    }
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

    let sent_at = utcnow_ms();
    let (code, _) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::OK);

    let request = relay_state.last_request().expect("relay saw no request");
    assert_eq!(request.slot, request_slot());
    assert_eq!(request.parent_hash, B256::ZERO);
    assert!(request.validator_pubkey.starts_with("0x"));

    // No timeout header from the caller, so PBS asks for its own budget, less
    // what the connect took
    let relay_timeout_ms = request.timeout_ms.expect("missing timeout header");
    assert!(
        (timeout_ms - 100..=timeout_ms).contains(&relay_timeout_ms),
        "timeout header {relay_timeout_ms}ms"
    );
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

/// PBS asks the relay to end its stream half a TCP connect before PBS's own
/// deadline, so the last bid, one downlink trip later, still lands.
#[tokio::test]
async fn test_get_header_ws_last_bid_lands_before_deadline() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let chain = Chain::Hoodi;
    let timeout_ms = 3_000;

    let relay_state = Arc::new(
        MockWsRelayState::new(chain, signer.clone())
            .with_bid_values(vec![U256::from(10), U256::from(20)])
            .with_update_interval(Duration::from_millis(400))
            .ends_at_timeout(Duration::from_millis(200)),
    );
    let (drain, drained) = oneshot::channel();
    let port = start_mock_ws_relay_with_full_backlog(relay_state.clone(), drained).await?;
    let relay = generate_mock_stream_relay(port, signer.public_key())?;
    let validator = start_pbs(chain, vec![relay], timeout_ms).await?;

    let requested_at_ms = utcnow_ms();
    let (res, ()) = tokio::join!(get_header_json(&validator), async {
        // After PBS's first SYN, before its retransmit
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = drain.send(());
    });
    let (code, res) = res?;

    assert_eq!(code, StatusCode::OK);
    assert_bid(&res.unwrap(), chain, &signer, U256::from(20));

    let request = relay_state.last_request().expect("relay saw no request");
    let connect_ms = request.accepted_at_ms - requested_at_ms;
    assert!(connect_ms >= 500, "the connect was not delayed: {connect_ms}ms");

    let relay_end_ms = request.start_time_ms.unwrap() + request.timeout_ms.unwrap();
    let early_ms = (requested_at_ms + timeout_ms) as i64 - relay_end_ms as i64;
    let half_connect_ms = connect_ms as i64 / 2;
    // PBS's delay before connecting skews both sides, hence the slack
    assert!(
        (half_connect_ms - 250..=half_connect_ms + 20).contains(&early_ms),
        "relay asked to end {early_ms}ms before the deadline, connect took {connect_ms}ms"
    );
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

/// The HTTP request raced alongside the stream is the relay's normal
/// get_header, timing games included.
#[tokio::test]
async fn test_get_header_ws_race_http_runs_timing_games() -> Result<()> {
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
    assert!(n_requests > 1, "HTTP skipped the timing games loop: {n_requests} requests");
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

/// A handshake that outlasts the budget: the HTTP request raced alongside it
/// supplies the bid.
#[tokio::test]
async fn test_get_header_ws_race_handshake_timeout_http_bid_serves() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let chain = Chain::Hoodi;
    let (http_state, ws_state, relay) = start_mock_dual_relay(
        MockRelayState::new(chain, signer.clone()).with_bid_value(U256::from(42)),
        MockWsRelayState::new(chain, signer.clone()).with_handshake_delay(Duration::from_secs(2)),
    )
    .await?;
    let validator = start_pbs(chain, vec![relay], 300).await?;

    let (code, res) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert_bid(&res.unwrap(), chain, &signer, U256::from(42));
    assert_eq!(http_state.received_get_header(), 1);
    assert_eq!(ws_state.handshake_attempts(), 1);
    assert_eq!(ws_state.received_connections(), 0, "the handshake never completed");
    Ok(())
}

/// A stream that breaks after a bid keeps that bid, here above the HTTP one.
#[tokio::test]
async fn test_get_header_ws_race_stream_break_keeps_held_bid() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let chain = Chain::Hoodi;
    let (_, ws_state, relay) = start_mock_dual_relay(
        MockRelayState::new(chain, signer.clone()).with_bid_value(U256::from(10)),
        MockWsRelayState::new(chain, signer.clone())
            .with_bid_values(vec![U256::from(50)])
            .abort_after_bids(),
    )
    .await?;
    let validator = start_pbs(chain, vec![relay], 1_000).await?;

    let (code, res) = get_header_json(&validator).await?;
    assert_eq!(code, StatusCode::OK);
    assert_bid(&res.unwrap(), chain, &signer, U256::from(50));
    assert_eq!(ws_state.received_connections(), 1);
    Ok(())
}

/// The higher candidate wins, the stream's being its latest bid, not its
/// highest; a stream with no bid leaves the HTTP one.
#[tokio::test]
async fn test_get_header_ws_race_higher_bid_wins() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let chain = Chain::Hoodi;

    for (http_bid, stream_bids, served) in
        [(10, vec![20, 50], 50), (60, vec![70, 50], 60), (42, vec![], 42)]
    {
        let (http_state, ws_state, relay) = start_mock_dual_relay(
            MockRelayState::new(chain, signer.clone()).with_bid_value(U256::from(http_bid)),
            MockWsRelayState::new(chain, signer.clone())
                .with_bid_values(stream_bids.into_iter().map(U256::from).collect()),
        )
        .await?;
        let validator = start_pbs(chain, vec![relay], 1_000).await?;

        let (code, res) = get_header_json(&validator).await?;
        assert_eq!(code, StatusCode::OK);
        assert_bid(&res.unwrap(), chain, &signer, U256::from(served));
        assert_eq!(http_state.received_get_header(), 1);
        assert_eq!(ws_state.received_connections(), 1);
    }
    Ok(())
}
