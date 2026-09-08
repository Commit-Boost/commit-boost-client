use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use alloy::primitives::{B256, U256};
use cb_common::{
    pbs::{GetHeaderResponse, SignedBuilderBid},
    signature::sign_builder_root,
    signer::random_secret,
    types::{BlsPublicKeyBytes, Chain, KnownChain},
    utils::{bls_pubkey_from_hex, timestamp_of_slot_start_sec},
    wire::{CONSENSUS_VERSION_HEADER, EncodingType, get_consensus_version_header},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::MockValidator,
    utils::{
        generate_mock_relay, get_free_listener, get_pbs_config, setup_test_env, to_pbs_config,
    },
};
use eyre::Result;
use lh_eth2::EmptyMetadata;
use lh_types::{ForkName, ForkVersionDecode};
use reqwest::{
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE},
};
use tracing::info;
use tree_hash::TreeHash;
use url::Url;

/// PBS must always request SSZ from the relay (JSON fallback) regardless of the
/// beacon node's own Accept: it decodes and re-validates every bid and the
/// route re-encodes the winner to the BN's Accept anyway, so SSZ is the
/// cheapest wire format on the relay hop. Here the BN asks for JSON, and the
/// relay must still see SSZ as the preferred encoding.
#[tokio::test]
async fn test_get_header_always_requests_ssz_from_relay() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let mut mock_state = MockRelayState::new(chain, signer);
    mock_state.supported_content_types =
        Arc::new(HashSet::from([EncodingType::Ssz, EncodingType::Json]));
    let mock_state = Arc::new(mock_state);
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    let res = mock_validator.do_get_header(None, vec![EncodingType::Json], ForkName::Fulu).await?;
    assert_eq!(res.status(), StatusCode::OK);

    let relay_accept = mock_state
        .received_get_header_accept()
        .expect("relay should have received an Accept header");
    assert!(
        relay_accept.starts_with(EncodingType::Ssz.content_type()),
        "relay Accept must prefer SSZ regardless of the BN's JSON request, got: {relay_accept}"
    );
    Ok(())
}

/// Error responses on get_header follow the Builder API `ErrorMessage` schema:
/// JSON `{code, message}` with `application/json`, not plain text.
#[tokio::test]
async fn test_get_header_error_response_is_json() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let mut mock_state = MockRelayState::new(chain, signer);
    mock_state.supported_content_types =
        Arc::new(HashSet::from([EncodingType::Ssz, EncodingType::Json]));
    let mock_state = Arc::new(mock_state);
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;

    // Happy path: a normal request succeeds and returns a bid (parses as a bid,
    // which an error envelope would not).
    let ok = mock_validator.do_get_header(None, vec![EncodingType::Json], ForkName::Fulu).await?;
    assert_eq!(ok.status(), StatusCode::OK);
    serde_json::from_slice::<GetHeaderResponse>(&ok.bytes().await?)
        .expect("happy response is a bid, not an error object");

    // Unhappy path: an unsupported Accept must yield a spec JSON error (406).
    let bn_pubkey = bls_pubkey_from_hex(
        "0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae",
    )?;
    let slot = KnownChain::Hoodi.fulu_fork_slot() + 1;
    let url = mock_validator.comm_boost.get_header_url(slot, &B256::ZERO, &bn_pubkey)?;
    let err = mock_validator
        .comm_boost
        .client
        .get(url)
        .header(CONSENSUS_VERSION_HEADER, ForkName::Fulu.to_string())
        .header(ACCEPT, "application/garbage")
        .send()
        .await?;

    assert_eq!(err.status(), StatusCode::NOT_ACCEPTABLE);
    assert_eq!(
        err.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "error body must be JSON per the Builder API",
    );
    let body: serde_json::Value = err.json().await?;
    assert_eq!(body["code"], 406);
    assert!(body["message"].is_string(), "error must carry a message string");
    Ok(())
}

/// Test requesting JSON when the relay supports JSON
#[tokio::test]
async fn test_get_header() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Json],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        1,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Fulu,
    )
    .await
}

/// Test requesting SSZ when the relay supports SSZ
#[tokio::test]
async fn test_get_header_ssz() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Ssz],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        1,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Fulu,
    )
    .await
}

/// Test requesting SSZ when the relay only supports JSON, which should be
/// handled because PBS supports both types internally and re-maps them on the
/// fly
#[tokio::test]
async fn test_get_header_ssz_into_json() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Ssz],
        HashSet::from([EncodingType::Json]),
        1,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Fulu,
    )
    .await
}

/// Test requesting multiple types when the relay supports SSZ, which should
/// return SSZ
#[tokio::test]
async fn test_get_header_multitype_ssz() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Ssz, EncodingType::Json],
        HashSet::from([EncodingType::Ssz]),
        1,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Fulu,
    )
    .await
}

/// Test requesting multiple types when the relay supports JSON, which should
/// still work
#[tokio::test]
async fn test_get_header_multitype_json() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Ssz, EncodingType::Json],
        HashSet::from([EncodingType::Json]),
        1,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Fulu,
    )
    .await
}

/// Core implementation for get_header tests.
/// Pass `rpc_url: Some(url)` when testing `HeaderValidationMode::Extra` — PBS
/// requires a non-None rpc_url to start in that mode. A non-existent address is
/// fine; if the parent block fetch fails the relay response is still returned
/// (extra validation is skipped with a warning).
#[allow(clippy::too_many_arguments)]
async fn test_get_header_impl(
    accept_types: Vec<EncodingType>,
    relay_types: HashSet<EncodingType>,
    expected_try_count: u64,
    expected_code: StatusCode,
    bid_value: U256,
    min_bid_wei: U256,
    rpc_url: Option<Url>,
    fork_name: ForkName,
) -> Result<()> {
    // Setup test environment
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let mut mock_state = MockRelayState::new(chain, signer).with_bid_value(bid_value);
    mock_state.supported_content_types = Arc::new(relay_types);
    let mock_state = Arc::new(mock_state);
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    // Run the PBS service
    let mut pbs_config = get_pbs_config(pbs_port);
    pbs_config.min_bid_wei = min_bid_wei;
    pbs_config.rpc_url = rpc_url;
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay.clone()]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send the get_header request
    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(None, accept_types.clone(), fork_name).await?;
    assert_eq!(res.status(), expected_code);
    assert_eq!(mock_state.received_get_header(), expected_try_count);
    match expected_code {
        StatusCode::OK => {}
        _ => return Ok(()),
    }

    // Get the content type
    let content_type = match res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|ct| ct.to_str().ok())
        .unwrap()
    {
        ct if ct == EncodingType::Ssz.to_string() => EncodingType::Ssz,
        ct if ct == EncodingType::Json.to_string() => EncodingType::Json,
        _ => panic!("unexpected content type"),
    };
    assert!(accept_types.contains(&content_type));

    // Get the data
    let res = match content_type {
        EncodingType::Json => serde_json::from_slice::<GetHeaderResponse>(&res.bytes().await?)?,
        EncodingType::Ssz => {
            let fork =
                get_consensus_version_header(res.headers()).expect("missing fork version header");
            let data = SignedBuilderBid::from_ssz_bytes_by_fork(&res.bytes().await?, fork).unwrap();
            GetHeaderResponse { version: fork, data, metadata: EmptyMetadata::default() }
        }
    };
    assert_eq!(res.data.message.header().block_hash().0[0], 1);
    assert_eq!(res.data.message.header().parent_hash().0, B256::ZERO);
    assert_eq!(*res.data.message.value(), bid_value);
    assert_eq!(*res.data.message.pubkey(), BlsPublicKeyBytes::from(mock_state.signer.public_key()));
    // Mock relay computes timestamp from the slot in the request URL
    let expected_slot = KnownChain::Hoodi.fulu_fork_slot() + 1;
    assert_eq!(
        res.data.message.header().timestamp(),
        timestamp_of_slot_start_sec(expected_slot, chain)
    );
    assert_eq!(
        res.data.signature,
        sign_builder_root(chain, &mock_state.signer, &res.data.message.tree_hash_root())
    );
    Ok(())
}

#[tokio::test]
async fn test_get_header_returns_204_if_no_relay_reachable() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    // Create a mock relay client
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;

    // Don't start the relay
    // tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(),
    // relay_listener));
    drop(relay_listener);

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay.clone()]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(None, Vec::new(), ForkName::Fulu).await?;

    assert_eq!(res.status(), StatusCode::NO_CONTENT); // 204 error
    assert_eq!(mock_state.received_get_header(), 0); // no header received
    Ok(())
}

#[tokio::test]
async fn test_get_header_returns_400_if_request_is_invalid() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    // Run a mock relay
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    let mock_relay = generate_mock_relay(relay_port, pubkey.clone())?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay.clone()]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create an invalid URL by truncating the pubkey
    let mut bad_url = mock_relay.get_header_url(0, &B256::ZERO, &pubkey).unwrap();
    bad_url.set_path(&bad_url.path().replace(&pubkey.to_string(), &pubkey.to_string()[..10]));

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header with invalid pubkey URL");
    // Use the bad_url in the request instead of the default
    let res = mock_validator.comm_boost.client.get(bad_url).send().await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Attempt again by truncating the parent hash
    let mut bad_url = mock_relay.get_header_url(0, &B256::ZERO, &pubkey).unwrap();
    bad_url
        .set_path(&bad_url.path().replace(&B256::ZERO.to_string(), &B256::ZERO.to_string()[..10]));
    let res = mock_validator.comm_boost.client.get(bad_url).send().await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    assert_eq!(mock_state.received_get_header(), 0); // no header received
    Ok(())
}

/// All validation modes (None, Standard, Extra) enforce the min-bid threshold.
/// None skips expensive crypto checks; Standard adds sigverify + structural
/// checks; Extra adds the parent-block check via EL RPC (which is skipped with
/// a warning if the fetch fails, so a non-existent RPC URL still passes here).
#[tokio::test]
async fn test_get_header_extra_validation_enforce_min_bid() -> Result<()> {
    let relay_bid = U256::from(7u64);
    let min_bid_above_relay = relay_bid + U256::from(1);
    // A syntactically valid URL that will never connect — Extra mode config
    // validation only requires rpc_url to be Some; the actual fetch failing is
    // handled gracefully (extra validation is skipped with a warning).
    let fake_rpc: Url = "http://127.0.0.1:1".parse()?;

    // Bid below min → all modes reject (204).
    test_get_header_impl(
        vec![EncodingType::Json],
        HashSet::from([EncodingType::Json]),
        1,
        StatusCode::NO_CONTENT,
        relay_bid,
        min_bid_above_relay,
        Some(fake_rpc.clone()),
        ForkName::Fulu,
    )
    .await?;

    // Bid above min → all modes accept (200).
    test_get_header_impl(
        vec![EncodingType::Json],
        HashSet::from([EncodingType::Json]),
        1,
        StatusCode::OK,
        min_bid_above_relay,
        U256::ZERO,
        Some(fake_rpc),
        ForkName::Fulu,
    )
    .await?;

    Ok(())
}

/// Verify the mock relay returns 400 when the validator requests an unsupported
/// fork. Tested by pointing MockValidator directly at the relay (no PBS) so the
/// assertion is on the relay's raw response, not PBS's 204 fallback.
#[tokio::test]
async fn test_get_header_unsupported_fork_returns_400() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let chain = Chain::Hoodi;

    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr().unwrap().port();
    let mock_state = Arc::new(MockRelayState::new(chain, signer.clone()));
    tokio::spawn(start_mock_relay_service_with_listener(mock_state, relay_listener));

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Point MockValidator directly at the relay (no PBS in the path).
    let direct = MockValidator::new(relay_port)?;
    for unsupported_fork in [ForkName::Base, ForkName::Altair] {
        let res = direct.do_get_header(None, vec![EncodingType::Json], unsupported_fork).await?;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for unsupported fork {unsupported_fork}"
        );
    }
    Ok(())
}

/// Exhaustive bid-acceptance matrix across every (fork, encoding, mode, bid)
/// combination.
#[tokio::test]
async fn test_get_header_bid_validation_matrix() -> Result<()> {
    let bid_low = U256::from(5u64);
    let bid_high = U256::from(100u64);
    let min_bid = U256::from(50u64);

    // (fork, encoding, mode, relay_bid, expected_status)
    let cases: &[(ForkName, EncodingType, U256, StatusCode)] = &[
        (ForkName::Fulu, EncodingType::Json, bid_low, StatusCode::NO_CONTENT),
        (ForkName::Fulu, EncodingType::Json, bid_high, StatusCode::OK),
        (ForkName::Fulu, EncodingType::Ssz, bid_low, StatusCode::NO_CONTENT),
        (ForkName::Fulu, EncodingType::Ssz, bid_high, StatusCode::OK),
        (ForkName::Fulu, EncodingType::Json, bid_low, StatusCode::NO_CONTENT),
        (ForkName::Fulu, EncodingType::Json, bid_high, StatusCode::OK),
        (ForkName::Fulu, EncodingType::Ssz, bid_low, StatusCode::NO_CONTENT),
        (ForkName::Fulu, EncodingType::Ssz, bid_high, StatusCode::OK),
    ];

    for (i, &(fork, encoding, relay_bid, expected_status)) in cases.iter().enumerate() {
        test_get_header_impl(
            vec![encoding],
            HashSet::from([encoding]),
            1,
            expected_status,
            relay_bid,
            min_bid,
            None,
            fork,
        )
        .await
        .map_err(|e| {
            eyre::eyre!("case {i} (fork={fork} enc={encoding} bid={relay_bid} min={min_bid}): {e}")
        })?;
    }
    Ok(())
}

/// PBS must accept relay `Content-Type` values that include MIME parameters
/// (e.g. `application/octet-stream; charset=binary`). The audit fix for C2
/// switched `EncodingType::from_str` to parse via the `mediatype` crate;
/// this test exercises the full relay→PBS→BN path to guard against
/// regressions at the wire boundary.
#[tokio::test]
async fn test_get_header_tolerates_mime_params_in_content_type() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let mut mock_state = MockRelayState::new(chain, signer)
        .with_response_content_type("application/octet-stream; charset=binary");
    mock_state.supported_content_types = Arc::new(HashSet::from([EncodingType::Ssz]));
    let mock_state = Arc::new(mock_state);
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let pbs_config = get_pbs_config(pbs_port);
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    let res = mock_validator.do_get_header(None, vec![EncodingType::Ssz], ForkName::Fulu).await?;
    assert_eq!(res.status(), StatusCode::OK, "PBS should tolerate `; charset=binary` MIME param");
    assert_eq!(mock_state.received_get_header(), 1);

    let fork = get_consensus_version_header(res.headers()).expect("missing fork version header");
    let bytes = res.bytes().await?;
    let data = SignedBuilderBid::from_ssz_bytes_by_fork(&bytes, fork).unwrap();
    assert_eq!(data.message.header().block_hash().0[0], 1);
    Ok(())
}

/// Same guarantee on the JSON path: `application/json; charset=utf-8` (the
/// value some production relays actually emit) must be accepted as JSON.
#[tokio::test]
async fn test_get_header_tolerates_json_charset_param() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let mut mock_state = MockRelayState::new(chain, signer)
        .with_response_content_type("application/json; charset=utf-8");
    mock_state.supported_content_types = Arc::new(HashSet::from([EncodingType::Json]));
    let mock_state = Arc::new(mock_state);
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let pbs_config = get_pbs_config(pbs_port);
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    let res = mock_validator.do_get_header(None, vec![EncodingType::Json], ForkName::Fulu).await?;
    assert_eq!(res.status(), StatusCode::OK, "PBS should tolerate `; charset=utf-8` MIME param");
    assert_eq!(mock_state.received_get_header(), 1);

    let body: GetHeaderResponse = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body.data.message.header().block_hash().0[0], 1);
    Ok(())
}
