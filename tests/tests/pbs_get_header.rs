use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use alloy::primitives::{B256, U256};
use cb_common::{
    config::HeaderValidationMode,
    pbs::{GetHeaderResponse, SignedBuilderBid},
    signature::sign_builder_root,
    signer::random_secret,
    types::{BlsPublicKeyBytes, Chain},
    utils::{
        EncodingType, ForkName, get_bid_value_from_signed_builder_bid_ssz,
        get_consensus_version_header, timestamp_of_slot_start_sec,
    },
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
use lh_types::ForkVersionDecode;
use reqwest::StatusCode;
use tracing::info;
use tree_hash::TreeHash;
use url::Url;

/// Test requesting JSON when the relay supports JSON
#[tokio::test]
async fn test_get_header() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Json],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        1,
        HeaderValidationMode::Standard,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Electra,
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
        HeaderValidationMode::Standard,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Electra,
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
        HeaderValidationMode::Standard,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Electra,
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
        HeaderValidationMode::Standard,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Electra,
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
        HeaderValidationMode::Standard,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Electra,
    )
    .await
}

// === Light Mode Tests ===

/// Test requesting JSON without validation when the relay supports JSON
#[tokio::test]
async fn test_get_header_light() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Json],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        1,
        HeaderValidationMode::None,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Electra,
    )
    .await
}

/// Test requesting SSZ without validation when the relay supports SSZ
#[tokio::test]
async fn test_get_header_ssz_light() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Ssz],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        1,
        HeaderValidationMode::None,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Electra,
    )
    .await
}

/// Test requesting SSZ without validation when the relay only supports JSON.
/// This should actually fail because in no-validation mode we just forward the
/// response without re-encoding it.
#[tokio::test]
async fn test_get_header_ssz_into_json_light() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Ssz],
        HashSet::from([EncodingType::Json]),
        1,
        HeaderValidationMode::None,
        StatusCode::NO_CONTENT, // Should fail because the only relay can't be used
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Electra,
    )
    .await
}

/// Test requesting multiple types without validation when the relay supports
/// SSZ, which should return SSZ
#[tokio::test]
async fn test_get_header_multitype_ssz_light() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Ssz, EncodingType::Json],
        HashSet::from([EncodingType::Ssz]),
        1,
        HeaderValidationMode::None,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Electra,
    )
    .await
}

/// Test requesting multiple types without validation when the relay supports
/// JSON, which should still work
#[tokio::test]
async fn test_get_header_multitype_json_light() -> Result<()> {
    test_get_header_impl(
        vec![EncodingType::Ssz, EncodingType::Json],
        HashSet::from([EncodingType::Json]),
        1,
        HeaderValidationMode::None,
        StatusCode::OK,
        U256::from(10u64),
        U256::ZERO,
        None,
        ForkName::Electra,
    )
    .await
}

/// Core implementation for get_header tests.
/// Pass `rpc_url: Some(url)` when testing `HeaderValidationMode::Extra` — PBS
/// requires a non-None rpc_url to start in that mode. A non-existent address is
/// fine; if the parent block fetch fails the relay response is still returned
/// (extra validation is skipped with a warning).
async fn test_get_header_impl(
    accept_types: Vec<EncodingType>,
    relay_types: HashSet<EncodingType>,
    expected_try_count: u64,
    mode: HeaderValidationMode,
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
    let chain = Chain::Holesky;
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
    pbs_config.header_validation_mode = mode;
    pbs_config.min_bid_wei = min_bid_wei;
    pbs_config.rpc_url = rpc_url;
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay.clone()]);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

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
    assert_eq!(res.data.message.header().timestamp(), timestamp_of_slot_start_sec(0, chain));
    assert_eq!(
        res.data.signature,
        sign_builder_root(chain, &mock_state.signer, &res.data.message.tree_hash_root())
    );
    Ok(())
}

#[tokio::test]
async fn test_get_header_returns_204_if_relay_down() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
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
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(None, Vec::new(), ForkName::Electra).await?;

    assert_eq!(res.status(), StatusCode::NO_CONTENT); // 204 error
    assert_eq!(mock_state.received_get_header(), 0); // no header received
    Ok(())
}

#[tokio::test]
async fn test_get_header_returns_400_if_request_is_invalid() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
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
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

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
async fn test_get_header_all_modes_enforce_min_bid() -> Result<()> {
    let relay_bid = U256::from(7u64);
    let min_bid_above_relay = relay_bid + U256::from(1);
    // A syntactically valid URL that will never connect — Extra mode config
    // validation only requires rpc_url to be Some; the actual fetch failing is
    // handled gracefully (extra validation is skipped with a warning).
    let fake_rpc: Url = "http://127.0.0.1:1".parse()?;

    for (mode, rpc_url) in [
        (HeaderValidationMode::Standard, None),
        (HeaderValidationMode::None, None),
        (HeaderValidationMode::Extra, Some(fake_rpc.clone())),
    ] {
        // Bid below min → all modes reject (204).
        test_get_header_impl(
            vec![EncodingType::Json],
            HashSet::from([EncodingType::Json]),
            1,
            mode,
            StatusCode::NO_CONTENT,
            relay_bid,
            min_bid_above_relay,
            rpc_url.clone(),
            ForkName::Electra,
        )
        .await?;

        // Bid above min → all modes accept (200).
        test_get_header_impl(
            vec![EncodingType::Json],
            HashSet::from([EncodingType::Json]),
            1,
            mode,
            StatusCode::OK,
            min_bid_above_relay,
            U256::ZERO,
            rpc_url,
            ForkName::Electra,
        )
        .await?;
    }
    Ok(())
}

/// SSZ round-trip: configure the relay with a specific bid value, request via
/// PBS in None mode with SSZ encoding, and verify the raw response bytes decode
/// to the exact value that was configured. This exercises the byte-offset
/// extraction logic (`get_bid_value_from_signed_builder_bid_ssz`) end-to-end
/// through a live HTTP relay for both currently-supported forks.
#[tokio::test]
async fn test_get_header_ssz_bid_value_round_trip() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;

    // Use a distinctive value so accidental zero-matches are impossible.
    let relay_bid = U256::from(999_888_777u64);

    for fork_name in [ForkName::Electra, ForkName::Fulu] {
        let pbs_listener = get_free_listener().await;
        let relay_listener = get_free_listener().await;
        let pbs_port = pbs_listener.local_addr().unwrap().port();
        let relay_port = relay_listener.local_addr().unwrap().port();
        let mock_state =
            Arc::new(MockRelayState::new(chain, signer.clone()).with_bid_value(relay_bid));
        let mock_relay = generate_mock_relay(relay_port, pubkey.clone())?;
        tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

        let mut pbs_config = get_pbs_config(pbs_port);
        // None mode: PBS forwards the raw SSZ bytes without re-encoding.
        pbs_config.header_validation_mode = HeaderValidationMode::None;
        pbs_config.min_bid_wei = U256::ZERO;
        let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
        let state = PbsState::new(config, PathBuf::new());
        drop(pbs_listener);
        tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mock_validator = MockValidator::new(pbs_port)?;
        let res = mock_validator.do_get_header(None, vec![EncodingType::Ssz], fork_name).await?;
        assert_eq!(res.status(), StatusCode::OK, "fork {fork_name}: expected 200");

        let bytes = res.bytes().await?;
        let extracted = get_bid_value_from_signed_builder_bid_ssz(&bytes, fork_name)
            .map_err(|e| eyre::eyre!("fork {fork_name}: SSZ extraction failed: {e}"))?;
        assert_eq!(
            extracted, relay_bid,
            "fork {fork_name}: SSZ-extracted bid value does not match configured relay bid"
        );
    }
    Ok(())
}

/// Verify the mock relay returns 400 when the validator requests an unsupported
/// fork. Tested by pointing MockValidator directly at the relay (no PBS) so the
/// assertion is on the relay's raw response, not PBS's 204 fallback.
#[tokio::test]
async fn test_get_header_unsupported_fork_returns_400() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let chain = Chain::Holesky;

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
    let cases: &[(ForkName, EncodingType, HeaderValidationMode, U256, StatusCode)] = &[
        (
            ForkName::Electra,
            EncodingType::Json,
            HeaderValidationMode::None,
            bid_low,
            StatusCode::NO_CONTENT,
        ),
        (
            ForkName::Electra,
            EncodingType::Json,
            HeaderValidationMode::None,
            bid_high,
            StatusCode::OK,
        ),
        (
            ForkName::Electra,
            EncodingType::Ssz,
            HeaderValidationMode::None,
            bid_low,
            StatusCode::NO_CONTENT,
        ),
        (
            ForkName::Electra,
            EncodingType::Ssz,
            HeaderValidationMode::None,
            bid_high,
            StatusCode::OK,
        ),
        (
            ForkName::Fulu,
            EncodingType::Json,
            HeaderValidationMode::None,
            bid_low,
            StatusCode::NO_CONTENT,
        ),
        (ForkName::Fulu, EncodingType::Json, HeaderValidationMode::None, bid_high, StatusCode::OK),
        (
            ForkName::Fulu,
            EncodingType::Ssz,
            HeaderValidationMode::None,
            bid_low,
            StatusCode::NO_CONTENT,
        ),
        (ForkName::Fulu, EncodingType::Ssz, HeaderValidationMode::None, bid_high, StatusCode::OK),
        (
            ForkName::Electra,
            EncodingType::Json,
            HeaderValidationMode::Standard,
            bid_low,
            StatusCode::NO_CONTENT,
        ),
        (
            ForkName::Electra,
            EncodingType::Json,
            HeaderValidationMode::Standard,
            bid_high,
            StatusCode::OK,
        ),
        (
            ForkName::Electra,
            EncodingType::Ssz,
            HeaderValidationMode::Standard,
            bid_low,
            StatusCode::NO_CONTENT,
        ),
        (
            ForkName::Electra,
            EncodingType::Ssz,
            HeaderValidationMode::Standard,
            bid_high,
            StatusCode::OK,
        ),
        (
            ForkName::Fulu,
            EncodingType::Json,
            HeaderValidationMode::Standard,
            bid_low,
            StatusCode::NO_CONTENT,
        ),
        (
            ForkName::Fulu,
            EncodingType::Json,
            HeaderValidationMode::Standard,
            bid_high,
            StatusCode::OK,
        ),
        (
            ForkName::Fulu,
            EncodingType::Ssz,
            HeaderValidationMode::Standard,
            bid_low,
            StatusCode::NO_CONTENT,
        ),
        (
            ForkName::Fulu,
            EncodingType::Ssz,
            HeaderValidationMode::Standard,
            bid_high,
            StatusCode::OK,
        ),
    ];

    for (i, &(fork, encoding, mode, relay_bid, expected_status)) in cases.iter().enumerate() {
        test_get_header_impl(
            vec![encoding],
            HashSet::from([encoding]),
            1,
            mode,
            expected_status,
            relay_bid,
            min_bid,
            None,
            fork,
        )
        .await
        .map_err(|e| eyre::eyre!("case {i} (fork={fork} enc={encoding} mode={mode:?} bid={relay_bid} min={min_bid}): {e}"))?;
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
    let chain = Chain::Holesky;
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
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    let res =
        mock_validator.do_get_header(None, vec![EncodingType::Ssz], ForkName::Electra).await?;
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
    let chain = Chain::Holesky;
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
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    let res =
        mock_validator.do_get_header(None, vec![EncodingType::Json], ForkName::Electra).await?;
    assert_eq!(res.status(), StatusCode::OK, "PBS should tolerate `; charset=utf-8` MIME param");
    assert_eq!(mock_state.received_get_header(), 1);

    let body: GetHeaderResponse = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body.data.message.header().block_hash().0[0], 1);
    Ok(())
}

/// Standard mode rejects a bid whose embedded pubkey does not match the relay's
/// configured pubkey; None mode forwards it unchecked, proving the bypass works
/// for the signature/pubkey validation check.
#[tokio::test]
async fn test_get_header_none_mode_bypasses_pubkey_validation() -> Result<()> {
    setup_test_env();
    let chain = Chain::Holesky;

    // The mock relay signs with `signer` and embeds `signer.public_key()` in
    // its message, but we register the relay in PBS with a *different* pubkey.
    // Standard mode catches this mismatch; None mode does not check.
    let signer = random_secret();
    let wrong_pubkey = random_secret().public_key();

    for (mode, expected_status) in [
        (HeaderValidationMode::Standard, StatusCode::NO_CONTENT),
        (HeaderValidationMode::None, StatusCode::OK),
    ] {
        let pbs_listener = get_free_listener().await;
        let relay_listener = get_free_listener().await;
        let pbs_port = pbs_listener.local_addr().unwrap().port();
        let relay_port = relay_listener.local_addr().unwrap().port();
        let mock_state = Arc::new(MockRelayState::new(chain, signer.clone()));
        // Register with `wrong_pubkey` — PBS will expect this key but the relay
        // embeds `signer.public_key()`, causing a mismatch in Standard mode.
        let mock_relay = generate_mock_relay(relay_port, wrong_pubkey.clone())?;
        tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

        let mut pbs_config = get_pbs_config(pbs_port);
        pbs_config.header_validation_mode = mode;
        let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
        let state = PbsState::new(config, PathBuf::new());
        drop(pbs_listener);
        tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mock_validator = MockValidator::new(pbs_port)?;
        let res = mock_validator.do_get_header(None, Vec::new(), ForkName::Electra).await?;
        assert_eq!(res.status(), expected_status, "unexpected status for mode {mode:?}");
    }
    Ok(())
}
