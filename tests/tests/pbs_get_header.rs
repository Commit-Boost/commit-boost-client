use std::{collections::HashSet, sync::Arc, time::Duration};

use alloy::primitives::{B256, U256};
use cb_common::{
    pbs::{GetHeaderResponse, SignedBuilderBid},
    signature::sign_builder_root,
    signer::random_secret,
    types::{BlsPublicKeyBytes, Chain},
    utils::{EncodingType, ForkName, get_consensus_version_header, timestamp_of_slot_start_sec},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service},
    mock_validator::MockValidator,
    utils::{generate_mock_relay, get_pbs_static_config, setup_test_env, to_pbs_config},
};
use eyre::Result;
use lh_types::{ForkVersionDecode, beacon_response::EmptyMetadata};
use reqwest::StatusCode;
use tracing::info;
use tree_hash::TreeHash;

/// Test requesting JSON when the relay supports JSON
#[tokio::test]
async fn test_get_header() -> Result<()> {
    test_get_header_impl(
        3200,
        HashSet::from([EncodingType::Json]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        1,
    )
    .await
}

/// Test requesting SSZ when the relay supports SSZ
#[tokio::test]
async fn test_get_header_ssz() -> Result<()> {
    test_get_header_impl(
        3210,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        1,
    )
    .await
}

/// Test requesting SSZ when the relay only supports JSON, which should cause
/// PBS to retry internally with JSON
#[tokio::test]
async fn test_get_header_ssz_into_json() -> Result<()> {
    test_get_header_impl(
        3220,
        HashSet::from([EncodingType::Ssz]),
        HashSet::from([EncodingType::Json]),
        2,
    )
    .await
}

/// Test requesting multiple types when the relay supports SSZ, which should
/// return SSZ
#[tokio::test]
async fn test_get_header_multitype_ssz() -> Result<()> {
    test_get_header_impl(
        3230,
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        HashSet::from([EncodingType::Ssz]),
        1,
    )
    .await
}

/// Test requesting multiple types when the relay supports JSON, which should
/// return JSON
#[tokio::test]
async fn test_get_header_multitype_json() -> Result<()> {
    test_get_header_impl(
        3240,
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        HashSet::from([EncodingType::Json]),
        1,
    )
    .await
}

/// Core implementation for get_header tests
async fn test_get_header_impl(
    pbs_port: u16,
    accept_types: HashSet<EncodingType>,
    relay_types: HashSet<EncodingType>,
    expected_try_count: u64,
) -> Result<()> {
    // Setup test environment
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;
    let relay_port = pbs_port + 1;

    // Run a mock relay
    let mut mock_state = MockRelayState::new(chain, signer);
    mock_state.supported_content_types = Arc::new(relay_types);
    let mock_state = Arc::new(mock_state);
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    tokio::spawn(start_mock_relay_service(mock_state.clone(), relay_port));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send the get_header request
    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(None, accept_types.clone(), ForkName::Electra).await?;
    assert_eq!(res.status(), StatusCode::OK);

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
            assert_eq!(fork, ForkName::Electra);
            let data = SignedBuilderBid::from_ssz_bytes_by_fork(&res.bytes().await?, fork).unwrap();
            GetHeaderResponse { version: fork, data, metadata: EmptyMetadata::default() }
        }
    };

    // Validate the data
    assert_eq!(mock_state.received_get_header(), expected_try_count);
    assert_eq!(res.version, ForkName::Electra);
    assert_eq!(res.data.message.header().block_hash().0[0], 1);
    assert_eq!(res.data.message.header().parent_hash().0, B256::ZERO);
    assert_eq!(*res.data.message.value(), U256::from(10));
    assert_eq!(*res.data.message.pubkey(), BlsPublicKeyBytes::from(mock_state.signer.public_key()));
    assert_eq!(res.data.message.header().timestamp(), timestamp_of_slot_start_sec(0, chain));
    assert_eq!(
        res.data.signature,
        sign_builder_root(chain, &mock_state.signer, res.data.message.tree_hash_root())
    );
    Ok(())
}

#[tokio::test]
async fn test_get_header_returns_204_if_relay_down() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_port = 3300;
    let relay_port = pbs_port + 1;

    // Create a mock relay client
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;

    // Don't start the relay
    // tokio::spawn(start_mock_relay_service(mock_state.clone(), relay_port));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), vec![mock_relay.clone()]);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(None, HashSet::new(), ForkName::Electra).await?;

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
    let pbs_port = 3400;
    let relay_port = pbs_port + 1;

    // Run a mock relay
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    let mock_relay = generate_mock_relay(relay_port, pubkey.clone())?;
    tokio::spawn(start_mock_relay_service(mock_state.clone(), relay_port));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), vec![mock_relay.clone()]);
    let state = PbsState::new(config);
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
