use std::{sync::Arc, time::Duration};

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
use lh_types::ForkVersionDecode;
use reqwest::StatusCode;
use tracing::info;
use tree_hash::TreeHash;

#[tokio::test]
async fn test_get_header() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_port = 3200;
    let relay_port = pbs_port + 1;

    // Run a mock relay
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    tokio::spawn(start_mock_relay_service(mock_state.clone(), relay_port));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), vec![mock_relay.clone()]);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(None, None, ForkName::Electra).await?;
    assert_eq!(res.status(), StatusCode::OK);

    let res = serde_json::from_slice::<GetHeaderResponse>(&res.bytes().await?)?;

    assert_eq!(mock_state.received_get_header(), 1);
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
async fn test_get_header_ssz() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_port = 3210;
    let relay_port = pbs_port + 1;

    // Run a mock relay
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    tokio::spawn(start_mock_relay_service(mock_state.clone(), relay_port));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), vec![mock_relay.clone()]);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res =
        mock_validator.do_get_header(None, Some(EncodingType::Ssz), ForkName::Electra).await?;
    assert_eq!(res.status(), StatusCode::OK);

    let fork = get_consensus_version_header(res.headers()).expect("missing fork version header");
    assert_eq!(fork, ForkName::Electra);
    let data = SignedBuilderBid::from_ssz_bytes_by_fork(&res.bytes().await?, fork).unwrap();

    assert_eq!(mock_state.received_get_header(), 1);
    assert_eq!(data.message.header().block_hash().0[0], 1);
    assert_eq!(data.message.header().parent_hash().0, B256::ZERO);
    assert_eq!(*data.message.value(), U256::from(10));
    assert_eq!(*data.message.pubkey(), BlsPublicKeyBytes::from(mock_state.signer.public_key()));
    assert_eq!(data.message.header().timestamp(), timestamp_of_slot_start_sec(0, chain));
    assert_eq!(
        data.signature,
        sign_builder_root(chain, &mock_state.signer, data.message.tree_hash_root())
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
    let res = mock_validator.do_get_header(None, None, ForkName::Electra).await?;

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
