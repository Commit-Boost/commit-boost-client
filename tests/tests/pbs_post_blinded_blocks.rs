use std::{sync::Arc, time::Duration};

use cb_common::{
    pbs::{DenebSpec, ElectraSpec, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse},
    signer::{random_secret, BlsPublicKey},
    types::Chain,
    utils::blst_pubkey_to_alloy,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{start_mock_relay_service, MockRelayState},
    mock_validator::MockValidator,
    utils::{generate_mock_relay, get_pbs_static_config, setup_test_env, to_pbs_config},
};
use eyre::Result;
use reqwest::StatusCode;
use tracing::info;

#[tokio::test]
async fn test_submit_block_deneb() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let pbs_port = 3800;

    // Run a mock relay
    let relays = vec![generate_mock_relay(pbs_port + 1, *pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service::<DenebSpec>(mock_state.clone(), pbs_port + 1));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DenebSpec, DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = mock_validator.do_submit_block::<DenebSpec>(Some(SignedBlindedBeaconBlock::default())).await?;

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_submit_block(), 1);

    let response_body = serde_json::from_slice::<SubmitBlindedBlockResponse<DenebSpec>>(&res.bytes().await?)?;
    assert_eq!(response_body.block_hash(), SubmitBlindedBlockResponse::<DenebSpec>::default().block_hash());
    Ok(())
}

#[tokio::test]
async fn test_submit_block_electra() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let pbs_port = 3850;

    // Run a mock relay
    let relays = vec![generate_mock_relay(pbs_port + 1, *pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service::<ElectraSpec>(mock_state.clone(), pbs_port + 1));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), ElectraSpec, DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = mock_validator.do_submit_block::<ElectraSpec>(Some(SignedBlindedBeaconBlock::default())).await?;

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_submit_block(), 1);

    let response_body = serde_json::from_slice::<SubmitBlindedBlockResponse<ElectraSpec>>(&res.bytes().await?)?;
    assert_eq!(response_body.block_hash(), SubmitBlindedBlockResponse::<ElectraSpec>::default().block_hash());
    Ok(())
}

#[tokio::test]
async fn test_submit_block_too_large_deneb() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let pbs_port = 3900;

    let relays = vec![generate_mock_relay(pbs_port + 1, *pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer).with_large_body());
    tokio::spawn(start_mock_relay_service::<DenebSpec>(mock_state.clone(), pbs_port + 1));

    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DenebSpec, DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = mock_validator.do_submit_block::<DenebSpec>(None).await;

    // response size exceeds max size: max: 20971520
    assert_eq!(res.unwrap().status(), StatusCode::BAD_GATEWAY);
    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(())
}


#[tokio::test]
async fn test_submit_block_too_large_electra() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let pbs_port = 3950;

    let relays = vec![generate_mock_relay(pbs_port + 1, *pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer).with_large_body());
    tokio::spawn(start_mock_relay_service::<ElectraSpec>(mock_state.clone(), pbs_port + 1));

    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), ElectraSpec, DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = mock_validator.do_submit_block::<ElectraSpec>(None).await;

    // response size exceeds max size: max: 20971520
    assert_eq!(res.unwrap().status(), StatusCode::BAD_GATEWAY);
    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(())
}
