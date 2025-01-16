use std::{
    sync::Arc,
    time::Duration,
};

use cb_common::{
    pbs::SubmitBlindedBlockResponse, signer::{random_secret, BlsPublicKey}, types::Chain, utils::blst_pubkey_to_alloy
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{start_mock_relay_service, MockRelayState},
    mock_validator::MockValidator,
    utils::{generate_mock_relay, setup_test_env, to_pbs_config, get_pbs_static_config},
};
use eyre::Result;
use tracing::info;

#[tokio::test]
async fn test_submit_block() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let pbs_port = 3700;

    // Run a mock relay
    let relays = vec![generate_mock_relay(pbs_port + 1, *pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 1));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = mock_validator.do_submit_block().await.expect("failed to submit block");

    assert_eq!(mock_state.received_submit_block(), 1);

    let expected_response = SubmitBlindedBlockResponse::default();
    assert_eq!(res.block_hash(), expected_response.block_hash());
    Ok(())
}

#[tokio::test]
async fn test_submit_block_too_large() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let pbs_port = 3600;

    let relays = vec![generate_mock_relay(pbs_port + 1, *pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer).with_large_body());
    dbg!(&mock_state.large_body());
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 1));

    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = mock_validator.do_submit_block().await;
    // dbg!(&res);
    assert!(res.is_err());

    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(())
}
