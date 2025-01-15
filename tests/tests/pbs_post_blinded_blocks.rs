mod common;

use std::{
    sync::Arc,
    time::Duration,
};

use cb_common::{
    signer::{random_secret, BlsPublicKey},
    types::Chain,
    utils::blst_pubkey_to_alloy,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{start_mock_relay_service, MockRelayState},
    mock_validator::MockValidator,
    utils::{generate_mock_relay, setup_test_env},
};
use eyre::Result;
use tracing::info;

#[tokio::test]
async fn test_submit_block() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let port = 3400;

    let relays = vec![generate_mock_relay(port + 1, *pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), port + 1));

    let config = common::to_pbs_config(chain, common::get_pbs_static_config(port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(port)?;
    info!("Sending submit block");
    let res = mock_validator.do_submit_block().await;

    assert!(res.is_err());
    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(())
}

#[tokio::test]
async fn test_submit_block_too_large() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let port = 3500;

    let relays = vec![generate_mock_relay(port + 1, *pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer).with_large_body());
    tokio::spawn(start_mock_relay_service(mock_state.clone(), port + 1));

    let config = common::to_pbs_config(chain, common::get_pbs_static_config(port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(port)?;
    info!("Sending submit block");
    let res = mock_validator.do_submit_block().await;

    assert!(res.is_err());
    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(())
}
