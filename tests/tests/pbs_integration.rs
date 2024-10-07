use std::{sync::Arc, time::Duration, u64};

use alloy::primitives::U256;
use cb_common::{
    config::{PbsConfig, PbsModuleConfig},
    pbs::RelayClient,
    signer::{schemes::bls::random_secret, BlsPublicKey},
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

fn get_pbs_static_config(port: u16) -> PbsConfig {
    PbsConfig {
        port,
        relay_check: true,
        timeout_get_header_ms: u64::MAX,
        timeout_get_payload_ms: u64::MAX,
        timeout_register_validator_ms: u64::MAX,
        skip_sigverify: false,
        min_bid_wei: U256::ZERO,
        late_in_slot_time_ms: u64::MAX,
        relay_monitors: vec![],
    }
}

fn to_pbs_config(chain: Chain, pbs_config: PbsConfig, relays: Vec<RelayClient>) -> PbsModuleConfig {
    PbsModuleConfig {
        chain,
        pbs_config: Arc::new(pbs_config),
        signer_client: None,
        event_publisher: None,
        relays,
    }
}

#[tokio::test]
async fn test_get_header() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let port = 3000;

    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    let mock_relay = generate_mock_relay(port + 1, *pubkey)?;
    tokio::spawn(start_mock_relay_service(mock_state.clone(), port + 1));

    let config = to_pbs_config(chain, get_pbs_static_config(port), vec![mock_relay]);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header().await;

    assert!(res.is_ok());
    assert_eq!(mock_state.received_get_header(), 1);
    Ok(())
}

#[tokio::test]
async fn test_get_status() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let port = 3100;

    let relays =
        vec![generate_mock_relay(port + 1, *pubkey)?, generate_mock_relay(port + 2, *pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), port + 1));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), port + 2));

    let config = to_pbs_config(chain, get_pbs_static_config(port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(port)?;
    info!("Sending get status");
    let res = mock_validator.do_get_status().await;

    assert!(res.is_ok());
    assert_eq!(mock_state.received_get_status(), 2);
    Ok(())
}

#[tokio::test]
async fn test_register_validators() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let port = 3300;

    let relays = vec![generate_mock_relay(port + 1, *pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), port + 1));

    let config = to_pbs_config(chain, get_pbs_static_config(port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(port)?;
    info!("Sending register validator");
    let res = mock_validator.do_register_validator().await;

    assert!(res.is_ok());
    assert_eq!(mock_state.received_register_validator(), 1);
    Ok(())
}

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

    let config = to_pbs_config(chain, get_pbs_static_config(port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(port)?;
    info!("Sending submit block");
    let res = mock_validator.do_submit_block().await;

    assert!(res.is_ok());
    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(())
}
