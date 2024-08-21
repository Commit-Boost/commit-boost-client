use std::{net::SocketAddr, sync::Arc, time::Duration, u64};

use alloy::primitives::U256;
use cb_common::{
    config::{PbsConfig, PbsModuleConfig}, pbs::RelayClient, signer::ConsensusSigner, types::Chain
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{mock_relay_app_router, MockRelayState},
    mock_validator::MockValidator,
    utils::{generate_mock_relay, setup_test_env},
};
use eyre::Result;
use tokio::net::TcpListener;
use tracing::info;

async fn start_mock_relay_service(state: Arc<MockRelayState>, port: u16) -> Result<()> {
    let app = mock_relay_app_router(state);

    let socket = SocketAddr::new("0.0.0.0".parse()?, port);
    let listener = TcpListener::bind(socket).await?;

    info!("Starting mock relay on {socket:?}");
    axum::serve(listener, app).await?;
    Ok(())
}

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
        event_publiher: None,
        relays,
    }
}

#[tokio::test]
async fn test_get_header() -> Result<()> {
    setup_test_env();
    let signer = ConsensusSigner::new_random();

    let chain = Chain::Holesky;
    let port = 3000;

    let mock_relay = generate_mock_relay(port + 1, signer.pubkey())?;
    let mock_state = Arc::new(MockRelayState::new(chain, signer, 0));
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
    let signer = ConsensusSigner::new_random();

    let chain = Chain::Holesky;
    let port = 3100;

    let relays = vec![
        generate_mock_relay(port + 1, signer.pubkey())?,
        generate_mock_relay(port + 2, signer.pubkey())?,
    ];
    let mock_state = Arc::new(MockRelayState::new(chain, signer, 0));
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
    let signer = ConsensusSigner::new_random();

    let chain = Chain::Holesky;
    let port = 3300;

    let relays = vec![generate_mock_relay(port + 1, signer.pubkey())?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer, 0));
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
    let signer = ConsensusSigner::new_random();

    let chain = Chain::Holesky;
    let port = 3400;

    let relays = vec![generate_mock_relay(port + 1, signer.pubkey())?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer, 0));
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
