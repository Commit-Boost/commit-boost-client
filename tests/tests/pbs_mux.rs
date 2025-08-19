use std::{collections::HashMap, sync::Arc, time::Duration};

use cb_common::{
    config::RuntimeMuxConfig,
    signer::{random_secret, BlsPublicKey},
    types::Chain,
    utils::blst_pubkey_to_alloy,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{start_mock_relay_service, MockRelayState},
    mock_validator::MockValidator,
    utils::{generate_mock_relay, get_pbs_config, setup_test_env, to_pbs_config},
};
use eyre::Result;
use reqwest::StatusCode;
use tracing::info;

#[tokio::test]
async fn test_mux() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk());

    let chain = Chain::Holesky;
    let pbs_port = 3700;

    let mux_relay_1 = generate_mock_relay(pbs_port + 1, pubkey)?;
    let mux_relay_2 = generate_mock_relay(pbs_port + 2, pubkey)?;
    let default_relay = generate_mock_relay(pbs_port + 3, pubkey)?;

    // Run 3 mock relays
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 1));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 2));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 3));

    // Register all relays in PBS config
    let relays = vec![default_relay.clone()];
    let mut config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    config.all_relays = vec![mux_relay_1.clone(), mux_relay_2.clone(), default_relay.clone()];

    // Configure mux for two relays
    let mux = RuntimeMuxConfig {
        id: String::from("test"),
        config: config.pbs_config.clone(),
        relays: vec![mux_relay_1, mux_relay_2],
    };

    // Bind mux to a specific validator key
    let validator_pubkey = blst_pubkey_to_alloy(&random_secret().sk_to_pk());
    config.muxes = Some(HashMap::from([(validator_pubkey, mux)]));

    // Run PBS service
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send default request without specifying a validator key
    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header with default");
    assert_eq!(mock_validator.do_get_header(None).await?.status(), StatusCode::OK);
    assert_eq!(mock_state.received_get_header(), 1); // only default relay was used

    // Send request specifying a validator key to use mux
    info!("Sending get header with mux");
    assert_eq!(
        mock_validator.do_get_header(Some(validator_pubkey)).await?.status(),
        StatusCode::OK
    );
    assert_eq!(mock_state.received_get_header(), 3); // two mux relays were used

    // Status requests should go to all relays
    info!("Sending get status");
    assert_eq!(mock_validator.do_get_status().await?.status(), StatusCode::OK);
    assert_eq!(mock_state.received_get_status(), 3); // default + 2 mux relays were used

    // Register requests should go to all relays
    info!("Sending register validator");
    assert_eq!(mock_validator.do_register_validator().await?.status(), StatusCode::OK);
    assert_eq!(mock_state.received_register_validator(), 3); // default + 2 mux relays were used

    // v1 Submit block requests should go to all relays
    info!("Sending submit block v1");
    assert_eq!(mock_validator.do_submit_block_v1(None).await?.status(), StatusCode::OK);
    assert_eq!(mock_state.received_submit_block(), 3); // default + 2 mux relays were used

    // v2 Submit block requests should go to all relays
    info!("Sending submit block v2");
    assert_eq!(mock_validator.do_submit_block_v2(None).await?.status(), StatusCode::ACCEPTED);
    assert_eq!(mock_state.received_submit_block(), 6); // default + 2 mux relays were used

    Ok(())
}
