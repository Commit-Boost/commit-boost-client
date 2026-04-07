use std::{path::PathBuf, sync::Arc, time::Duration};

use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use cb_common::{
    signer::random_secret,
    types::{BlsPublicKey, Chain},
};
use cb_pbs::{PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::MockValidator,
    utils::{
        generate_mock_relay, get_free_listener, get_pbs_config, setup_test_env, to_pbs_config,
    },
};
use eyre::Result;
use reqwest::StatusCode;
use tracing::info;

#[tokio::test]
async fn test_register_validators() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    // Run a mock relay
    let relays = vec![generate_mock_relay(relay_port, pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener(state, pbs_listener));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending register validator");

    let registration: ValidatorRegistration = serde_json::from_str(
        r#"{
        "message": {
            "fee_recipient": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "gas_limit": "100000",
            "timestamp": "1000000",
            "pubkey": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "signature": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }"#,
    )?;

    let registrations = vec![registration];
    let res = mock_validator.do_register_custom_validators(registrations).await?;

    assert_eq!(mock_state.received_register_validator(), 1);
    assert_eq!(res.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn test_register_validators_does_not_retry_on_429() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    // Set up mock relay state and override response to 429
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    mock_state.set_response_override(StatusCode::TOO_MANY_REQUESTS);

    // Run a mock relay
    let relays = vec![generate_mock_relay(relay_port, pubkey)?];
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener(state.clone(), pbs_listener));

    // Leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending register validator to test 429 response");

    let registration: ValidatorRegistration = serde_json::from_str(
        r#"{
        "message": {
            "fee_recipient": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "gas_limit": "100000",
            "timestamp": "1000000",
            "pubkey": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "signature": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }"#,
    )?;

    let registrations = vec![registration];
    let res = mock_validator.do_register_custom_validators(registrations).await?;

    // Should only be called once (no retry)
    assert_eq!(mock_state.received_register_validator(), 1);
    // Expected to return 429 status code
    // But it returns `No relay passed register_validator successfully` with 502
    // status code
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);

    Ok(())
}

#[tokio::test]
async fn test_register_validators_retries_on_500() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    // Set up internal mock relay with 500 response override
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    mock_state.set_response_override(StatusCode::INTERNAL_SERVER_ERROR); // 500

    let relays = vec![generate_mock_relay(relay_port, pubkey)?];
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    // Set retry limit to 3
    let mut pbs_config = get_pbs_config(pbs_port);
    pbs_config.register_validator_retry_limit = 3;

    let config = to_pbs_config(chain, pbs_config, relays);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener(state.clone(), pbs_listener));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending register validator to test retry on 500");

    let registration: ValidatorRegistration = serde_json::from_str(
        r#"{
        "message": {
            "fee_recipient": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "gas_limit": "100000",
            "timestamp": "1000000",
            "pubkey": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "signature": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }"#,
    )?;

    let registrations = vec![registration];
    let _ = mock_validator.do_register_custom_validators(registrations).await;

    // Should retry 3 times (0, 1, 2) → total 3 calls
    assert_eq!(mock_state.received_register_validator(), 3);

    Ok(())
}
