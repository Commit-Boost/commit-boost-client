use std::{sync::Arc, time::Duration};

use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use cb_common::{
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
async fn test_register_validators() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk());

    let chain = Chain::Holesky;
    let pbs_port = 4000;

    // Run a mock relay
    let relays = vec![generate_mock_relay(pbs_port + 1, pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 1));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

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
async fn test_register_validators_returns_422_if_request_is_malformed() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk());

    let chain = Chain::Holesky;
    let pbs_port = 4100;

    // Run a mock relay
    let relays = vec![generate_mock_relay(pbs_port + 1, pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 1));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    let url = mock_validator.comm_boost.register_validator_url().unwrap();
    info!("Sending register validator");

    // Bad fee recipient
    let bad_json = r#"[{
        "message": {
            "fee_recipient": "0xaa",
            "gas_limit": "100000",
            "timestamp": "1000000",
            "pubkey": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "signature": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }]"#;

    let res = mock_validator
        .comm_boost
        .client
        .post(url.clone())
        .header("Content-Type", "application/json")
        .body(bad_json)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Bad pubkey
    let bad_json = r#"[{
        "message": {
            "fee_recipient": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "gas_limit": "100000",
            "timestamp": "1000000",
            "pubkey": "0xbbb"
        },
        "signature": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }]"#;

    let res = mock_validator
        .comm_boost
        .client
        .post(url.clone())
        .header("Content-Type", "application/json")
        .body(bad_json)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Bad signature
    let bad_json = r#"[{
        "message": {
            "fee_recipient": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "gas_limit": "100000",
            "timestamp": "1000000",
            "pubkey": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "signature": "0xcccc"
    }]"#;

    let res = mock_validator
        .comm_boost
        .client
        .post(url.clone())
        .header("Content-Type", "application/json")
        .body(bad_json)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // gas limit too high
    let bad_json = r#"[{
        "message": {
            "fee_recipient": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "gas_limit": "10000000000000000000000000000000000000000000000000000000",
            "timestamp": "1000000",
            "pubkey": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        },
        "signature": "0xcccc"
    }]"#;

    let res = mock_validator
        .comm_boost
        .client
        .post(url.clone())
        .header("Content-Type", "application/json")
        .body(bad_json)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // timestamp too high
    let bad_json = r#"[{
            "message": {
                "fee_recipient": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "gas_limit": "1000000",
                "timestamp": "10000000000000000000000000000000000000000000000000000000",
                "pubkey": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            },
            "signature": "0xcccc"
        }]"#;

    let res = mock_validator
        .comm_boost
        .client
        .post(url.clone())
        .header("Content-Type", "application/json")
        .body(bad_json)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    assert_eq!(mock_state.received_register_validator(), 0);
    Ok(())
}

#[tokio::test]
async fn test_register_validators_does_not_retry_on_429() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk());

    let chain = Chain::Holesky;
    let pbs_port = 4200;

    // Set up mock relay state and override response to 429
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    mock_state.set_response_override(StatusCode::TOO_MANY_REQUESTS);

    // Run a mock relay
    let relays = vec![generate_mock_relay(pbs_port + 1, pubkey)?];
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 1));

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state.clone()));

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
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk());

    let chain = Chain::Holesky;
    let pbs_port = 4300;

    // Set up internal mock relay with 500 response override
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    mock_state.set_response_override(StatusCode::INTERNAL_SERVER_ERROR); // 500

    let relays = vec![generate_mock_relay(pbs_port + 1, pubkey)?];
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 1));

    // Set retry limit to 3
    let mut pbs_config = get_pbs_config(pbs_port);
    pbs_config.register_validator_retry_limit = 3;

    let config = to_pbs_config(chain, pbs_config, relays);
    let state = PbsState::new(config);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state.clone()));

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
