use std::{sync::Arc, time::Duration};

use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use cb_common::{
    signer::{random_secret, BlsPublicKey},
    pbs::{ElectraSpec, DenebSpec},
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
async fn test_register_validators_deneb() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let pbs_port = 4000;

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
async fn test_register_validators_electra() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let pbs_port = 4050;

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
async fn test_register_validators_returns_422_if_request_is_malformed_deneb() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let pbs_port = 4100;

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
async fn test_register_validators_returns_422_if_request_is_malformed_electra() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey: BlsPublicKey = blst_pubkey_to_alloy(&signer.sk_to_pk()).into();

    let chain = Chain::Holesky;
    let pbs_port = 4150;

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
