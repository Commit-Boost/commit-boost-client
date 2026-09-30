use std::{io::Write, path::PathBuf, sync::Arc, time::Duration};

use cb_common::{signer::random_secret, types::Chain};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState, STATUS_ENDPOINT_TAG};
use cb_tests::{
    mock_relay::{
        MockRelayState, start_mock_relay_service, start_mock_relay_service_with_listener,
    },
    mock_validator::MockValidator,
    utils::{
        generate_mock_relay, generate_mock_relay_with_api_key_file, get_free_listener,
        get_pbs_config, setup_test_env, to_pbs_config,
    },
};
use eyre::Result;
use reqwest::StatusCode;
use tracing::info;

#[tokio::test]
async fn test_get_status() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_port = 3500;
    let relay_0_port = pbs_port + 1;
    let relay_1_port = pbs_port + 2;

    let relays = vec![
        generate_mock_relay(relay_0_port, pubkey.clone())?,
        generate_mock_relay(relay_1_port, pubkey)?,
    ];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), relay_0_port));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), relay_1_port));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays.clone());
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get status");
    let res = mock_validator.do_get_status().await.expect("failed to get status");
    assert_eq!(res.status(), StatusCode::OK);

    // Expect two statuses since two relays in config
    assert_eq!(mock_state.received_get_status(), 2);
    Ok(())
}

#[tokio::test]
async fn test_get_status_returns_502_if_relay_down() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_port = 3600;
    let relay_port = pbs_port + 1;

    let relays = vec![generate_mock_relay(relay_port, pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));

    // Don't start the relay
    // tokio::spawn(start_mock_relay_service(mock_state.clone(), relay_port));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays.clone());
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get status");
    let res = mock_validator.do_get_status().await.expect("failed to get status");
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY); // 502 error

    // Expect no statuses since relay is down
    assert_eq!(mock_state.received_get_status(), 0);
    Ok(())
}

#[tokio::test]
async fn test_get_status_sends_api_key_from_file() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;

    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();
    let relay_listener = get_free_listener().await;
    let relay_port = relay_listener.local_addr()?.port();

    let mut key_file = tempfile::NamedTempFile::new()?;
    key_file.write_all(b"file-only-api-key\n")?;
    let relays = vec![generate_mock_relay_with_api_key_file(relay_port, pubkey, key_file.path())?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    let res = mock_validator.do_get_status().await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        mock_state.api_key_seen(STATUS_ENDPOINT_TAG).as_deref(),
        Some("file-only-api-key"),
        "the relay must receive the key from the file, without its trailing newline"
    );
    Ok(())
}
