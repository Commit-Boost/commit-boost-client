use std::{collections::HashMap, sync::Arc, time::Duration};

use cb_common::{
    config::{HTTP_TIMEOUT_SECONDS_DEFAULT, MUXER_HTTP_MAX_LENGTH, RuntimeMuxConfig},
    interop::ssv::utils::fetch_ssv_pubkeys_from_url,
    signer::random_secret,
    types::Chain,
    utils::{ResponseReadError, set_ignore_content_length},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service},
    mock_ssv::{SsvMockState, TEST_HTTP_TIMEOUT, create_mock_ssv_server},
    mock_validator::MockValidator,
    utils::{
        bls_pubkey_from_hex_unchecked, generate_mock_relay, get_pbs_static_config, setup_test_env,
        to_pbs_config,
    },
};
use eyre::Result;
use reqwest::StatusCode;
use tokio::sync::RwLock;
use tracing::info;
use url::Url;

#[tokio::test]
/// Tests that a successful SSV network fetch is handled and parsed properly
async fn test_ssv_network_fetch() -> Result<()> {
    // Start the mock server
    let port = 30100;
    let _server_handle = create_mock_ssv_server(port, None).await?;
    let url =
        Url::parse(&format!("http://localhost:{port}/api/v4/test_chain/validators/in_operator/1"))
            .unwrap();
    let response =
        fetch_ssv_pubkeys_from_url(url, Duration::from_secs(HTTP_TIMEOUT_SECONDS_DEFAULT)).await?;

    // Make sure the response is correct
    // NOTE: requires that ssv_data.json dpesn't change
    assert_eq!(response.validators.len(), 3);
    let expected_pubkeys = [
        bls_pubkey_from_hex_unchecked(
            "967ba17a3e7f82a25aa5350ec34d6923e28ad8237b5a41efe2c5e325240d74d87a015bf04634f21900963539c8229b2a",
        ),
        bls_pubkey_from_hex_unchecked(
            "ac769e8cec802e8ffee34de3253be8f438a0c17ee84bdff0b6730280d24b5ecb77ebc9c985281b41ee3bda8663b6658c",
        ),
        bls_pubkey_from_hex_unchecked(
            "8c866a5a05f3d45c49b457e29365259021a509c5daa82e124f9701a960ee87b8902e87175315ab638a3d8b1115b23639",
        ),
    ];
    for (i, validator) in response.validators.iter().enumerate() {
        assert_eq!(validator.pubkey, expected_pubkeys[i]);
    }

    // Clean up the server handle
    _server_handle.abort();

    Ok(())
}

#[tokio::test]
/// Tests that the SSV network fetch is handled properly when the response's
/// body is too large
async fn test_ssv_network_fetch_big_data() -> Result<()> {
    // Start the mock server
    let port = 30101;
    let server_handle = cb_tests::mock_ssv::create_mock_ssv_server(port, None).await?;
    let url = Url::parse(&format!("http://localhost:{port}/big_data")).unwrap();
    let response = fetch_ssv_pubkeys_from_url(url, Duration::from_secs(120)).await;

    // The response should fail due to content length being too big
    match response {
        Ok(_) => {
            panic!("Expected an error due to big content length, but got a successful response")
        }
        Err(e) => match e.downcast_ref::<ResponseReadError>() {
            Some(ResponseReadError::PayloadTooLarge { max, content_length, raw }) => {
                assert_eq!(*max, MUXER_HTTP_MAX_LENGTH);
                assert!(*content_length > MUXER_HTTP_MAX_LENGTH);
                assert!(raw.is_empty());
            }
            _ => panic!("Expected PayloadTooLarge error, got: {}", e),
        },
    }

    // Clean up the server handle
    server_handle.abort();

    Ok(())
}

#[tokio::test]
/// Tests that the SSV network fetch is handled properly when the request
/// times out
async fn test_ssv_network_fetch_timeout() -> Result<()> {
    // Start the mock server
    let port = 30102;
    let state = SsvMockState {
        validators: Arc::new(RwLock::new(vec![])),
        force_timeout: Arc::new(RwLock::new(true)),
    };
    let server_handle = create_mock_ssv_server(port, Some(state)).await?;
    let url =
        Url::parse(&format!("http://localhost:{port}/api/v4/test_chain/validators/in_operator/1"))
            .unwrap();
    let response = fetch_ssv_pubkeys_from_url(url, Duration::from_secs(TEST_HTTP_TIMEOUT)).await;

    // The response should fail due to timeout
    assert!(response.is_err(), "Expected timeout error, but got success");
    if let Err(e) = response {
        assert!(e.to_string().contains("timed out"), "Expected timeout error, got: {}", e);
    }

    // Clean up the server handle
    server_handle.abort();

    Ok(())
}

#[tokio::test]
/// Tests that the SSV network fetch is handled properly when the response's
/// content-length header is missing
async fn test_ssv_network_fetch_big_data_without_content_length() -> Result<()> {
    // Start the mock server
    let port = 30103;
    set_ignore_content_length(true);
    let server_handle = create_mock_ssv_server(port, None).await?;
    let url = Url::parse(&format!("http://localhost:{port}/big_data")).unwrap();
    let response = fetch_ssv_pubkeys_from_url(url, Duration::from_secs(120)).await;

    // The response should fail due to the body being too big
    match response {
        Ok(_) => {
            panic!("Expected an error due to excessive data, but got a successful response")
        }
        Err(e) => match e.downcast_ref::<ResponseReadError>() {
            Some(ResponseReadError::PayloadTooLarge { max, content_length, raw }) => {
                assert_eq!(*max, MUXER_HTTP_MAX_LENGTH);
                assert_eq!(*content_length, 0);
                assert!(!raw.is_empty());
            }
            _ => panic!("Expected PayloadTooLarge error, got: {}", e),
        },
    }

    // Clean up the server handle
    server_handle.abort();

    Ok(())
}

#[tokio::test]
async fn test_mux() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_port = 3700;

    let mux_relay_1 = generate_mock_relay(pbs_port + 1, pubkey.clone())?;
    let mux_relay_2 = generate_mock_relay(pbs_port + 2, pubkey.clone())?;
    let default_relay = generate_mock_relay(pbs_port + 3, pubkey.clone())?;

    // Run 3 mock relays
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 1));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 2));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), pbs_port + 3));

    // Register all relays in PBS config
    let relays = vec![default_relay.clone()];
    let mut config = to_pbs_config(chain, get_pbs_static_config(pbs_port), relays);
    config.all_relays = vec![mux_relay_1.clone(), mux_relay_2.clone(), default_relay.clone()];

    // Configure mux for two relays
    let mux = RuntimeMuxConfig {
        id: String::from("test"),
        config: config.pbs_config.clone(),
        relays: vec![mux_relay_1, mux_relay_2],
    };

    // Bind mux to a specific validator key
    let validator_pubkey = random_secret().public_key();
    config.mux_lookup = Some(HashMap::from([(validator_pubkey.clone(), mux)]));

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
