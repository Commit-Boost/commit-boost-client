use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy::primitives::U256;
use cb_common::{
    config::{
        HTTP_TIMEOUT_SECONDS_DEFAULT, MUXER_HTTP_MAX_LENGTH, MuxConfig, MuxKeysLoader, PbsMuxes,
        RuntimeMuxConfig,
    },
    interop::ssv::{
        types::{SSVNodeValidator, SSVPublicValidator},
        utils::{request_ssv_pubkeys_from_public_api, request_ssv_pubkeys_from_ssv_node},
    },
    signer::random_secret,
    types::Chain,
    utils::{ResponseReadError, set_ignore_content_length},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service},
    mock_ssv_node::{SsvNodeMockState, create_mock_ssv_node_server},
    mock_ssv_public::{PublicSsvMockState, TEST_HTTP_TIMEOUT, create_mock_public_ssv_server},
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
/// from the public API
async fn test_ssv_public_network_fetch() -> Result<()> {
    // Start the mock server
    let port = 30100;
    let server_handle = create_mock_public_ssv_server(port, None).await?;
    let url =
        Url::parse(&format!("http://localhost:{port}/api/v4/test_chain/validators/in_operator/1"))
            .unwrap();
    let response =
        request_ssv_pubkeys_from_public_api(url, Duration::from_secs(HTTP_TIMEOUT_SECONDS_DEFAULT))
            .await?;

    // Make sure the response is correct
    // NOTE: requires that ssv_valid_public.json doesn't change
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
    server_handle.abort();

    Ok(())
}

#[tokio::test]
/// Tests that the SSV network fetch is handled properly when the response's
/// body is too large
async fn test_ssv_network_fetch_big_data() -> Result<()> {
    // Start the mock server
    let port = 30101;
    let server_handle =
        cb_tests::mock_ssv_public::create_mock_public_ssv_server(port, None).await?;
    let url = Url::parse(&format!("http://localhost:{port}/big_data")).unwrap();
    let response = request_ssv_pubkeys_from_public_api(url, Duration::from_secs(120)).await;

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
    let state = PublicSsvMockState {
        validators: Arc::new(RwLock::new(vec![])),
        force_timeout: Arc::new(RwLock::new(true)),
    };
    let server_handle = create_mock_public_ssv_server(port, Some(state)).await?;
    let url =
        Url::parse(&format!("http://localhost:{port}/api/v4/test_chain/validators/in_operator/1"))
            .unwrap();
    let response =
        request_ssv_pubkeys_from_public_api(url, Duration::from_secs(TEST_HTTP_TIMEOUT)).await;

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
    let server_handle = create_mock_public_ssv_server(port, None).await?;
    let url = Url::parse(&format!("http://localhost:{port}/big_data")).unwrap();
    let response = request_ssv_pubkeys_from_public_api(url, Duration::from_secs(120)).await;

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
/// Tests that a successful SSV network fetch is handled and parsed properly
/// from the node API
async fn test_ssv_node_network_fetch() -> Result<()> {
    // Start the mock server
    let port = 30104;
    let _server_handle = create_mock_ssv_node_server(port, None).await?;
    let url = Url::parse(&format!("http://localhost:{port}/v1/validators")).unwrap();
    let response = request_ssv_pubkeys_from_ssv_node(
        url,
        U256::from(1),
        Duration::from_secs(HTTP_TIMEOUT_SECONDS_DEFAULT),
    )
    .await?;

    // Make sure the response is correct
    // NOTE: requires that ssv_valid_node.json doesn't change
    assert_eq!(response.data.len(), 1);
    let expected_pubkeys = [bls_pubkey_from_hex_unchecked(
        "aa370f6250d421d00437b9900407a7ad93b041aeb7259d99b55ab8b163277746680e93e841f87350737bceee46aa104d",
    )];
    for (i, validator) in response.data.iter().enumerate() {
        assert_eq!(validator.public_key, expected_pubkeys[i]);
    }

    // Clean up the server handle
    _server_handle.abort();

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

/// Tests the SSV mux with dynamic registry fetching from an SSV node
#[tokio::test]
async fn test_ssv_multi_with_node() -> Result<()> {
    // Generate keys
    let signer = random_secret();
    let pubkey = signer.public_key();
    let signer2 = random_secret();
    let pubkey2 = signer2.public_key();

    let chain = Chain::Hoodi;
    let pbs_port = 3711;

    // Start the mock SSV node
    let ssv_node_port = pbs_port + 1;
    let ssv_node_url = Url::parse(&format!("http://localhost:{ssv_node_port}/v1/"))?;
    let mock_ssv_node_state = SsvNodeMockState {
        validators: Arc::new(RwLock::new(vec![
            SSVNodeValidator { public_key: pubkey.clone() },
            SSVNodeValidator { public_key: pubkey2.clone() },
        ])),
        force_timeout: Arc::new(RwLock::new(false)),
    };
    let ssv_node_handle =
        create_mock_ssv_node_server(ssv_node_port, Some(mock_ssv_node_state.clone())).await?;

    // Start the mock SSV public API
    let ssv_public_port = ssv_node_port + 1;
    let ssv_public_url = Url::parse(&format!("http://localhost:{ssv_public_port}/api/v4/"))?;
    let mock_ssv_public_state = PublicSsvMockState {
        validators: Arc::new(RwLock::new(vec![SSVPublicValidator { pubkey: pubkey.clone() }])),
        force_timeout: Arc::new(RwLock::new(false)),
    };
    let ssv_public_handle =
        create_mock_public_ssv_server(ssv_public_port, Some(mock_ssv_public_state.clone())).await?;

    // Start a mock relay to be used by the mux
    let relay_port = ssv_public_port + 1;
    let relay = generate_mock_relay(relay_port, pubkey.clone())?;
    let relay_id = relay.id.clone().to_string();
    let relay_state = Arc::new(MockRelayState::new(chain, signer));
    let relay_task = tokio::spawn(start_mock_relay_service(relay_state.clone(), relay_port));

    // Create the registry mux
    let loader = MuxKeysLoader::Registry {
        enable_refreshing: true,
        node_operator_id: 1,
        lido_module_id: None,
        registry: cb_common::config::NORegistry::SSV,
    };
    let muxes = PbsMuxes {
        muxes: vec![MuxConfig {
            id: relay_id.clone(),
            loader: Some(loader),
            late_in_slot_time_ms: Some(u64::MAX),
            relays: vec![(*relay.config).clone()],
            timeout_get_header_ms: Some(u64::MAX - 1),
            validator_pubkeys: vec![],
        }],
    };

    // Set up the PBS config
    let mut pbs_config = get_pbs_static_config(pbs_port);
    pbs_config.ssv_node_api_url = ssv_node_url.clone();
    pbs_config.ssv_public_api_url = ssv_public_url.clone();
    pbs_config.mux_registry_refresh_interval_seconds = 1; // Refresh the mux every second
    let (mux_lookup, registry_muxes) = muxes.validate_and_fill(chain, &pbs_config).await?;
    let relays = vec![relay.clone()]; // Default relay only
    let mut config = to_pbs_config(chain, pbs_config, relays);
    config.all_relays.push(relay.clone()); // Add the mux relay to just this field
    config.mux_lookup = Some(mux_lookup);
    config.registry_muxes = Some(registry_muxes);

    // Run PBS service
    let state = PbsState::new(config);
    let pbs_server = tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));
    info!("Started PBS server with pubkey {pubkey}");

    // Wait for the server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try to run a get_header on the new pubkey, which should use the default
    // relay only since it hasn't been seen in the mux yet
    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(Some(pubkey2.clone())).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(relay_state.received_get_header(), 1); // pubkey2 was loaded from the SSV node 

    // Shut down the server handles
    pbs_server.abort();
    ssv_node_handle.abort();
    ssv_public_handle.abort();
    relay_task.abort();

    Ok(())
}

/// Tests the SSV mux with dynamic registry fetching from the public SSV API
/// when the local node is down
#[tokio::test]
async fn test_ssv_multi_with_public() -> Result<()> {
    // Generate keys
    let signer = random_secret();
    let pubkey = signer.public_key();
    let signer2 = random_secret();
    let pubkey2 = signer2.public_key();

    let chain = Chain::Hoodi;
    let pbs_port = 3720;

    // Start the mock SSV node
    let ssv_node_port = pbs_port + 1;
    let ssv_node_url = Url::parse(&format!("http://localhost:{ssv_node_port}/v1/"))?;

    // Don't start the SSV node server to simulate it being down
    // let ssv_node_handle = create_mock_ssv_node_server(ssv_node_port,
    // Some(mock_ssv_node_state.clone())).await?;

    // Start the mock SSV public API
    let ssv_public_port = ssv_node_port + 1;
    let ssv_public_url = Url::parse(&format!("http://localhost:{ssv_public_port}/api/v4/"))?;
    let mock_ssv_public_state = PublicSsvMockState {
        validators: Arc::new(RwLock::new(vec![
            SSVPublicValidator { pubkey: pubkey.clone() },
            SSVPublicValidator { pubkey: pubkey2.clone() },
        ])),
        force_timeout: Arc::new(RwLock::new(false)),
    };
    let ssv_public_handle =
        create_mock_public_ssv_server(ssv_public_port, Some(mock_ssv_public_state.clone())).await?;

    // Start a mock relay to be used by the mux
    let relay_port = ssv_public_port + 1;
    let relay = generate_mock_relay(relay_port, pubkey.clone())?;
    let relay_id = relay.id.clone().to_string();
    let relay_state = Arc::new(MockRelayState::new(chain, signer));
    let relay_task = tokio::spawn(start_mock_relay_service(relay_state.clone(), relay_port));

    // Create the registry mux
    let loader = MuxKeysLoader::Registry {
        enable_refreshing: true,
        node_operator_id: 1,
        lido_module_id: None,
        registry: cb_common::config::NORegistry::SSV,
    };
    let muxes = PbsMuxes {
        muxes: vec![MuxConfig {
            id: relay_id.clone(),
            loader: Some(loader),
            late_in_slot_time_ms: Some(u64::MAX),
            relays: vec![(*relay.config).clone()],
            timeout_get_header_ms: Some(u64::MAX - 1),
            validator_pubkeys: vec![],
        }],
    };

    // Set up the PBS config
    let mut pbs_config = get_pbs_static_config(pbs_port);
    pbs_config.ssv_node_api_url = ssv_node_url.clone();
    pbs_config.ssv_public_api_url = ssv_public_url.clone();
    pbs_config.mux_registry_refresh_interval_seconds = 1; // Refresh the mux every second
    let (mux_lookup, registry_muxes) = muxes.validate_and_fill(chain, &pbs_config).await?;
    let relays = vec![relay.clone()]; // Default relay only
    let mut config = to_pbs_config(chain, pbs_config, relays);
    config.all_relays.push(relay.clone()); // Add the mux relay to just this field
    config.mux_lookup = Some(mux_lookup);
    config.registry_muxes = Some(registry_muxes);

    // Run PBS service
    let state = PbsState::new(config);
    let pbs_server = tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));
    info!("Started PBS server with pubkey {pubkey}");

    // Wait for the server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try to run a get_header on the new pubkey, which should use the default
    // relay only since it hasn't been seen in the mux yet
    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(Some(pubkey2.clone())).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(relay_state.received_get_header(), 1); // pubkey2 was loaded from the SSV public API 

    // Shut down the server handles
    pbs_server.abort();
    //ssv_node_handle.abort();
    ssv_public_handle.abort();
    relay_task.abort();

    Ok(())
}
