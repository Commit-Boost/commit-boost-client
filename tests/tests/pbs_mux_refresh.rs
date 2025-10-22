use std::{sync::Arc, time::Duration};

use cb_common::{
    config::{MuxConfig, MuxKeysLoader, PbsMuxes},
    interop::ssv::types::SSVValidator,
    signer::random_secret,
    types::Chain,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service},
    mock_ssv::{SsvMockState, create_mock_ssv_server},
    mock_validator::MockValidator,
    utils::{generate_mock_relay, get_pbs_static_config, to_pbs_config},
};
use eyre::Result;
use reqwest::StatusCode;
use tokio::sync::RwLock;
use tracing::info;
use url::Url;

#[tokio::test]
#[allow(unused_assignments)]
#[tracing_test::traced_test]
async fn test_auto_refresh() -> Result<()> {
    // This test reads the log files to verify behavior, so we can't attach a global
    // trace listener setup_test_env();

    // Generate 3 keys: one not in the mux relay, one in the relay, and one that
    // hasn't been added yet but will be later. The existing key isn't used but is
    // needed in the initial config since CB won't start a mux without at least one
    // key.
    let default_signer = random_secret();
    let default_pubkey = default_signer.public_key();
    let existing_mux_signer = random_secret();
    let existing_mux_pubkey = existing_mux_signer.public_key();
    let new_mux_signer = random_secret();
    let new_mux_pubkey = new_mux_signer.public_key();

    let chain = Chain::Hoodi;
    let pbs_port = 3710;

    // Start the mock SSV API server
    let ssv_api_port = pbs_port + 1;
    // Intentionally missing a trailing slash to ensure this is handled properly
    let ssv_api_url = Url::parse(&format!("http://localhost:{ssv_api_port}/api/v4"))?;
    let mock_ssv_state = SsvMockState {
        validators: Arc::new(RwLock::new(vec![SSVValidator {
            pubkey: existing_mux_pubkey.clone(),
        }])),
        force_timeout: Arc::new(RwLock::new(false)),
    };
    let ssv_server_handle =
        create_mock_ssv_server(ssv_api_port, Some(mock_ssv_state.clone())).await?;

    // Start a default relay for non-mux keys
    let default_relay_port = ssv_api_port + 1;
    let default_relay = generate_mock_relay(default_relay_port, default_pubkey.clone())?;
    let default_relay_state = Arc::new(MockRelayState::new(chain, default_signer.clone()));
    let default_relay_task =
        tokio::spawn(start_mock_relay_service(default_relay_state.clone(), default_relay_port));

    // Start a mock relay to be used by the mux
    let mux_relay_port = default_relay_port + 1;
    let mux_relay = generate_mock_relay(mux_relay_port, default_pubkey.clone())?;
    let mux_relay_id = mux_relay.id.clone().to_string();
    let mux_relay_state = Arc::new(MockRelayState::new(chain, default_signer));
    let mux_relay_task =
        tokio::spawn(start_mock_relay_service(mux_relay_state.clone(), mux_relay_port));

    // Create the registry mux
    let loader = MuxKeysLoader::Registry {
        enable_refreshing: true,
        node_operator_id: 1,
        registry: cb_common::config::NORegistry::SSV,
    };
    let muxes = PbsMuxes {
        muxes: vec![MuxConfig {
            id: mux_relay_id.clone(),
            loader: Some(loader),
            late_in_slot_time_ms: Some(u64::MAX),
            relays: vec![(*mux_relay.config).clone()],
            timeout_get_header_ms: Some(u64::MAX - 1),
            validator_pubkeys: vec![],
        }],
    };

    // Set up the PBS config
    let mut pbs_config = get_pbs_static_config(pbs_port);
    pbs_config.ssv_api_url = ssv_api_url.clone();
    pbs_config.mux_registry_refresh_interval_seconds = 1; // Refresh the mux every second
    let (mux_lookup, registry_muxes) = muxes.validate_and_fill(chain, &pbs_config).await?;
    let relays = vec![default_relay.clone()]; // Default relay only
    let mut config = to_pbs_config(chain, pbs_config, relays);
    config.all_relays.push(mux_relay.clone()); // Add the mux relay to just this field
    config.mux_lookup = Some(mux_lookup);
    config.registry_muxes = Some(registry_muxes);

    // Run PBS service
    let state = PbsState::new(config);
    let pbs_server = tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));
    info!("Started PBS server with pubkey {default_pubkey}");

    // Wait for the server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try to run a get_header on the new pubkey, which should use the default
    // relay only since it hasn't been seen in the mux yet
    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(Some(new_mux_pubkey.clone())).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(default_relay_state.received_get_header(), 1); // default relay was used
    assert_eq!(mux_relay_state.received_get_header(), 0); // mux relay was not used

    // Wait for the first refresh to complete
    let wait_for_refresh_time = Duration::from_secs(2);
    tokio::time::sleep(wait_for_refresh_time).await;

    // Check the logs to ensure a refresh happened
    assert!(logs_contain(&format!("fetched 1 pubkeys for registry mux {mux_relay_id}")));
    assert!(!logs_contain(&format!("fetched 2 pubkeys for registry mux {mux_relay_id}")));
    assert!(!logs_contain("adding new pubkey"));

    // Add another validator
    {
        let mut validators = mock_ssv_state.validators.write().await;
        validators.push(SSVValidator { pubkey: new_mux_pubkey.clone() });
        info!("Added new validator {new_mux_pubkey} to the SSV mock server");
    }

    // Wait for the next refresh to complete
    tokio::time::sleep(wait_for_refresh_time).await;

    // Check the logs to ensure the new pubkey was added
    assert!(logs_contain(&format!("fetched 2 pubkeys for registry mux {mux_relay_id}")));

    // Try to run a get_header on the new pubkey - now it should use the mux relay
    let res = mock_validator.do_get_header(Some(new_mux_pubkey.clone())).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(default_relay_state.received_get_header(), 1); // default relay was not used here
    assert_eq!(mux_relay_state.received_get_header(), 1); // mux relay was used

    // Now try to do a get_header with the old pubkey - it should only use the
    // default relay
    let res = mock_validator.do_get_header(Some(default_pubkey.clone())).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(default_relay_state.received_get_header(), 2); // default relay was used
    assert_eq!(mux_relay_state.received_get_header(), 1); // mux relay was not used

    // Finally, remove the original mux pubkey from the SSV server
    {
        let mut validators = mock_ssv_state.validators.write().await;
        validators.retain(|v| v.pubkey != existing_mux_pubkey);
        info!("Removed existing validator {existing_mux_pubkey} from the SSV mock server");
    }

    // Wait for the next refresh to complete
    tokio::time::sleep(wait_for_refresh_time).await;

    // Try to do a get_header with the removed pubkey - it should only use the
    // default relay
    let res = mock_validator.do_get_header(Some(existing_mux_pubkey.clone())).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(default_relay_state.received_get_header(), 3); // default relay was used
    assert_eq!(mux_relay_state.received_get_header(), 1); // mux relay was not used

    // Shut down the server handles
    pbs_server.abort();
    ssv_server_handle.abort();
    default_relay_task.abort();
    mux_relay_task.abort();

    Ok(())
}
