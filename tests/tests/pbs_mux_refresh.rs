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
    utils::{generate_mock_relay, get_pbs_static_config, to_pbs_config},
};
use eyre::Result;
use tokio::sync::RwLock;
use tracing::info;
use url::Url;

#[tokio::test]
#[allow(unused_assignments)]
#[tracing_test::traced_test]
async fn test_auto_refresh() -> Result<()> {
    // This test reads the log files to verify behavior, so we can't attach a global
    // trace listener setup_test_env();

    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Hoodi;
    let pbs_port = 3710;

    // Start the mock SSV API server
    let mut next_port = pbs_port + 1;
    let ssv_api_port = next_port;
    next_port += 1;
    let ssv_api_url = Url::parse(&format!("http://localhost:{ssv_api_port}"))?;
    let mock_ssv_state = SsvMockState {
        validators: Arc::new(RwLock::new(vec![SSVValidator { pubkey: pubkey.clone() }])),
        force_timeout: Arc::new(RwLock::new(false)),
    };
    let ssv_server_handle =
        create_mock_ssv_server(ssv_api_port, Some(mock_ssv_state.clone())).await?;

    // Start a mock relay to be used by the mux
    let default_relay = generate_mock_relay(next_port, pubkey.clone())?;
    let relay_id = default_relay.id.clone().to_string();
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(mock_state.clone(), next_port));
    next_port += 1;

    // Create the registry mux
    let loader = MuxKeysLoader::Registry {
        enable_refreshing: true,
        node_operator_id: 1,
        registry: cb_common::config::NORegistry::SSV,
    };
    let muxes = PbsMuxes {
        muxes: vec![MuxConfig {
            id: relay_id.clone(),
            loader: Some(loader),
            late_in_slot_time_ms: Some(2000),
            relays: vec![(*default_relay.config).clone()],
            timeout_get_header_ms: Some(750),
            validator_pubkeys: vec![],
        }],
    };

    // Set up the PBS config
    let mut pbs_config = get_pbs_static_config(pbs_port);
    pbs_config.ssv_api_url = Some(ssv_api_url.clone());
    pbs_config.mux_registry_refresh_interval_seconds = 1; // Refresh the mux every second
    let (mux_lookup, registry_muxes) = muxes.validate_and_fill(chain, &pbs_config).await?;
    let relays = vec![default_relay.clone()];
    let mut config = to_pbs_config(chain, pbs_config, relays);
    config.all_relays = vec![default_relay.clone()];
    config.mux_lookup = Some(mux_lookup);
    config.registry_muxes = Some(registry_muxes);

    // Run PBS service
    let state = PbsState::new(config);
    let pbs_server = tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));
    info!("Started PBS server with pubkey {pubkey}");

    // Wait for the first refresh to complete
    let wait_for_refresh_time = Duration::from_secs(2);
    tokio::time::sleep(wait_for_refresh_time).await;

    // Check the logs to ensure a refresh happened
    assert!(logs_contain(&format!("fetched 1 pubkeys for registry mux {relay_id}")));
    assert!(!logs_contain(&format!("fetched 2 pubkeys for registry mux {relay_id}")));
    assert!(!logs_contain("adding new pubkey"));

    // Add another validator
    let new_secret = random_secret();
    let new_pubkey = new_secret.public_key();
    {
        let mut validators = mock_ssv_state.validators.write().await;
        validators.push(SSVValidator { pubkey: new_pubkey.clone() });
        info!("Added new validator {new_pubkey} to the SSV mock server");
    }

    // Wait for the next refresh to complete
    tokio::time::sleep(wait_for_refresh_time).await;

    // Check the logs to ensure the new pubkey was added
    assert!(logs_contain(&format!("adding new pubkey {new_pubkey} to mux {relay_id}")));
    assert!(logs_contain(&format!("fetched 2 pubkeys for registry mux {relay_id}")));

    // Shut down the server handles
    pbs_server.abort();
    ssv_server_handle.abort();

    Ok(())
}
