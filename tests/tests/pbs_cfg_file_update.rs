use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use alloy::primitives::U256;
use cb_common::{
    config::{CommitBoostConfig, LogsSettings, PbsConfig, RelayConfig, StaticPbsConfig},
    pbs::RelayEntry,
    signer::random_secret,
    types::Chain,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service},
    mock_validator::MockValidator,
    utils::{generate_mock_relay, get_pbs_static_config, setup_test_env, to_pbs_config},
};
use eyre::Result;
use reqwest::StatusCode;
use tracing::info;
use url::Url;

/// Updates the config file that was used to load the PBS config, and ensures
/// the filesystem watcher triggers a reload of the configuration.
#[tokio::test]
async fn test_cfg_file_update() -> Result<()> {
    // Random keys needed for the relays to start
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Hoodi;
    let pbs_port = 3720;

    // Start relay 1
    let relay1_port = pbs_port + 1;
    let relay1 = generate_mock_relay(relay1_port, pubkey.clone())?;
    let relay1_state = Arc::new(MockRelayState::new(chain, signer.clone()));
    tokio::spawn(start_mock_relay_service(relay1_state.clone(), relay1_port));

    // Start relay 2
    let relay2_port = relay1_port + 1;
    let relay2 = generate_mock_relay(relay2_port, pubkey.clone())?;
    let relay2_id = relay2.id.clone().to_string();
    let relay2_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service(relay2_state.clone(), relay2_port));

    // Make a config with relay 1 only
    let pbs_config = PbsConfig {
        // get_pbs_static_config(pbs_port);
        host: Ipv4Addr::LOCALHOST,
        port: pbs_port,
        relay_check: false,
        wait_all_registrations: false,
        timeout_get_header_ms: 950,
        timeout_get_payload_ms: 4000,
        timeout_register_validator_ms: 3000,
        skip_sigverify: true,
        min_bid_wei: U256::ZERO,
        late_in_slot_time_ms: u64::MAX / 2, /* serde gets very upset about serializing u64::MAX
                                             * or anything close to it */
        extra_validation_enabled: false,
        rpc_url: None,
        ssv_api_url: Url::parse("http://example.com").unwrap(),
        http_timeout_seconds: 10,
        register_validator_retry_limit: 3,
        validator_registration_batch_size: None,
        mux_registry_refresh_interval_seconds: 384,
    };
    let cb_config = CommitBoostConfig {
        chain,
        pbs: StaticPbsConfig {
            docker_image: String::new(),
            pbs_config: pbs_config.clone(),
            with_signer: false,
        },
        muxes: None,
        modules: None,
        signer: None,
        logs: LogsSettings::default(),
        metrics: None,
        relays: vec![RelayConfig {
            id: Some(relay1.id.to_string()),
            enable_timing_games: false,
            frequency_get_header_ms: None,
            get_params: None,
            headers: None,
            target_first_request_ms: None,
            validator_registration_batch_size: None,
            entry: RelayEntry {
                id: relay1.id.to_string(),
                url: Url::parse(&format!("http://localhost:{relay1_port}"))?,
                pubkey: pubkey.clone(),
            },
        }],
    };

    // Save to a file
    let temp_file = tempfile::NamedTempFile::new()?;
    let config_path = temp_file.path().to_path_buf();
    let config_toml = toml::to_string_pretty(&cb_config)?;
    info!("Writing initial config to {:?}", config_path);
    std::fs::write(config_path.clone(), config_toml.as_bytes())?;

    // Run the PBS service
    let config = to_pbs_config(chain, get_pbs_static_config(pbs_port), vec![relay1.clone()]);
    let state = PbsState::new(config, config_path.clone());
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));

    // leave some time to start servers - extra time for the file watcher
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Send a get header request - should go to relay 1 only
    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending get header");
    let res = mock_validator.do_get_header(None).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(relay1_state.received_get_header(), 1);
    assert_eq!(relay2_state.received_get_header(), 0);

    // Update the config to only have relay 2
    let cb_config = CommitBoostConfig {
        chain,
        pbs: StaticPbsConfig { docker_image: String::new(), pbs_config, with_signer: false },
        muxes: None,
        modules: None,
        signer: None,
        logs: LogsSettings::default(),
        metrics: None,
        relays: vec![RelayConfig {
            id: Some(relay2_id.clone()),
            enable_timing_games: false,
            frequency_get_header_ms: None,
            get_params: None,
            headers: None,
            target_first_request_ms: None,
            validator_registration_batch_size: None,
            entry: RelayEntry {
                id: relay2_id,
                url: Url::parse(&format!("http://{pubkey}@localhost:{relay2_port}"))?,
                pubkey,
            },
        }],
    };
    let config_toml = toml::to_string_pretty(&cb_config)?;
    info!("Writing updated config to {:?}", config_path);
    std::fs::write(config_path, config_toml.as_bytes())?;

    // leave some time for the watcher to pick up the change and reload
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Send another get header request - should go to relay 2 only
    info!("Sending get header after config update");
    let res = mock_validator.do_get_header(None).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(relay1_state.received_get_header(), 1); // no change
    assert_eq!(relay2_state.received_get_header(), 1); // incremented

    Ok(())
}
