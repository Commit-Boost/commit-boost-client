use std::net::Ipv4Addr;

use alloy::primitives::U256;
use cb_common::{config::CommitBoostConfig, types::Chain, utils::WEI_PER_ETH};
use eyre::Result;
use url::Url;

#[tokio::test]
async fn test_load_example_config() -> Result<()> {
    let config = CommitBoostConfig::from_file("../config.example.toml")?;
    config.validate().await?;
    assert_eq!(config.chain, Chain::Holesky);
    assert!(config.relays[0].headers.is_some());

    Ok(())
}

#[tokio::test]
async fn test_load_pbs_happy() -> Result<()> {
    let config = CommitBoostConfig::from_file("./data/configs/pbs.happy.toml")?;
    config.validate().await?;

    // Chain and existing header check
    assert_eq!(config.chain, Chain::Holesky);
    assert_eq!(
        config.relays[0].headers.as_ref().unwrap().get("X-MyCustomHeader").unwrap(),
        "MyCustomHeader"
    );

    // Docker and general settings
    assert_eq!(config.pbs.docker_image, "ghcr.io/commit-boost/pbs:latest");
    assert_eq!(config.pbs.with_signer, false);
    assert_eq!(config.pbs.pbs_config.host, "127.0.0.1".parse::<Ipv4Addr>().unwrap());
    assert_eq!(config.pbs.pbs_config.port, 18550);
    assert_eq!(config.pbs.pbs_config.relay_check, true);
    assert_eq!(config.pbs.pbs_config.wait_all_registrations, true);

    // Timeouts
    assert_eq!(config.pbs.pbs_config.timeout_get_header_ms, 950);
    assert_eq!(config.pbs.pbs_config.timeout_get_payload_ms, 4000);
    assert_eq!(config.pbs.pbs_config.timeout_register_validator_ms, 3000);

    // Bid settings and validation
    assert_eq!(config.pbs.pbs_config.skip_sigverify, false);
    dbg!(&config.pbs.pbs_config.min_bid_wei);
    dbg!(&U256::from(0.5));
    assert_eq!(config.pbs.pbs_config.min_bid_wei, U256::from((0.5 * WEI_PER_ETH as f64) as u64));
    assert!(config.pbs.pbs_config.relay_monitors.is_empty());
    assert_eq!(config.pbs.pbs_config.late_in_slot_time_ms, 2000);
    assert_eq!(config.pbs.pbs_config.extra_validation_enabled, false);
    assert_eq!(
        config.pbs.pbs_config.rpc_url,
        Some("https://ethereum-holesky-rpc.publicnode.com".parse::<Url>().unwrap())
    );

    // Relay specific settings
    let relay = &config.relays[0];
    assert_eq!(relay.id, Some("example-relay".to_string()));
    assert_eq!(relay.entry.url, "http://0xa1cec75a3f0661e99299274182938151e8433c61a19222347ea1313d839229cb4ce4e3e5aa2bdeb71c8fcf1b084963c2@abc.xyz".parse::<Url>().unwrap());
    assert_eq!(relay.enable_timing_games, false);
    assert_eq!(relay.target_first_request_ms, Some(200));
    assert_eq!(relay.frequency_get_header_ms, Some(300));

    Ok(())
}

#[tokio::test]
async fn test_validate_bad_timeout_get_header_ms() -> Result<()> {
    let mut config = CommitBoostConfig::from_file("./data/configs/pbs.happy.toml")?;

    // Set invalid timeout
    config.pbs.pbs_config.timeout_get_header_ms = 0;

    let result = config.validate().await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("timeout_get_header_ms must be greater than 0"));

    Ok(())
}

#[tokio::test]
async fn test_validate_bad_timeout_get_payload_ms() -> Result<()> {
    let mut config = CommitBoostConfig::from_file("./data/configs/pbs.happy.toml")?;
    config.pbs.pbs_config.timeout_get_payload_ms = 0;

    let result = config.validate().await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("timeout_get_payload_ms must be greater than 0"));
    Ok(())
}

#[tokio::test]
async fn test_validate_bad_timeout_register_validator_ms() -> Result<()> {
    let mut config = CommitBoostConfig::from_file("./data/configs/pbs.happy.toml")?;
    config.pbs.pbs_config.timeout_register_validator_ms = 0;

    let result = config.validate().await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("timeout_register_validator_ms must be greater than 0"));
    Ok(())
}

#[tokio::test]
async fn test_validate_bad_late_in_slot_time_ms() -> Result<()> {
    let mut config = CommitBoostConfig::from_file("./data/configs/pbs.happy.toml")?;
    config.pbs.pbs_config.late_in_slot_time_ms = 0;

    let result = config.validate().await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("late_in_slot_time_ms must be greater than 0"));
    Ok(())
}

#[tokio::test]
async fn test_validate_bad_timeout_header_vs_late() -> Result<()> {
    let mut config = CommitBoostConfig::from_file("./data/configs/pbs.happy.toml")?;
    config.pbs.pbs_config.timeout_get_header_ms = 3000;
    config.pbs.pbs_config.late_in_slot_time_ms = 2000;

    let result = config.validate().await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("timeout_get_header_ms must be less than late_in_slot_time_ms"));
    Ok(())
}

#[tokio::test]
async fn test_validate_bad_min_bid() -> Result<()> {
    let mut config = CommitBoostConfig::from_file("./data/configs/pbs.happy.toml")?;
    config.pbs.pbs_config.min_bid_wei = U256::from(2 * WEI_PER_ETH);

    let result = config.validate().await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("min bid is too high"));
    Ok(())
}

#[tokio::test]
async fn test_validate_missing_rpc_url() -> Result<()> {
    let mut config = CommitBoostConfig::from_file("./data/configs/pbs.happy.toml")?;
    config.pbs.pbs_config.extra_validation_enabled = true;
    config.pbs.pbs_config.rpc_url = None;

    let result = config.validate().await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("rpc_url is required if extra_validation_enabled is true"));
    Ok(())
}
