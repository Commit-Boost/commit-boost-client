//! Configuration for the PBS module

use std::{collections::HashMap, sync::Arc};

use alloy::primitives::U256;
use eyre::Result;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{constants::PBS_DEFAULT_IMAGE, CommitBoostConfig};
use crate::{
    commit::client::SignerClient,
    config::{load_env_var, load_file_from_env, CB_CONFIG_ENV, MODULE_JWT_ENV, SIGNER_SERVER_ENV},
    pbs::{BuilderEventPublisher, DefaultTimeout, RelayClient, RelayEntry, LATE_IN_SLOT_TIME_MS},
    types::Chain,
    utils::{as_eth_str, default_bool, default_u256, default_u64},
};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RelayConfig {
    /// Relay ID, if missing will default to the URL hostname from the entry
    pub id: Option<String>,
    /// Relay in the form of scheme://pubkey@host
    #[serde(rename = "url")]
    pub entry: RelayEntry,
    /// Optional headers to send with each request
    pub headers: Option<HashMap<String, String>>,
    /// Whether to enable timing games
    #[serde(default = "default_bool::<false>")]
    pub enable_timing_games: bool,
    /// Target time in slot when to send the first header request
    pub target_first_request_ms: Option<u64>,
    /// Frequency in ms to send get_header requests
    pub frequency_get_header_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PbsConfig {
    /// Port to receive BuilderAPI calls from beacon node
    pub port: u16,
    /// Whether to forward `get_status` to relays or skip it
    #[serde(default = "default_bool::<true>")]
    pub relay_check: bool,
    /// Timeout for get_header request in milliseconds
    #[serde(default = "default_u64::<{ DefaultTimeout::GET_HEADER_MS }>")]
    pub timeout_get_header_ms: u64,
    /// Timeout for get_payload request in milliseconds
    #[serde(default = "default_u64::<{ DefaultTimeout::GET_PAYLOAD_MS }>")]
    pub timeout_get_payload_ms: u64,
    /// Timeout for register_validator request in milliseconds
    #[serde(default = "default_u64::<{ DefaultTimeout::REGISTER_VALIDATOR_MS }>")]
    pub timeout_register_validator_ms: u64,
    /// Whether to skip the relay signature verification
    #[serde(default = "default_bool::<false>")]
    pub skip_sigverify: bool,
    /// Minimum bid that will be accepted from get_header
    #[serde(rename = "min_bid_eth", with = "as_eth_str", default = "default_u256")]
    pub min_bid_wei: U256,
    /// How late in the slot we consider to be "late"
    #[serde(default = "default_u64::<LATE_IN_SLOT_TIME_MS>")]
    pub late_in_slot_time_ms: u64,
}

/// Static pbs config from config file
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct StaticPbsConfig {
    /// Docker image of the module
    #[serde(default = "default_pbs")]
    pub docker_image: String,
    /// Config of pbs module
    #[serde(flatten)]
    pub pbs_config: PbsConfig,
    /// Whether to enable the signer client
    #[serde(default = "default_bool::<false>")]
    pub with_signer: bool,
}

/// Runtime config for the pbs module
#[derive(Debug, Clone)]
pub struct PbsModuleConfig {
    /// Chain spec
    pub chain: Chain,
    /// Pbs default config
    pub pbs_config: Arc<PbsConfig>,
    /// List of relays
    pub relays: Vec<RelayClient>,
    /// Signer client to call Signer API
    pub signer_client: Option<SignerClient>,
    /// Event publisher
    pub event_publiher: Option<BuilderEventPublisher>,
}

fn default_pbs() -> String {
    PBS_DEFAULT_IMAGE.to_string()
}

/// Loads the default pbs config, i.e. with no signer client or custom data
pub fn load_pbs_config() -> Result<PbsModuleConfig> {
    let config = CommitBoostConfig::from_env_path()?;
    let relay_clients =
        config.relays.into_iter().map(RelayClient::new).collect::<Result<Vec<_>>>()?;
    let maybe_publiher = BuilderEventPublisher::new_from_env();

    Ok(PbsModuleConfig {
        chain: config.chain,
        pbs_config: Arc::new(config.pbs.pbs_config),
        relays: relay_clients,
        signer_client: None,
        event_publiher: maybe_publiher,
    })
}

/// Loads a custom pbs config, i.e. with signer client and/or custom data
pub fn load_pbs_custom_config<T: DeserializeOwned>() -> Result<(PbsModuleConfig, T)> {
    #[derive(Debug, Deserialize)]
    struct CustomPbsConfig<U> {
        #[serde(flatten)]
        static_config: StaticPbsConfig,
        #[serde(flatten)]
        extra: U,
    }

    #[derive(Deserialize, Debug)]
    struct StubConfig<U> {
        chain: Chain,
        relays: Vec<RelayConfig>,
        pbs: CustomPbsConfig<U>,
    }

    // load module config including the extra data (if any)
    let cb_config: StubConfig<T> = load_file_from_env(CB_CONFIG_ENV)?;
    let relay_clients =
        cb_config.relays.into_iter().map(RelayClient::new).collect::<Result<Vec<_>>>()?;
    let maybe_publiher = BuilderEventPublisher::new_from_env();

    let signer_client = if cb_config.pbs.static_config.with_signer {
        // if custom pbs requires a signer client, load jwt
        let module_jwt = load_env_var(MODULE_JWT_ENV)?;
        let signer_server_address = load_env_var(SIGNER_SERVER_ENV)?;
        Some(SignerClient::new(signer_server_address, &module_jwt)?)
    } else {
        None
    };

    Ok((
        PbsModuleConfig {
            chain: cb_config.chain,
            pbs_config: Arc::new(cb_config.pbs.static_config.pbs_config),
            relays: relay_clients,
            signer_client,
            event_publiher: maybe_publiher,
        },
        cb_config.pbs.extra,
    ))
}
