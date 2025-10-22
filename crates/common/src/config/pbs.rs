//! Configuration for the PBS module

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use alloy::{
    primitives::{U256, utils::format_ether},
    providers::{Provider, ProviderBuilder},
};
use eyre::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use url::Url;

use super::{
    CommitBoostConfig, HTTP_TIMEOUT_SECONDS_DEFAULT, PBS_ENDPOINT_ENV, RuntimeMuxConfig,
    constants::PBS_IMAGE_DEFAULT, load_optional_env_var,
};
use crate::{
    commit::client::SignerClient,
    config::{
        CONFIG_ENV, MODULE_JWT_ENV, MuxKeysLoader, PBS_MODULE_NAME, PbsMuxes, SIGNER_URL_ENV,
        load_env_var, load_file_from_env,
    },
    pbs::{
        DEFAULT_PBS_PORT, DEFAULT_REGISTRY_REFRESH_SECONDS, DefaultTimeout, LATE_IN_SLOT_TIME_MS,
        REGISTER_VALIDATOR_RETRY_LIMIT, RelayClient, RelayEntry,
    },
    types::{BlsPublicKey, Chain, Jwt, ModuleId},
    utils::{
        WEI_PER_ETH, as_eth_str, default_bool, default_host, default_u16, default_u32, default_u64,
        default_u256,
    },
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Relay ID, if missing will default to the URL hostname from the entry
    pub id: Option<String>,
    /// Relay in the form of scheme://pubkey@host
    #[serde(rename = "url")]
    pub entry: RelayEntry,
    /// Optional headers to send with each request
    pub headers: Option<HashMap<String, String>>,
    /// Optional GET parameters to add to each request
    pub get_params: Option<HashMap<String, String>>,
    /// Whether to enable timing games
    #[serde(default = "default_bool::<false>")]
    pub enable_timing_games: bool,
    /// Target time in slot when to send the first header request
    pub target_first_request_ms: Option<u64>,
    /// Frequency in ms to send get_header requests
    pub frequency_get_header_ms: Option<u64>,
    /// Maximum number of validators to send to relays in one registration
    /// request
    #[serde(deserialize_with = "empty_string_as_none", default)]
    pub validator_registration_batch_size: Option<usize>,
}

fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Helper {
        Str(String),
        Number(usize),
    }

    match Helper::deserialize(deserializer)? {
        Helper::Str(str) if str.is_empty() => Ok(None),
        Helper::Str(str) => Ok(Some(str.parse().map_err(|_| {
            serde::de::Error::custom("Expected empty string or number".to_string())
        })?)),
        Helper::Number(number) => Ok(Some(number)),
    }
}

impl RelayConfig {
    pub fn id(&self) -> &str {
        self.id.as_deref().unwrap_or(self.entry.id.as_str())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PbsConfig {
    /// Host to receive BuilderAPI calls from beacon node
    #[serde(default = "default_host")]
    pub host: Ipv4Addr,
    /// Port to receive BuilderAPI calls from beacon node
    #[serde(default = "default_u16::<DEFAULT_PBS_PORT>")]
    pub port: u16,
    /// Whether to forward `get_status` to relays or skip it
    #[serde(default = "default_bool::<true>")]
    pub relay_check: bool,
    /// Whether to wait  for all registrations to complete before returning
    #[serde(default = "default_bool::<true>")]
    pub wait_all_registrations: bool,
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
    /// Enable extra validation of get_header responses
    #[serde(default = "default_bool::<false>")]
    pub extra_validation_enabled: bool,
    /// Execution Layer RPC url to use for extra validation
    pub rpc_url: Option<Url>,
    /// URL for the SSV network API
    #[serde(default = "default_ssv_api_url")]
    pub ssv_api_url: Url,
    /// Timeout for HTTP requests in seconds
    #[serde(default = "default_u64::<HTTP_TIMEOUT_SECONDS_DEFAULT>")]
    pub http_timeout_seconds: u64,
    /// Maximum number of retries for validator registration request per relay
    #[serde(default = "default_u32::<REGISTER_VALIDATOR_RETRY_LIMIT>")]
    pub register_validator_retry_limit: u32,
    /// Maximum number of validators to send to relays in a single registration
    /// request
    #[serde(deserialize_with = "empty_string_as_none", default)]
    pub validator_registration_batch_size: Option<usize>,
    /// For any Registry-based Mux configurations that have dynamic pubkey
    /// refreshing enabled, this is how often to refresh the list of pubkeys
    /// from the registry, in seconds
    #[serde(default = "default_u64::<{ DEFAULT_REGISTRY_REFRESH_SECONDS }>")]
    pub mux_registry_refresh_interval_seconds: u64,
}

impl PbsConfig {
    /// Validate PBS config parameters
    pub async fn validate(&self, chain: Chain) -> Result<()> {
        // timeouts must be positive
        ensure!(self.timeout_get_header_ms > 0, "timeout_get_header_ms must be greater than 0");
        ensure!(self.timeout_get_payload_ms > 0, "timeout_get_payload_ms must be greater than 0");
        ensure!(
            self.timeout_register_validator_ms > 0,
            "timeout_register_validator_ms must be greater than 0"
        );
        ensure!(self.late_in_slot_time_ms > 0, "late_in_slot_time_ms must be greater than 0");

        ensure!(
            self.timeout_get_header_ms < self.late_in_slot_time_ms,
            "timeout_get_header_ms must be less than late_in_slot_time_ms"
        );
        ensure!(
            self.register_validator_retry_limit > 0,
            "register_validator_retry_limit must be greater than 0"
        );

        ensure!(
            self.min_bid_wei < U256::from(WEI_PER_ETH),
            format!("min bid is too high: {} ETH", format_ether(self.min_bid_wei))
        );

        if self.extra_validation_enabled {
            ensure!(
                self.rpc_url.is_some(),
                "rpc_url is required if extra_validation_enabled is true"
            );
        }

        if let Some(rpc_url) = &self.rpc_url {
            // TODO: remove this once we support chain ids for custom chains
            if !matches!(chain, Chain::Custom { .. }) {
                let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
                let chain_id = provider.get_chain_id().await?;
                ensure!(
                    chain_id == chain.id(),
                    "Rpc url is for the wrong chain, expected: {} ({:?}) got {}",
                    chain.id(),
                    chain,
                    chain_id
                );
            }
        }

        ensure!(
            self.mux_registry_refresh_interval_seconds > 0,
            "registry mux refreshing interval must be greater than 0"
        );

        Ok(())
    }
}

/// Static pbs config from config file
#[derive(Debug, Deserialize, Serialize)]
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
    /// Endpoint to receive BuilderAPI calls from beacon node
    pub endpoint: SocketAddr,
    /// Pbs default config
    pub pbs_config: Arc<PbsConfig>,
    /// List of default relays
    pub relays: Vec<RelayClient>,
    /// List of all default relays plus additional relays from muxes (based on
    /// URL) DO NOT use this for get_header calls, use `relays` or `mux_lookup`
    /// instead
    pub all_relays: Vec<RelayClient>,
    /// Signer client to call Signer API
    pub signer_client: Option<SignerClient>,
    /// List of raw mux details configured, if any
    pub registry_muxes: Option<HashMap<MuxKeysLoader, RuntimeMuxConfig>>,
    /// Lookup of pubkey to mux config
    pub mux_lookup: Option<HashMap<BlsPublicKey, RuntimeMuxConfig>>,
}

fn default_pbs() -> String {
    PBS_IMAGE_DEFAULT.to_string()
}

/// Loads the default pbs config, i.e. with no signer client or custom data
pub async fn load_pbs_config() -> Result<PbsModuleConfig> {
    let config = CommitBoostConfig::from_env_path()?;
    config.validate().await?;

    // Make sure relays isn't empty - since the config is still technically valid if
    // there are no relays for things like Docker compose generation, this check
    // isn't in validate().
    ensure!(
        !config.relays.is_empty(),
        "At least one relay must be configured to run the PBS service"
    );

    // use endpoint from env if set, otherwise use default host and port
    let endpoint = if let Some(endpoint) = load_optional_env_var(PBS_ENDPOINT_ENV) {
        endpoint.parse()?
    } else {
        SocketAddr::from((config.pbs.pbs_config.host, config.pbs.pbs_config.port))
    };

    // Get the list of relays from the default config
    let relay_clients =
        config.relays.into_iter().map(RelayClient::new).collect::<Result<Vec<_>>>()?;
    let mut all_relays = HashMap::with_capacity(relay_clients.len());

    // Validate the muxes and build the lookup tables
    let (mux_lookup, registry_muxes) = match config.muxes {
        Some(muxes) => {
            let (mux_lookup, registry_muxes) =
                muxes.validate_and_fill(config.chain, &config.pbs.pbs_config).await?;
            (Some(mux_lookup), Some(registry_muxes))
        }
        None => (None, None),
    };

    // Build the list of all relays, starting with muxes
    if let Some(muxes) = &mux_lookup {
        for (_, mux) in muxes.iter() {
            for relay in mux.relays.iter() {
                all_relays.insert(&relay.config.entry.url, relay.clone());
            }
        }
    }

    // insert default relays after to make sure we keep these as defaults,
    // this means we override timing games which is ok since this won't be used for
    // get_header we also override headers if the same relays has two
    // definitions (in muxes and default)
    for relay in relay_clients.iter() {
        all_relays.insert(&relay.config.entry.url, relay.clone());
    }

    let all_relays = all_relays.into_values().collect();

    Ok(PbsModuleConfig {
        chain: config.chain,
        endpoint,
        pbs_config: Arc::new(config.pbs.pbs_config),
        relays: relay_clients,
        all_relays,
        signer_client: None,
        registry_muxes,
        mux_lookup,
    })
}

/// Loads a custom pbs config, i.e. with signer client and/or custom data
pub async fn load_pbs_custom_config<T: DeserializeOwned>() -> Result<(PbsModuleConfig, T)> {
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
        muxes: Option<PbsMuxes>,
    }

    // load module config including the extra data (if any)
    let cb_config: StubConfig<T> = load_file_from_env(CONFIG_ENV)?;
    cb_config.pbs.static_config.pbs_config.validate(cb_config.chain).await?;

    // use endpoint from env if set, otherwise use default host and port
    let endpoint = if let Some(endpoint) = load_optional_env_var(PBS_ENDPOINT_ENV) {
        endpoint.parse()?
    } else {
        SocketAddr::from((
            cb_config.pbs.static_config.pbs_config.host,
            cb_config.pbs.static_config.pbs_config.port,
        ))
    };

    // Get the list of relays from the default config
    let relay_clients =
        cb_config.relays.into_iter().map(RelayClient::new).collect::<Result<Vec<_>>>()?;
    let mut all_relays = HashMap::with_capacity(relay_clients.len());

    // Validate the muxes and build the lookup tables
    let (mux_lookup, registry_muxes) = match cb_config.muxes {
        Some(muxes) => {
            let (mux_lookup, registry_muxes) = muxes
                .validate_and_fill(cb_config.chain, &cb_config.pbs.static_config.pbs_config)
                .await?;
            (Some(mux_lookup), Some(registry_muxes))
        }
        None => (None, None),
    };

    // Build the list of all relays, starting with muxes
    if let Some(muxes) = &mux_lookup {
        for (_, mux) in muxes.iter() {
            for relay in mux.relays.iter() {
                all_relays.insert(&relay.config.entry.url, relay.clone());
            }
        }
    }

    // insert default relays after to make sure we keep these as defaults,
    // this also means we override timing games which is ok since this won't be used
    // for get header we also override headers if the same relays has two
    // definitions (in muxes and default)
    for relay in relay_clients.iter() {
        all_relays.insert(&relay.config.entry.url, relay.clone());
    }

    let all_relays = all_relays.into_values().collect();

    let signer_client = if cb_config.pbs.static_config.with_signer {
        // if custom pbs requires a signer client, load jwt
        let module_jwt = Jwt(load_env_var(MODULE_JWT_ENV)?);
        let signer_server_url = load_env_var(SIGNER_URL_ENV)?.parse()?;
        Some(SignerClient::new(
            signer_server_url,
            module_jwt,
            ModuleId(PBS_MODULE_NAME.to_string()),
        )?)
    } else {
        None
    };

    Ok((
        PbsModuleConfig {
            chain: cb_config.chain,
            endpoint,
            pbs_config: Arc::new(cb_config.pbs.static_config.pbs_config),
            relays: relay_clients,
            all_relays,
            signer_client,
            registry_muxes,
            mux_lookup,
        },
        cb_config.pbs.extra,
    ))
}

/// Default URL for the SSV network API
fn default_ssv_api_url() -> Url {
    Url::parse("https://api.ssv.network/api/v4/").expect("default URL is valid")
}
