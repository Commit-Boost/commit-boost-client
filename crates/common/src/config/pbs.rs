//! Configuration for the PBS module

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy::{
    primitives::{Bytes, U256, utils::format_ether},
    providers::{Provider, ProviderBuilder},
};
use docker_image::DockerImage;
use eyre::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{info, warn};
use url::Url;

use super::{
    CommitBoostConfig, HTTP_TIMEOUT_SECONDS_DEFAULT, PBS_ENDPOINT_ENV, RuntimeMuxConfig,
    load_optional_env_var,
};
use crate::{
    commit::client::SignerClient,
    config::{
        COMMIT_BOOST_IMAGE_DEFAULT, CONFIG_ENV, MODULE_JWT_ENV, MuxKeysLoader, PBS_SERVICE_NAME,
        PbsMuxes, SIGNER_TLS_CERTIFICATE_NAME, SIGNER_TLS_CERTIFICATES_PATH_ENV, SIGNER_URL_ENV,
        SignerConfig, TlsMode, load_env_var, load_file_from_env,
    },
    pbs::{
        DEFAULT_PBS_PORT, DEFAULT_REGISTRY_REFRESH_SECONDS, DefaultTimeout, LATE_IN_SLOT_TIME_MS,
        PROPOSER_DEADLINE_BUFFER_MS, REGISTER_VALIDATOR_RETRY_LIMIT, RelayClient, RelayEntry,
    },
    types::{BlsPublicKey, Chain, Jwt, ModuleId},
    utils::{
        WEI_PER_ETH, as_eth_str, as_opt_eth_str, default_bool, default_host, default_u16,
        default_u32, default_u64, default_u256,
    },
};

/// How CB fetches get_header bids from this relay: `Http` = request/response,
/// `Stream` = the relay's WebSocket bid stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GetHeaderTransport {
    #[default]
    Http,
    Stream,
}

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
    #[serde(default)]
    pub get_header: GetHeaderTransport,
    /// Whether to enable timing games
    #[serde(default = "default_bool::<false>")]
    pub enable_timing_games: bool,
    /// Target time in slot when to send the first header request
    pub target_first_request_ms: Option<u64>,
    /// Frequency in ms to send get_header requests
    pub frequency_get_header_ms: Option<u64>,
    /// How long each ePBS bid poll may take, except the last which holds until
    /// the proposer's deadline
    pub bid_poll_timeout_ms: Option<u64>,
    /// Maximum number of validators to send to relays in one registration
    /// request
    #[serde(deserialize_with = "empty_string_as_none", default)]
    pub validator_registration_batch_size: Option<usize>,
    /// Per-relay override of the ePBS bid-ranking execution-payment cap in
    /// Gwei (see `PbsConfig::max_execution_payment_gwei`)
    pub max_execution_payment_gwei: Option<u64>,
    /// ePBS auth data this relay serves: a bid request routes here only when
    /// its `auth.message.data` equals this value. When unset, the relay is
    /// matched only by auth data carrying its URL
    pub expected_auth_data: Option<Bytes>,
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

    /// Validate relay-level knobs the PBS runtime reads directly. The timing
    /// knobs are optional, but a zero would stall the ePBS bid poll / timing
    /// games rather than mean "unset", so reject it explicitly.
    pub fn validate(&self) -> Result<()> {
        if let Some(ms) = self.bid_poll_timeout_ms {
            ensure!(ms > 0, "bid_poll_timeout_ms must be greater than 0 when set");
        }
        if let Some(ms) = self.frequency_get_header_ms {
            ensure!(ms > 0, "frequency_get_header_ms must be greater than 0 when set");
        }
        Ok(())
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
    /// Execution-payment cap in Gwei used when RANKING ePBS bids: a bid ranks
    /// at `value + min(execution_payment, cap)`, mirroring the BN's valuation
    /// (beacon-APIs #630 clamps at `max_execution_payment` instead of
    /// rejecting). Not an accept/reject check; the BN enforces the cap.
    /// Default: unset (None) = unclamped
    #[serde(default)]
    pub max_execution_payment_gwei: Option<u64>,
    /// When enabled, the BLS signature of an ePBS request's
    /// `SignedBuilderRequestAuth` is verified against the proposer pubkey.
    /// False by default: CB forwards because the downstream builder must
    /// re-verify anyway; operators terminating trust at CB set it true
    #[serde(default = "default_bool::<false>")]
    pub verify_builder_request_auth: bool,
    /// How late in the slot we consider to be "late" (legacy get_header path)
    #[serde(default = "default_u64::<LATE_IN_SLOT_TIME_MS>")]
    pub late_in_slot_time_ms: u64,
    /// ePBS bid path only: ms reserved before the proposer's declared deadline
    /// (Date-Milliseconds + X-Timeout-Ms) for the winning bid's return trip to
    /// the beacon node and the beacon node's own selection/assembly. CB asks
    /// the builder for `deadline - this`, deriving its timeout from the
    /// BN's live X-Timeout-Ms instead of a static config;
    /// timeout_get_header_ms and late_in_slot_time_ms (legacy get_header
    /// knobs, which carry no X-Timeout-Ms) are not consulted on the ePBS
    /// bid path.
    #[serde(default = "default_u64::<PROPOSER_DEADLINE_BUFFER_MS>")]
    pub proposer_deadline_buffer_ms: u64,
    /// Enable extra validation of get_header responses
    #[serde(default = "default_bool::<false>")]
    pub extra_validation_enabled: bool,
    /// Opt-in strict decoding of the reveal at POST
    /// /eth/v1/builder/beacon_blocks. Default (false): CB is a blind pipe,
    /// forwarding the block bytes to the builder without parsing them (the
    /// builder validates and rejects, per builder-specs). When true: CB
    /// decodes the SignedBeaconBlock, rejects a non-gloas or undecodable
    /// body with 400, and re-encodes it outbound.
    #[serde(default = "default_bool::<false>")]
    pub strict_block_decode: bool,
    /// Execution Layer RPC url to use for extra validation
    pub rpc_url: Option<Url>,
    /// URL for the user's own SSV node API endpoint
    #[serde(default = "default_ssv_node_api_url")]
    pub ssv_node_api_url: Url,
    /// URL for the public SSV network API server
    #[serde(default = "default_public_ssv_api_url")]
    pub ssv_public_api_url: Url,
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
    /// CB's externally-reachable URLs; used by the ePBS pipe self-URL guard
    #[serde(default)]
    pub advertised_urls: Vec<Url>,
    // The p2p projection-only fields below are consumed by KM tooling, not read
    // by the PBS runtime.
    /// The ePBS KEY-LEVEL minimum total payment: it governs p2p bids and
    /// builder entries that omit their own min_bid (projected entries always
    /// carry explicit per-entry values sourced from the mux/global min_bid)
    #[serde(
        rename = "min_bid_p2p_eth",
        with = "as_opt_eth_str",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub min_bid_p2p_wei: Option<U256>,
    /// The ePBS KEY-LEVEL builder_boost_factor: it governs p2p bids and
    /// builder entries that omit their own (entry values stay mux-sourced)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_boost_factor_p2p: Option<u64>,
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

        // The buffer is subtracted from the proposer's own deadline; a value at
        // or above one slot would leave no time for the bid poll. 0 is allowed
        // (no reserve).
        const MAX_PROPOSER_DEADLINE_BUFFER_MS: u64 = 12_000;
        ensure!(
            self.proposer_deadline_buffer_ms < MAX_PROPOSER_DEADLINE_BUFFER_MS,
            "proposer_deadline_buffer_ms must be less than one slot ({MAX_PROPOSER_DEADLINE_BUFFER_MS} ms)"
        );

        if self.min_bid_p2p_wei.is_some() {
            info!("field min_bid_p2p_eth is applied via KM tooling, not by the PBS runtime");
        }
        if self.builder_boost_factor_p2p.is_some() {
            info!(
                "field builder_boost_factor_p2p is applied via KM tooling, not by the PBS runtime"
            );
        }

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
            let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
            let chain_id = provider.get_chain_id().await?;
            let chain_id_big = U256::from(chain_id);
            ensure!(
                chain_id_big == chain.id(),
                "Rpc url is for the wrong chain, expected: {} ({:?}) got {}",
                chain.id(),
                chain,
                chain_id_big
            );
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

impl StaticPbsConfig {
    /// Validate static pbs config
    pub async fn validate(&self, chain: Chain) -> Result<()> {
        // The Docker tag must parse
        ensure!(!self.docker_image.is_empty(), "Docker image is empty");
        ensure!(
            DockerImage::parse(&self.docker_image).is_ok(),
            format!("Invalid Docker image: {}", self.docker_image)
        );

        // Validate the inner pbs config
        self.pbs_config.validate(chain).await
    }
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
    COMMIT_BOOST_IMAGE_DEFAULT.to_string()
}

/// Loads the default pbs config, i.e. with no signer client or custom data
pub async fn load_pbs_config(config_path: Option<PathBuf>) -> Result<(PbsModuleConfig, PathBuf)> {
    let (config, config_path) = match config_path {
        Some(path) => (CommitBoostConfig::from_file(&path)?, path),
        None => CommitBoostConfig::from_env_path()?,
    };
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

    // The ePBS transient pipe (forwarding a bid/preferences request to a
    // proposer-addressed builder that is not in the relay config) is fail-closed
    // without advertised_urls: CB cannot tell an unconfigured key's self-URL
    // default from an external builder, so it will not dial. Warn once at startup
    // so this reads as a deliberate opt-in, not a silent 400 at request time.
    if mux_lookup.is_some() && config.pbs.pbs_config.advertised_urls.is_empty() {
        warn!(
            "advertised_urls is unset: the ePBS transient pipe is disabled, so a bid or \
             preferences request addressed to a builder not in your relay config is rejected \
             with 400. Set advertised_urls to CB's advertised URL(s) to enable forwarding to \
             proposer-addressed builders."
        );
    }

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

    Ok((
        PbsModuleConfig {
            chain: config.chain,
            endpoint,
            pbs_config: Arc::new(config.pbs.pbs_config),
            relays: relay_clients,
            all_relays,
            signer_client: None,
            registry_muxes,
            mux_lookup,
        },
        config_path,
    ))
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
        signer: Option<SignerConfig>,
        muxes: Option<PbsMuxes>,
    }

    // load module config including the extra data (if any)
    let (cb_config, config_path): (StubConfig<T>, _) = load_file_from_env(CONFIG_ENV)?;
    super::warn_unknown_mux_fields(&config_path);
    warn_unknown_pbs_fields(&config_path);
    cb_config.pbs.static_config.validate(cb_config.chain).await?;

    // use endpoint from env if set, otherwise use default host and port
    let endpoint = if let Some(endpoint) = load_optional_env_var(PBS_ENDPOINT_ENV) {
        endpoint.parse()?
    } else {
        SocketAddr::from((
            cb_config.pbs.static_config.pbs_config.host,
            cb_config.pbs.static_config.pbs_config.port,
        ))
    };

    // Get the list of relays from the default config. Validate each first: the
    // default binary validates top-level relays via `CommitBoostConfig::validate`,
    // which this custom-module load path does not call.
    for relay in cb_config.relays.iter() {
        relay.validate()?;
    }
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

    // The ePBS transient pipe (forwarding a bid/preferences request to a
    // proposer-addressed builder that is not in the relay config) is fail-closed
    // without advertised_urls: CB cannot tell an unconfigured key's self-URL
    // default from an external builder, so it will not dial. Warn once at startup
    // so this reads as a deliberate opt-in, not a silent 400 at request time.
    if mux_lookup.is_some() && cb_config.pbs.static_config.pbs_config.advertised_urls.is_empty() {
        warn!(
            "advertised_urls is unset: the ePBS transient pipe is disabled, so a bid or \
             preferences request addressed to a builder not in your relay config is rejected \
             with 400. Set advertised_urls to CB's advertised URL(s) to enable forwarding to \
             proposer-addressed builders."
        );
    }

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
        let certs_path = match cb_config
            .signer
            .ok_or_else(|| eyre::eyre!("with_signer = true but no [signer] section in config"))?
            .tls_mode
        {
            TlsMode::Insecure => None,
            TlsMode::Certificate(path) => Some(
                load_env_var(SIGNER_TLS_CERTIFICATES_PATH_ENV)
                    .map(PathBuf::from)
                    .unwrap_or(path)
                    .join(SIGNER_TLS_CERTIFICATE_NAME),
            ),
        };
        Some(SignerClient::new(
            signer_server_url,
            certs_path,
            module_jwt,
            ModuleId(PBS_SERVICE_NAME.to_string()),
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

/// Default URL for the user's SSV node API endpoint (/v1/validators).
fn default_ssv_node_api_url() -> Url {
    Url::parse("http://localhost:16000/v1/").expect("default URL is valid")
}

/// Default URL for the public SSV network API.
fn default_public_ssv_api_url() -> Url {
    Url::parse("https://api.ssv.network/api/v4/").expect("default URL is valid")
}

/// The serde keys recognized on the `[pbs]` table: the `StaticPbsConfig`
/// wrapper (`docker_image`, `with_signer`) plus the flattened `PbsConfig`
/// fields in their serde-renamed form (e.g. `min_bid_eth`, not `min_bid_wei`).
/// Kept in lockstep with those two structs.
const KNOWN_PBS_FIELDS: &[&str] = &[
    // StaticPbsConfig wrapper
    "docker_image",
    "with_signer",
    // PbsConfig (flattened)
    "host",
    "port",
    "relay_check",
    "wait_all_registrations",
    "timeout_get_header_ms",
    "timeout_get_payload_ms",
    "timeout_register_validator_ms",
    "skip_sigverify",
    "min_bid_eth",
    "max_execution_payment_gwei",
    "verify_builder_request_auth",
    "late_in_slot_time_ms",
    "proposer_deadline_buffer_ms",
    "extra_validation_enabled",
    "strict_block_decode",
    "rpc_url",
    "ssv_node_api_url",
    "ssv_public_api_url",
    "http_timeout_seconds",
    "register_validator_retry_limit",
    "validator_registration_batch_size",
    "mux_registry_refresh_interval_seconds",
    "advertised_urls",
    "min_bid_p2p_eth",
    "builder_boost_factor_p2p",
];

/// Unknown keys on the `[pbs]` table of a raw config document. `PbsConfig` is
/// `#[serde(flatten)]`ed into `StaticPbsConfig`, and a flattened struct cannot
/// take `#[serde(deny_unknown_fields)]` (it would reject the outer struct's own
/// keys), so typo visibility comes from this extra pass over the raw TOML
/// instead (mirrors [`super::unknown_mux_fields`]).
pub fn unknown_pbs_fields(raw: &toml::Value) -> Vec<String> {
    let Some(table) = raw.get("pbs").and_then(|value| value.as_table()) else {
        return Vec::new();
    };
    table.keys().filter(|key| !KNOWN_PBS_FIELDS.contains(&key.as_str())).cloned().collect()
}

/// WARN-logs every unknown `[pbs]` key in the config file at `path`.
/// Best-effort: unreadable/unparseable input is serde's problem to report.
pub fn warn_unknown_pbs_fields(path: &Path) {
    let Ok(raw) = std::fs::read_to_string(path) else { return };
    let Ok(value) = raw.parse::<toml::Value>() else { return };
    for key in unknown_pbs_fields(&value) {
        warn!("unknown field `{key}` on the [pbs] table is ignored by the PBS runtime");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Projection-only p2p fields: parsed for KM tooling, absent = None so
    // existing configs project exactly as before.
    #[test]
    fn p2p_projection_fields_parse_and_default() {
        let cfg: PbsConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.min_bid_p2p_wei, None);
        assert_eq!(cfg.builder_boost_factor_p2p, None);

        let cfg: PbsConfig = toml::from_str(
            r#"
            min_bid_p2p_eth = "0.2"
            builder_boost_factor_p2p = 0
            "#,
        )
        .unwrap();
        assert_eq!(cfg.min_bid_p2p_wei, Some(U256::from(200_000_000_000_000_000u64)));
        assert_eq!(cfg.builder_boost_factor_p2p, Some(0));
    }

    // The false-positive trap: a renamed field (`min_bid_eth`) or a wrapper key
    // (`docker_image`) must not be flagged as unknown.
    #[test]
    fn unknown_pbs_fields_flags_typos_only() {
        let raw: toml::Value = r#"
            [pbs]
            docker_image = "x"
            with_signer = false
            min_bid_eth = 0.0
            max_execution_payment_gwei = 1000000000
            strict_block_decode = true
            proposer_deadline_buffer_ms = 50
            skip_sigverify = false
            bid_poll_timeout_ms = 500
        "#
        .parse()
        .unwrap();
        assert_eq!(unknown_pbs_fields(&raw), vec!["bid_poll_timeout_ms".to_string()]);

        let raw: toml::Value = "chain = \"Holesky\"".parse().unwrap();
        assert!(unknown_pbs_fields(&raw).is_empty());
    }
}
