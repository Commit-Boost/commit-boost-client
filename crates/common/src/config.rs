use std::{collections::HashMap, sync::Arc};

use eyre::{eyre, ContextCompat, Result, WrapErr};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    commit::client::SignerClient,
    loader::SignerLoader,
    pbs::{PbsConfig, RelayClient, RelayConfig},
    types::Chain,
    utils::default_bool,
};

pub const MODULE_ID_ENV: &str = "CB_MODULE_ID";
pub const MODULE_JWT_ENV: &str = "CB_SIGNER_JWT";
pub const METRICS_SERVER_ENV: &str = "METRICS_SERVER";
pub const SIGNER_SERVER_ENV: &str = "SIGNER_SERVER";

pub const CB_CONFIG_ENV: &str = "CB_CONFIG";
pub const CB_CONFIG_NAME: &str = "/cb-config.toml";

pub const SIGNER_KEYS_ENV: &str = "CB_SIGNER_FILE";
pub const SIGNER_KEYS: &str = "/keys.json";
pub const SIGNER_DIR_KEYS_ENV: &str = "SIGNER_LOADER_DIR_KEYS";
pub const SIGNER_DIR_KEYS: &str = "/keys";
pub const SIGNER_DIR_SECRETS_ENV: &str = "SIGNER_LOADER_DIR_SECRETS";
pub const SIGNER_DIR_SECRETS: &str = "/secrets";

pub const JWTS_ENV: &str = "CB_JWTS";

// TODO: replace these with an actual image in the registry
pub const PBS_DEFAULT_IMAGE: &str = "commitboost_pbs_default";
pub const SIGNER_IMAGE: &str = "commitboost_signer";

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitBoostConfig {
    // TODO: generalize this with a spec file
    pub chain: Chain,
    pub relays: Vec<RelayConfig>,
    pub pbs: StaticPbsConfig,
    pub modules: Option<Vec<StaticModuleConfig>>,
    pub signer: Option<SignerConfig>,
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub logs: LogsSettings,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogsSettings {
    pub duration: RollingDuration,
    pub prefixes: HashMap<String, String>,
}

impl Default for LogsSettings {
    fn default() -> Self {
        Self { duration: RollingDuration::Hourly, prefixes: Default::default() }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RollingDuration {
    #[serde(rename = "minutely")]
    Minutely,
    #[serde(rename = "hourly")]
    Hourly,
    #[serde(rename = "daily")]
    Daily,
    #[serde(rename = "never")]
    Never,
}

fn load_from_file<T: DeserializeOwned>(path: &str) -> Result<T> {
    let config_file =
        std::fs::read_to_string(path).wrap_err(format!("Unable to find config file: {path}"))?;
    toml::from_str(&config_file).wrap_err("could not deserialize toml from string")
}

fn load_file_from_env<T: DeserializeOwned>(env: &str) -> Result<T> {
    let path = std::env::var(env).wrap_err(format!("{env} is not set"))?;
    load_from_file(&path)
}

/// Loads a map of module id -> jwt token from a json env
fn load_jwts() -> Result<HashMap<String, String>> {
    let jwts = std::env::var(JWTS_ENV).wrap_err(format!("{JWTS_ENV} is not set"))?;
    serde_json::from_str(&jwts).wrap_err("could not deserialize json from string")
}

impl CommitBoostConfig {
    pub fn from_file(path: &str) -> Result<Self> {
        load_from_file(path)
    }

    pub fn from_env_path() -> Result<Self> {
        load_file_from_env(CB_CONFIG_ENV)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignerConfig {
    /// Docker image of the module
    #[serde(default = "default_signer")]
    pub docker_image: String,
    /// Which keys to load
    pub loader: SignerLoader,
}

fn default_signer() -> String {
    SIGNER_IMAGE.to_string()
}

#[derive(Debug)]
pub struct StartSignerConfig {
    pub chain: Chain,
    pub loader: SignerLoader,
    pub server_port: u16,
    pub jwts: HashMap<String, String>,
    pub logs_settings: LogsSettings,
}

impl StartSignerConfig {
    pub fn load_from_env() -> Result<Self> {
        let config = CommitBoostConfig::from_env_path()?;

        let jwts = load_jwts()?;
        let server_port = load_env_var(SIGNER_SERVER_ENV)?.parse()?;

        Ok(StartSignerConfig {
            chain: config.chain,
            loader: config.signer.expect("Signer config is missing").loader,
            server_port,
            jwts,
            logs_settings: config.logs,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetricsConfig {
    /// Path to prometheus config file
    pub prometheus_config: String,
    /// Whether to start a grafana service
    pub use_grafana: bool,
}

pub struct ModuleMetricsConfig {
    /// Where to open metrics server
    pub server_port: u16,
}

impl ModuleMetricsConfig {
    pub fn load_from_env() -> Result<Self> {
        let server_port = load_env_var(METRICS_SERVER_ENV)?.parse()?;
        Ok(ModuleMetricsConfig { server_port })
    }
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

/// Runtime config for the pbs module with support for custom extra config
/// This will be shared across threads, so the `extra` should be thread safe,
/// e.g. wrapped in an Arc
#[derive(Debug, Clone)]
pub struct PbsModuleConfig<T = ()> {
    /// Chain spec
    pub chain: Chain,
    /// Pbs default config
    pub pbs_config: Arc<PbsConfig>,
    /// List of relays
    pub relays: Vec<RelayClient>,
    /// Signer client to call Signer API
    pub signer_client: Option<SignerClient>,
    /// Opaque module config
    pub extra: T,
    /// Settings for logging in file, refer to Default implementation to see
    /// default values if not set.
    pub logs_settings: LogsSettings,
}

fn default_pbs() -> String {
    PBS_DEFAULT_IMAGE.to_string()
}

/// Loads the default pbs config, i.e. with no signer client or custom data
pub fn load_pbs_config() -> Result<PbsModuleConfig<()>> {
    let config = CommitBoostConfig::from_env_path()?;
    let relay_clients =
        config.relays.into_iter().map(RelayClient::new).collect::<Result<Vec<RelayClient>>>()?;

    Ok(PbsModuleConfig {
        chain: config.chain,
        pbs_config: Arc::new(config.pbs.pbs_config),
        relays: relay_clients,
        signer_client: None,
        extra: (),
        logs_settings: config.logs,
    })
}

/// Loads a custom pbs config, i.e. with signer client and/or custom data
pub fn load_pbs_custom_config<T: DeserializeOwned>() -> Result<PbsModuleConfig<T>> {
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
        #[serde(default)]
        logs_settings: LogsSettings,
    }

    // load module config including the extra data (if any)
    let cb_config: StubConfig<T> = load_file_from_env(CB_CONFIG_ENV)?;
    let relay_clients =
        cb_config.relays.into_iter().map(RelayClient::new).collect::<Result<Vec<RelayClient>>>()?;

    let signer_client = if cb_config.pbs.static_config.with_signer {
        // if custom pbs requires a signer client, load jwt
        let module_jwt = load_env_var(MODULE_JWT_ENV)?;
        let signer_server_address = load_env_var(SIGNER_SERVER_ENV)?;
        Some(SignerClient::new(signer_server_address, &module_jwt))
    } else {
        None
    }
    .transpose()?;

    Ok(PbsModuleConfig {
        chain: cb_config.chain,
        pbs_config: Arc::new(cb_config.pbs.static_config.pbs_config),
        relays: relay_clients,
        signer_client,
        extra: cb_config.pbs.extra,
        logs_settings: cb_config.logs_settings,
    })
}

/// Static module config from config file
#[derive(Debug, Deserialize, Serialize)]
pub struct StaticModuleConfig {
    /// Unique id of the module
    pub id: String,
    /// Docker image of the module
    pub docker_image: String,
}

/// Runtime config to start a module
#[derive(Debug)]
pub struct StartModuleConfig<T = ()> {
    /// Unique id of the module
    pub id: String,
    /// Chain spec
    pub chain: Chain,
    /// Signer client to call Signer API
    pub signer_client: SignerClient,
    /// Opaque module config
    pub extra: T,
    pub logs_settings: LogsSettings,
}

/// Loads a module config from the environment and config file:
/// - [MODULE_ID_ENV] - the id of the module to load
/// - [CB_CONFIG_ENV] - the path to the config file
/// - [MODULE_JWT_ENV] - the jwt token for the module
// TODO: add metrics url here
pub fn load_module_config<T: DeserializeOwned>() -> Result<StartModuleConfig<T>> {
    let module_id = load_env_var(MODULE_ID_ENV)?;
    let module_jwt = load_env_var(MODULE_JWT_ENV)?;
    let signer_server_address = load_env_var(SIGNER_SERVER_ENV)?;

    #[derive(Debug, Deserialize)]
    struct ThisModuleConfig<U> {
        #[serde(flatten)]
        static_config: StaticModuleConfig,
        #[serde(flatten)]
        extra: U,
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum ThisModule<U> {
        Target(ThisModuleConfig<U>),
        Other,
    }

    #[derive(Deserialize, Debug)]
    struct StubConfig<U> {
        chain: Chain,
        modules: Vec<ThisModule<U>>,
        #[serde(default)]
        logs_settings: LogsSettings,
    }

    // load module config including the extra data (if any)
    let cb_config: StubConfig<T> = load_file_from_env(CB_CONFIG_ENV)?;

    // find all matching modules config
    let matches: Vec<ThisModuleConfig<T>> = cb_config
        .modules
        .into_iter()
        .filter_map(|m| if let ThisModule::Target(config) = m { Some(config) } else { None })
        .collect();

    if matches.is_empty() {
        Err(eyre!("Failed to find matching config type"))
    } else {
        let module_config = matches
            .into_iter()
            .find(|m| m.static_config.id == module_id)
            .wrap_err(format!("failed to find module for {module_id}"))?;

        let signer_client = SignerClient::new(signer_server_address, &module_jwt)?;

        Ok(StartModuleConfig {
            id: module_config.static_config.id,
            chain: cb_config.chain,
            signer_client,
            extra: module_config.extra,
            logs_settings: cb_config.logs_settings,
        })
    }
}

pub fn load_env_var(env: &str) -> Result<String> {
    std::env::var(env).wrap_err("{env} is not set")
}
