use std::net::SocketAddr;

use alloy_primitives::U256;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::utils::as_eth_str;
use crate::{pbs::RelayEntry, types::Chain};

pub const CONFIG_PATH_ENV: &str = "COMMIT_BOOST_CONFIG";
pub const MODULE_ID_ENV: &str = "COMMIT_BOOST_MODULE_ID";

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitBoostConfig {
    pub chain: Chain,
    pub pbs: BuilderConfig,
    pub modules: Vec<ModuleConfig>,
    pub signer: SignerConfig,
}

fn load_from_file<T: DeserializeOwned>(path: &str) -> T {
    let config_file =
        std::fs::read_to_string(path).expect(&format!("Unable to find config file: '{}'", path));
    toml::from_str(&config_file).unwrap()
}

fn load_from_env<T: DeserializeOwned>() -> T {
    let path = std::env::var(CONFIG_PATH_ENV).expect(&format!("{CONFIG_PATH_ENV} is not set"));

    load_from_file(&path)
}

impl CommitBoostConfig {
    pub fn from_file(path: &str) -> Self {
        load_from_file(path)
    }

    pub fn from_env_path() -> Self {
        load_from_env()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignerConfig {
    /// Where to start signing server
    pub address: SocketAddr,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BuilderConfig {
    /// Path to override PBS module
    pub path: Option<String>,
    /// Which port to open listen
    pub address: SocketAddr,
    /// Which relay to register/subscribe
    pub relays: Vec<RelayEntry>,
    /// Whether to forward getStatus to relays or skip it
    pub relay_check: bool,
    #[serde(default = "default_u64::<950>")]
    pub timeout_get_header_ms: u64,
    #[serde(default = "default_u64::<4000>")]
    pub timeout_get_payload_ms: u64,
    #[serde(default = "default_u64::<3000>")]
    pub timeout_register_validator_ms: u64,
    // TODO: add custom headers
    /// Whether to skip the relay signature verification
    #[serde(default = "default_bool::<false>")]
    pub skip_sigverify: bool,
    #[serde(rename = "min_bid_eth", with = "as_eth_str", default = "default_u256")]
    pub min_bid_wei: U256,
}

const fn default_u64<const U: u64>() -> u64 {
    U
}

const fn default_bool<const U: bool>() -> bool {
    U
}

const fn default_u256() -> U256 {
    U256::ZERO
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ModuleConfig<T = ()> {
    pub id: String,
    pub path: String,
    #[serde(flatten)]
    pub extra: T,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StartModuleConfig<T = ()> {
    pub chain: Chain,
    pub sign_address: SocketAddr,
    pub config: ModuleConfig<T>,
}

// TODO: load with custom data like module
pub fn load_pbs_config() -> (Chain, BuilderConfig) {
    let config = CommitBoostConfig::from_env_path();
    (config.chain, config.pbs)
}

pub fn load_module_config<T: DeserializeOwned>() -> StartModuleConfig<T> {
    let id = std::env::var(MODULE_ID_ENV).expect(&format!("{MODULE_ID_ENV} is not set"));

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum CustomModule<U> {
        Target(ModuleConfig<U>),
        Other,
    }

    #[derive(Deserialize, Debug)]
    struct StubConfig<U> {
        chain: Chain,
        signer: SignerConfig,
        modules: Vec<CustomModule<U>>,
    }

    let config: StubConfig<T> = load_from_env();

    let matches: Vec<ModuleConfig<T>> = config
        .modules
        .into_iter()
        .filter_map(|m| if let CustomModule::Target(config) = m { Some(config) } else { None })
        .collect();

    if matches.is_empty() {
        eprintln!("Failed to find matching config type");
        std::process::exit(1);
    }

    let module_config =
        matches.into_iter().find(|m| m.id == id).expect(&format!("failed to find module for {id}"));

    StartModuleConfig {
        chain: config.chain,
        config: module_config,
        sign_address: config.signer.address,
    }
}
