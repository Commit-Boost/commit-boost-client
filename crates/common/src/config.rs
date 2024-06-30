use std::{collections::HashMap, net::SocketAddr};

use alloy_primitives::U256;
use serde::{
    de::{self, DeserializeOwned},
    Deserialize, Deserializer, Serialize,
};

use super::utils::as_eth_str;
use crate::{pbs::RelayEntry, signer::Signer, types::Chain};

pub const MODULE_ID_ENV: &str = "CB_MODULE_ID";
pub const MODULE_JWT_ENV: &str = "CB_MODULE_JWT";
pub const METRICS_SERVER_URL: &str = "METRICS_SERVER_URL";

pub const CB_CONFIG_ENV: &str = "CB_CONFIG";
pub const CB_CONFIG_NAME: &str = "/cb-config.toml";

pub const SIGNER_LOADER_ENV: &str = "CB_SIGNER_LOADER_FILE";
pub const SIGNER_LOADER_NAME: &str = "/keys.json";

pub const JWTS_ENV: &str = "CB_JWTS";

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitBoostConfig {
    // TODO: generalize this with a spec file
    pub chain: Chain,
    pub pbs: PbsConfig,
    pub modules: Option<Vec<ModuleConfig>>,
    pub signer: Option<SignerConfig>,
    pub metrics: Option<MetricsConfig>,
}

fn load_from_file<T: DeserializeOwned>(path: &str) -> T {
    let config_file =
        std::fs::read_to_string(path).expect(&format!("Unable to find config file: '{}'", path));
    toml::from_str(&config_file).unwrap()
}

fn load_from_env<T: DeserializeOwned>(env: &str) -> T {
    let path = std::env::var(env).expect(&format!("{env} is not set"));
    load_from_file(&path)
}

/// Loads a map of module id -> jwt token from a json env
pub fn load_jwts() -> HashMap<String, String> {
    let jwts = std::env::var(JWTS_ENV).expect(&format!("{JWTS_ENV} is not set"));
    serde_json::from_str(&jwts).expect(&format!("Failed to parse jwts: {jwts}"))
}

impl CommitBoostConfig {
    pub fn from_file(path: &str) -> Self {
        load_from_file(path)
    }

    pub fn from_env_path() -> Self {
        load_from_env(CB_CONFIG_ENV)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignerConfig {
    /// Where to start signing server
    pub address: SocketAddr,

    /// Which keys to load
    pub loader: SignerLoader,
}

impl SignerConfig {
    pub fn load_from_env() -> (Chain, Self) {
        let config = CommitBoostConfig::from_env_path();
        (config.chain, config.signer.expect("Signer config is missing"))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetricsConfig {
    /// Where to start metrics server
    pub address: SocketAddr,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum SignerLoader {
    /// Plain text, do not use in prod
    File { key_path: String },
}

impl SignerLoader {
    pub fn load_keys(self) -> Vec<Signer> {
        // TODO: add flag to support also native loader
        self.load_from_env()
    }

    pub fn load_from_env(self) -> Vec<Signer> {
        match self {
            SignerLoader::File { .. } => {
                let path = std::env::var(SIGNER_LOADER_ENV)
                    .expect(&format!("{SIGNER_LOADER_ENV} is not set"));
                let file =
                    std::fs::read_to_string(path).expect(&format!("Unable to find keys file"));

                let keys: Vec<FileKey> = serde_json::from_str(&file).unwrap();

                keys.into_iter().map(|k| Signer::new_from_bytes(&k.secret_key)).collect()
            }
        }
    }
}

pub struct FileKey {
    pub secret_key: [u8; 32],
}

/// What a commit module needs to call the Signer API
pub struct CommitSignerConfig {
    /// Address of the signer service
    pub address: SocketAddr,
    /// JWT token to authenticate
    pub jwt: String,
}

// TODO: handle docker image override and other custom fields (like custom modules)
#[derive(Debug, Deserialize, Serialize)]
pub struct PbsConfig {
    /// Path to docker image
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
    pub docker_image: String,
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
pub fn load_pbs_config() -> (Chain, PbsConfig) {
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

    let config: StubConfig<T> = load_from_env(CB_CONFIG_ENV);

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

impl<'de> Deserialize<'de> for FileKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s =
            alloy_primitives::hex::decode(s.trim_start_matches("0x")).map_err(de::Error::custom)?;
        let bytes: [u8; 32] = s.try_into().map_err(|_| de::Error::custom("wrong lenght"))?;

        Ok(FileKey { secret_key: bytes })
    }
}

#[cfg(test)]
mod tests {

    use super::FileKey;

    #[test]
    fn test_decode() {
        let s = [
            0, 136, 227, 100, 165, 57, 106, 129, 181, 15, 235, 189, 200, 120, 70, 99, 251, 144,
            137, 181, 230, 124, 189, 193, 115, 153, 26, 0, 197, 135, 103, 63,
        ];

        let d = r#"[
    "0088e364a5396a81b50febbdc8784663fb9089b5e67cbdc173991a00c587673f",
    "0088e364a5396a81b50febbdc8784663fb9089b5e67cbdc173991a00c587673f"
]"#;
        let decoded: Vec<FileKey> = serde_json::from_str(d).unwrap();

        assert_eq!(decoded[0].secret_key, s)
    }
}
