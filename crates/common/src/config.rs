use std::net::SocketAddr;

use alloy_primitives::U256;
use serde::{
    de::{self, DeserializeOwned},
    Deserialize, Deserializer, Serialize,
};

use super::utils::as_eth_str;
use crate::{pbs::RelayEntry, signer::Signer, types::Chain};

pub const CONFIG_PATH_ENV: &str = "COMMIT_BOOST_CONFIG";
pub const MODULE_ID_ENV: &str = "COMMIT_BOOST_MODULE_ID";

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitBoostConfig {
    pub chain: Chain,
    pub pbs: BuilderConfig,
    pub modules: Option<Vec<ModuleConfig>>,
    pub signer: Option<SignerConfig>,
    pub metrics: Option<MetricsConfig>,
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

    pub loader: SignerLoader,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetricsConfig {
    /// Where to start metrics server
    pub address: SocketAddr,

    pub jwt_path: String
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignerLoader {
    /// Plain text, do not use in prod
    File { key_path: String },
}

impl SignerLoader {
    pub fn load_keys(self) -> Vec<Signer> {
        match self {
            SignerLoader::File { key_path: path } => {
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
