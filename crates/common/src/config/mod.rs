use std::path::PathBuf;

use eyre::Result;
use serde::{Deserialize, Serialize};

use crate::types::{load_chain_from_file, Chain, ChainLoader};

mod constants;
mod log;
mod metrics;
mod module;
mod pbs;
mod signer;
mod utils;

pub use constants::*;
pub use log::*;
pub use metrics::*;
pub use module::*;
pub use pbs::*;
pub use signer::*;
pub use utils::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitBoostConfig {
    pub chain: Chain,
    pub relays: Vec<RelayConfig>,
    pub pbs: StaticPbsConfig,
    pub modules: Option<Vec<StaticModuleConfig>>,
    pub signer: Option<SignerConfig>,
    pub metrics: Option<MetricsConfig>,
    pub logs: Option<LogsSettings>,
}

impl CommitBoostConfig {
    /// Validate config
    pub fn validate(&self) -> Result<()> {
        self.pbs.pbs_config.validate()?;
        Ok(())
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let config: Self = load_from_file(path)?;
        config.validate()?;
        Ok(config)
    }

    // When loading the config from the environment, it's important that every path
    // is replaced with the correct value if the config is loaded inside a container
    pub fn from_env_path() -> Result<Self> {
        let config = if let Some(path) = load_optional_env_var(CHAIN_SPEC_ENV) {
            // if the chain spec file is set, load it separately
            let chain: Chain = load_chain_from_file(path.parse()?)?;
            let rest_config: HelperConfig = load_file_from_env(CONFIG_ENV)?;

            CommitBoostConfig {
                chain,
                relays: rest_config.relays,
                pbs: rest_config.pbs,
                modules: rest_config.modules,
                signer: rest_config.signer,
                metrics: rest_config.metrics,
                logs: rest_config.logs,
            }
        } else {
            load_file_from_env(CONFIG_ENV)?
        };

        config.validate()?;
        Ok(config)
    }

    /// Returns the path to the chain spec file if any
    pub fn chain_spec_file(path: &str) -> Option<PathBuf> {
        match load_from_file::<ChainConfig>(path) {
            Ok(config) => {
                if let ChainLoader::Path(path_buf) = config.chain {
                    Some(path_buf)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}

/// Helper struct to load the chain spec file
#[derive(Deserialize)]
struct ChainConfig {
    chain: ChainLoader,
}

/// Helper struct to load the rest of the config
#[derive(Deserialize)]
struct HelperConfig {
    relays: Vec<RelayConfig>,
    pbs: StaticPbsConfig,
    modules: Option<Vec<StaticModuleConfig>>,
    signer: Option<SignerConfig>,
    metrics: Option<MetricsConfig>,
    logs: Option<LogsSettings>,
}
