use std::path::PathBuf;

use eyre::Result;
use serde::{Deserialize, Serialize};

use crate::types::{load_chain_from_file, Chain, ChainLoader, ForkVersion};

mod constants;
mod log;
mod metrics;
mod module;
mod mux;
mod pbs;
mod signer;
mod utils;

pub use constants::*;
pub use log::*;
pub use metrics::*;
pub use module::*;
pub use mux::*;
pub use pbs::*;
pub use signer::*;
pub use utils::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitBoostConfig {
    pub chain: Chain,
    pub relays: Vec<RelayConfig>,
    pub pbs: StaticPbsConfig,
    #[serde(flatten)]
    pub muxes: Option<PbsMuxes>,
    pub modules: Option<Vec<StaticModuleConfig>>,
    pub signer: Option<SignerConfig>,
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub logs: LogsSettings,
}

impl CommitBoostConfig {
    /// Validate config
    pub async fn validate(&self) -> Result<()> {
        self.pbs.pbs_config.validate(self.chain).await?;
        Ok(())
    }

    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let config: Self = load_from_file(path)?;
        Ok(config)
    }

    // When loading the config from the environment, it's important that every path
    // is replaced with the correct value if the config is loaded inside a container
    pub fn from_env_path() -> Result<Self> {
        let helper_config: HelperConfig = load_file_from_env(CONFIG_ENV)?;

        let chain = match helper_config.chain {
            ChainLoader::Path { path, genesis_time_secs } => {
                // check if the file path is overridden by env var
                let (slot_time_secs, genesis_fork_version) =
                    if let Some(path) = load_optional_env_var(CHAIN_SPEC_ENV) {
                        load_chain_from_file(path.parse()?)?
                    } else {
                        load_chain_from_file(path)?
                    };
                Chain::Custom { genesis_time_secs, slot_time_secs, genesis_fork_version }
            }
            ChainLoader::Known(known) => Chain::from(known),
            ChainLoader::Custom { genesis_time_secs, slot_time_secs, genesis_fork_version } => {
                let genesis_fork_version: ForkVersion = genesis_fork_version.as_ref().try_into()?;
                Chain::Custom { genesis_time_secs, slot_time_secs, genesis_fork_version }
            }
        };

        let config = CommitBoostConfig {
            chain,
            relays: helper_config.relays,
            pbs: helper_config.pbs,
            muxes: helper_config.muxes,
            modules: helper_config.modules,
            signer: helper_config.signer,
            metrics: helper_config.metrics,
            logs: helper_config.logs,
        };

        Ok(config)
    }

    /// Returns the path to the chain spec file if any
    pub fn chain_spec_file(path: &PathBuf) -> Option<PathBuf> {
        match load_from_file::<_, ChainConfig>(path) {
            Ok(config) => {
                if let ChainLoader::Path { path, genesis_time_secs: _ } = config.chain {
                    Some(path)
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
    chain: ChainLoader,
    relays: Vec<RelayConfig>,
    pbs: StaticPbsConfig,
    #[serde(flatten)]
    muxes: Option<PbsMuxes>,
    modules: Option<Vec<StaticModuleConfig>>,
    signer: Option<SignerConfig>,
    metrics: Option<MetricsConfig>,
    #[serde(default)]
    logs: LogsSettings,
}
