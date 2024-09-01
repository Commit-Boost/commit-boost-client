use eyre::Result;
use serde::{Deserialize, Serialize};

use crate::types::Chain;

mod constants;
mod metrics;
mod module;
mod pbs;
mod signer;
mod utils;

mod log;

pub use constants::*;
pub use log::*;
pub use metrics::*;
pub use module::*;
pub use pbs::*;
pub use signer::*;
pub use utils::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitBoostConfig {
    // TODO: generalize this with a spec file
    pub chain: Chain,
    pub relays: Vec<RelayConfig>,
    pub pbs: StaticPbsConfig,
    pub modules: Option<Vec<StaticModuleConfig>>,
    pub signer: Option<SignerConfig>,
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub logs: LogsSettings,
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

    pub fn from_env_path() -> Result<Self> {
        let config: Self = load_file_from_env(CB_CONFIG_ENV)?;
        config.validate()?;
        Ok(config)
    }
}
