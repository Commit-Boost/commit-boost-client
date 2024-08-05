use std::collections::HashMap;

use eyre::Result;
use serde::{Deserialize, Serialize};

use crate::types::Chain;

mod constants;
mod metrics;
mod module;
mod pbs;
mod signer;
mod utils;

pub use constants::*;
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
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub logs: LogsSettings,
}

impl CommitBoostConfig {
    pub fn from_file(path: &str) -> Result<Self> {
        load_from_file(path)
    }

    pub fn from_env_path() -> Result<Self> {
        load_file_from_env(CB_CONFIG_ENV)
    }
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
