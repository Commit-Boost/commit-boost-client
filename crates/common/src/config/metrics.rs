use eyre::Result;
use serde::{Deserialize, Serialize};

use super::{constants::METRICS_SERVER_ENV, load_optional_env_var};
use crate::utils::default_bool;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetricsConfig {
    /// Path to prometheus config file
    pub prometheus_config: String,
    /// Whether to start a grafana service
    #[serde(default = "default_bool::<true>")]
    pub use_grafana: bool,
}

/// Module runtime config set after init
pub struct ModuleMetricsConfig {
    /// Where to open metrics server
    pub server_port: u16,
}

impl ModuleMetricsConfig {
    pub fn load_from_env() -> Result<Option<Self>> {
        if let Some(server_port) = load_optional_env_var(METRICS_SERVER_ENV) {
            Ok(Some(ModuleMetricsConfig { server_port: server_port.parse()? }))
        } else {
            Ok(None)
        }
    }
}
