use eyre::Result;
use serde::{Deserialize, Serialize};

use super::{constants::METRICS_SERVER_ENV, load_env_var};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetricsConfig {
    /// Path to prometheus config file
    pub prometheus_config: String,
    /// Whether to start a grafana service
    pub use_grafana: bool,
}

/// Module runtime config set after init
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
