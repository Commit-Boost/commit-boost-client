use std::net::Ipv4Addr;

use eyre::Result;
use serde::{Deserialize, Serialize};

use super::{constants::METRICS_PORT_ENV, load_optional_env_var};
use crate::utils::{default_bool, default_host, default_u16};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetricsConfig {
    /// Whether to collect metrics
    #[serde(default = "default_bool::<true>")]
    pub enabled: bool,
    /// Host for metrics servers
    #[serde(default = "default_host")]
    pub host: Ipv4Addr,
    /// Port to listen on for metrics, following ports will be port+1, port+2,
    /// etc.
    #[serde(default = "default_u16::<10000>")]
    pub start_port: u16,
}

/// Module runtime config set after init
pub struct ModuleMetricsConfig {
    /// Where to open metrics server
    pub server_port: u16,
}

impl ModuleMetricsConfig {
    pub fn load_from_env() -> Result<Option<Self>> {
        if let Some(server_port) = load_optional_env_var(METRICS_PORT_ENV) {
            Ok(Some(ModuleMetricsConfig { server_port: server_port.parse()? }))
        } else {
            Ok(None)
        }
    }
}
