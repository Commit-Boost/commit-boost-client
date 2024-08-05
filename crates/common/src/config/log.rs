use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogsSettings {
    #[serde(default)]
    pub duration: RollingDuration,
    #[serde(default)]
    pub base_path: PathBuf,
}

impl Default for LogsSettings {
    fn default() -> Self {
        Self { duration: RollingDuration::Hourly, base_path: "/var/logs".into() }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RollingDuration {
    Minutely,
    Hourly,
    Daily,
    Never,
}

impl Default for RollingDuration {
    fn default() -> Self {
        Self::Daily
    }
}
