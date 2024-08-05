use std::{
    fmt::{Display, Formatter},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogsSettings {
    #[serde(default)]
    pub duration: RollingDuration,
    #[serde(default, rename = "host-path")]
    pub host_path: PathBuf,
    #[serde(default, rename = "rust-log")]
    pub rust_log: String,
}

impl Default for LogsSettings {
    fn default() -> Self {
        Self {
            duration: RollingDuration::Hourly,
            host_path: "/var/log/pbs".into(),
            rust_log: "info".to_string(),
        }
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

impl Display for RollingDuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RollingDuration::Minutely => write!(f, "minutely"),
            RollingDuration::Hourly => write!(f, "hourly"),
            RollingDuration::Daily => write!(f, "daily"),
            RollingDuration::Never => write!(f, "never"),
        }
    }
}

impl Default for RollingDuration {
    fn default() -> Self {
        Self::Daily
    }
}
