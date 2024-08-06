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
    #[serde(default, rename = "max-log-files")]
    pub max_log_files: Option<usize>,
}

impl Default for LogsSettings {
    fn default() -> Self {
        Self {
            duration: RollingDuration::Hourly,
            host_path: "/var/logs/commit-boost".into(),
            rust_log: "info".to_string(),
            max_log_files: None,
        }
    }
}

pub fn default_log_level() -> String {
    "info".into()
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RollingDuration {
    Hourly,
    #[default]
    Daily,
    Never,
}

impl Display for RollingDuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RollingDuration::Hourly => write!(f, "hourly"),
            RollingDuration::Daily => write!(f, "daily"),
            RollingDuration::Never => write!(f, "never"),
        }
    }
}
