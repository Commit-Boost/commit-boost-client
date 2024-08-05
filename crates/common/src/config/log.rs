use std::{
    fmt::{Display, Formatter},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

use super::CB_BASE_LOG_PATH;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogsSettings {
    #[serde(default)]
    pub rotation: RollingDuration,
    #[serde(default = "default_log_dir_path")]
    pub log_dir_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub max_log_files: Option<usize>,
}

impl Default for LogsSettings {
    fn default() -> Self {
        Self {
            rotation: RollingDuration::default(),
            log_dir_path: default_log_dir_path(),
            log_level: default_log_level(),
            max_log_files: None,
        }
    }
}

fn default_log_dir_path() -> PathBuf {
    CB_BASE_LOG_PATH.into()
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
