use std::path::PathBuf;

use eyre::Result;
use serde::{Deserialize, Serialize};

use super::{load_optional_env_var, CommitBoostConfig, LOGS_DIR_DEFAULT, LOGS_DIR_ENV};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogsSettings {
    #[serde(default = "default_log_dir_path")]
    pub log_dir_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub max_log_files: Option<usize>,
}

impl Default for LogsSettings {
    fn default() -> Self {
        LogsSettings {
            log_dir_path: default_log_dir_path(),
            log_level: default_log_level(),
            max_log_files: None,
        }
    }
}

impl LogsSettings {
    pub fn from_env_config() -> Result<Option<Self>> {
        let mut config = CommitBoostConfig::from_env_path()?;

        // Override log dir path if env var is set
        if let Some(log_config) = config.logs.as_mut() {
            if let Some(log_dir) = load_optional_env_var(LOGS_DIR_ENV) {
                log_config.log_dir_path = log_dir.into();
            }
        }

        Ok(config.logs)
    }
}

fn default_log_dir_path() -> PathBuf {
    LOGS_DIR_DEFAULT.into()
}

pub fn default_log_level() -> String {
    "info".into()
}
