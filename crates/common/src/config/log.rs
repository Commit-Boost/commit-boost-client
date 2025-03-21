use std::path::PathBuf;

use eyre::Result;
use serde::{Deserialize, Serialize};

use super::{load_optional_env_var, CommitBoostConfig, LOGS_DIR_DEFAULT, LOGS_DIR_ENV};
use crate::utils::default_bool;

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct LogsSettings {
    pub stdout: StdoutLogSettings,
    pub file: FileLogSettings,
}

impl LogsSettings {
    pub fn from_env_config() -> Result<Self> {
        let mut config = CommitBoostConfig::from_env_path()?;

        // Override log dir path if env var is set
        if let Some(log_dir) = load_optional_env_var(LOGS_DIR_ENV) {
            config.logs.file.dir_path = log_dir.into();
        }

        Ok(config.logs)
    }
}

fn default_log_dir_path() -> PathBuf {
    LOGS_DIR_DEFAULT.into()
}

fn default_level() -> String {
    "info".into()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StdoutLogSettings {
    #[serde(default = "default_bool::<true>")]
    pub enabled: bool,
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default = "default_bool::<false>")]
    pub use_json: bool,
    #[serde(default = "default_bool::<true>")]
    pub color: bool,
}

impl Default for StdoutLogSettings {
    fn default() -> Self {
        Self { enabled: true, level: "info".into(), use_json: false, color: true }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileLogSettings {
    #[serde(default = "default_bool::<false>")]
    pub enabled: bool,
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default = "default_bool::<true>")]
    pub use_json: bool,
    #[serde(default = "default_log_dir_path")]
    pub dir_path: PathBuf,
    #[serde(default)]
    pub max_files: Option<usize>,
}

impl Default for FileLogSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            level: "info".into(),
            use_json: true,
            dir_path: default_log_dir_path(),
            max_files: None,
        }
    }
}
