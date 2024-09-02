use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::CB_BASE_LOG_PATH;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogsSettings {
    #[serde(default = "default_log_dir_path")]
    pub log_dir_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub max_log_files: Option<usize>,
}

fn default_log_dir_path() -> PathBuf {
    CB_BASE_LOG_PATH.into()
}

pub fn default_log_level() -> String {
    "info".into()
}
