use std::path::PathBuf;

use eyre::Result;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{fmt, Layer, Registry};

use super::{load_optional_env_var, CommitBoostConfig, LOGS_DIR_DEFAULT, LOGS_DIR_ENV};
use crate::logging::RawFormatter;

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Default, // default tracing format
    Raw,  // key=value format
    Json, // JSON format
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogDest {
    Stdout, // Only console output
    File,   // Only file output
    #[default]
    Both, // Both console and file output
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogsSettings {
    #[serde(default = "default_log_dir_path")]
    pub log_dir_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub max_log_files: Option<usize>,
    #[serde(default)]
    pub format: LogFormat,
    #[serde(default)]
    pub destination: LogDest,
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

    /// Creates a format layer based on the configured format type
    pub fn create_format_layer(&self) -> Box<dyn Layer<Registry> + Send + Sync> {
        match self.format {
            LogFormat::Default => Box::new(fmt::layer().with_target(false)),
            LogFormat::Raw => Box::new(fmt::layer().with_target(false).event_format(RawFormatter)),
            LogFormat::Json => {
                Box::new(fmt::layer().with_target(false).json().with_current_span(true))
            }
        }
    }
}

impl Default for LogsSettings {
    fn default() -> Self {
        LogsSettings {
            log_dir_path: default_log_dir_path(),
            log_level: default_log_level(),
            max_log_files: None,
            format: LogFormat::default(),
            destination: LogDest::default(),
        }
    }
}

fn default_log_dir_path() -> PathBuf {
    LOGS_DIR_DEFAULT.into()
}

pub fn default_log_level() -> String {
    "info".into()
}
