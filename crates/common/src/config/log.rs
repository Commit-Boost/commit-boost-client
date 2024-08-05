use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogsSettings {
    pub duration: RollingDuration,
    pub prefixes: HashMap<String, String>,
}

impl Default for LogsSettings {
    fn default() -> Self {
        Self { duration: RollingDuration::Hourly, prefixes: Default::default() }
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
