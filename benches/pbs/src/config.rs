use std::fs;

use cb_common::config::CommitBoostConfig;
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    pub commit_boost: CommitBoostConfig,
    pub benchmark: BenchmarkConfig,
    pub bench: Vec<BenchConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    pub n_slots: u64,
    pub headers_per_slot: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchConfig {
    pub id: String,
    pub url: Url,
}

pub fn load_static_config() -> Config {
    let path =
        std::env::args().nth(1).expect("missing config path. Add config eg. `bench-config.toml'");
    let config_file = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("Unable to find config file: '{}'", path));
    let config: Config = toml::from_str(&config_file).expect("failed to parse toml");

    config
}
