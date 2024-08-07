use bimap::BiHashMap;
use eyre::{Context, Result};
use serde::de::DeserializeOwned;

use crate::types::{Jwt, ModuleId};

use super::constants::JWTS_ENV;

pub fn load_env_var(env: &str) -> Result<String> {
    std::env::var(env).wrap_err(format!("{env} is not set"))
}

pub fn load_from_file<T: DeserializeOwned>(path: &str) -> Result<T> {
    let config_file =
        std::fs::read_to_string(path).wrap_err(format!("Unable to find config file: {path}"))?;
    toml::from_str(&config_file).wrap_err("could not deserialize toml from string")
}

pub fn load_file_from_env<T: DeserializeOwned>(env: &str) -> Result<T> {
    let path = std::env::var(env).wrap_err(format!("{env} is not set"))?;
    load_from_file(&path)
}

/// Loads a bidirectional map of module id <-> jwt token from a json env
pub fn load_jwts() -> Result<BiHashMap<ModuleId, Jwt>> {
    let jwts = std::env::var(JWTS_ENV).wrap_err(format!("{JWTS_ENV} is not set"))?;
    serde_json::from_str(&jwts).wrap_err("could not deserialize json from string")
}
