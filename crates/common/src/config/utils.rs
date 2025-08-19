use std::{collections::HashMap, path::Path};

use alloy::rpc::types::beacon::BlsPublicKey;
use eyre::{bail, Context, Result};
use serde::de::DeserializeOwned;

use crate::{
    config::{ADMIN_JWT_ENV, JWTS_ENV, MUXER_HTTP_MAX_LENGTH},
    types::ModuleId,
    utils::read_chunked_body_with_max,
};

pub fn load_env_var(env: &str) -> Result<String> {
    std::env::var(env).wrap_err(format!("{env} is not set"))
}
pub fn load_optional_env_var(env: &str) -> Option<String> {
    std::env::var(env).ok()
}

pub fn load_from_file<P: AsRef<Path> + std::fmt::Debug, T: DeserializeOwned>(path: P) -> Result<T> {
    let config_file = std::fs::read_to_string(path.as_ref())
        .wrap_err(format!("Unable to find config file: {path:?}"))?;
    toml::from_str(&config_file).wrap_err("could not deserialize toml from string")
}

pub fn load_file_from_env<T: DeserializeOwned>(env: &str) -> Result<T> {
    let path = std::env::var(env).wrap_err(format!("{env} is not set"))?;
    load_from_file(&path)
}

/// Loads a map of module id -> jwt secret from a json env
pub fn load_jwt_secrets() -> Result<(String, HashMap<ModuleId, String>)> {
    let admin_jwt = std::env::var(ADMIN_JWT_ENV).wrap_err(format!("{ADMIN_JWT_ENV} is not set"))?;
    let jwt_secrets = std::env::var(JWTS_ENV).wrap_err(format!("{JWTS_ENV} is not set"))?;
    decode_string_to_map(&jwt_secrets).map(|secrets| (admin_jwt, secrets))
}

/// Reads an HTTP response safely, erroring out if it failed or if the body is
/// too large.
pub async fn safe_read_http_response(response: reqwest::Response) -> Result<Vec<u8>> {
    // Read the response to a buffer in chunks
    let status_code = response.status();
    match read_chunked_body_with_max(response, MUXER_HTTP_MAX_LENGTH).await {
        Ok(response_bytes) => {
            if status_code.is_success() {
                return Ok(response_bytes);
            }
            bail!(
                "Request failed with status: {status_code}, body: {}",
                String::from_utf8_lossy(&response_bytes)
            )
        }
        Err(e) => {
            if status_code.is_success() {
                return Err(e).wrap_err("Failed to read response body");
            }
            Err(e).wrap_err(format!(
                "Request failed with status {status_code}, but decoding the response body failed"
            ))
        }
    }
}

/// Removes duplicate entries from a vector of BlsPublicKey
pub fn remove_duplicate_keys(keys: Vec<BlsPublicKey>) -> Vec<BlsPublicKey> {
    let mut unique_keys = Vec::new();
    let mut key_set = std::collections::HashSet::new();

    for key in keys {
        if key_set.insert(key) {
            unique_keys.push(key);
        }
    }

    unique_keys
}

pub fn decode_string_to_map(raw: &str) -> Result<HashMap<ModuleId, String>> {
    // trim the string and split for comma
    raw.trim()
        .split(',')
        .map(|pair| {
            let mut parts = pair.trim().split('=');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => Ok((ModuleId(key.into()), value.into())),
                _ => bail!("Invalid key-value pair: {pair}"),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TODO: This was only used by the old JWT loader, can it be removed now?
    #[test]
    fn test_decode_string_to_map() {
        let raw = " KEY=VALUE , KEY2=value2 ";

        let map = decode_string_to_map(raw).unwrap();

        assert_eq!(map.get(&ModuleId("KEY".into())), Some(&"VALUE".to_string()));
        assert_eq!(map.get(&ModuleId("KEY2".into())), Some(&"value2".to_string()));
    }

    #[test]
    fn test_remove_duplicate_keys() {
        let key1 = BlsPublicKey::from([1; 48]);
        let key2 = BlsPublicKey::from([2; 48]);
        let keys = vec![key1, key2, key1];

        let unique_keys = remove_duplicate_keys(keys);
        assert_eq!(unique_keys.len(), 2);
        assert!(unique_keys.contains(&key1));
        assert!(unique_keys.contains(&key2));
    }
}
