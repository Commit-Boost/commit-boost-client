use std::{collections::HashMap, path::Path};

use bytes::{BufMut, BytesMut};
use eyre::{bail, Context, Result};
use serde::de::DeserializeOwned;

use super::JWTS_ENV;
use crate::{config::MUXER_HTTP_MAX_LENGTH, types::ModuleId};

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
pub fn load_jwt_secrets() -> Result<HashMap<ModuleId, String>> {
    let jwt_secrets = std::env::var(JWTS_ENV).wrap_err(format!("{JWTS_ENV} is not set"))?;
    decode_string_to_map(&jwt_secrets)
}

/// Reads an HTTP response safely, erroring out if it failed or if the body is
/// too large.
pub async fn safe_read_http_response(mut response: reqwest::Response) -> Result<String> {
    // Break if content length is provided but it's too big
    if let Some(length) = response.content_length() {
        if length > MUXER_HTTP_MAX_LENGTH {
            bail!("Response content length ({length}) exceeds the maximum allowed length ({MUXER_HTTP_MAX_LENGTH} bytes)");
        }
    }

    // Make sure the response is a 200
    if response.status() != reqwest::StatusCode::OK {
        bail!("Request failed with status: {}", response.status());
    }

    // Read the response to a buffer in chunks
    let mut buffer = BytesMut::with_capacity(1024);
    while let Some(chunk) = response.chunk().await? {
        if buffer.len() > MUXER_HTTP_MAX_LENGTH as usize {
            bail!(
                "Response body exceeds the maximum allowed length ({MUXER_HTTP_MAX_LENGTH} bytes)"
            );
        }
        buffer.put(chunk);
    }

    // Convert the buffer to a string
    let bytes = buffer.freeze();
    match std::str::from_utf8(&bytes) {
        Ok(s) => Ok(s.to_string()),
        Err(e) => bail!("Failed to decode response body as UTF-8: {e}"),
    }
}

fn decode_string_to_map(raw: &str) -> Result<HashMap<ModuleId, String>> {
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

    #[test]
    fn test_decode_string_to_map() {
        let raw = " KEY=VALUE , KEY2=value2 ";

        let map = decode_string_to_map(raw).unwrap();

        assert_eq!(map.get(&ModuleId("KEY".into())), Some(&"VALUE".to_string()));
        assert_eq!(map.get(&ModuleId("KEY2".into())), Some(&"value2".to_string()));
    }
}
