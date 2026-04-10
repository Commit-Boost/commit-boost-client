use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use eyre::{Context, Result, bail};
use serde::de::DeserializeOwned;

use crate::{
    config::{ADMIN_JWT_ENV, JWTS_ENV, MUXER_HTTP_MAX_LENGTH},
    types::{BlsPublicKey, ModuleId},
    utils::read_chunked_body_with_max,
};

pub fn load_env_var(env: &str) -> Result<String> {
    std::env::var(env).wrap_err(format!("{env} is not set"))
}
pub fn load_optional_env_var(env: &str) -> Option<String> {
    std::env::var(env).ok()
}

pub fn load_from_file<P: AsRef<Path> + std::fmt::Debug, T: DeserializeOwned>(
    path: P,
) -> Result<(T, PathBuf)> {
    let config_file = std::fs::read_to_string(path.as_ref())
        .wrap_err(format!("Unable to find config file: {path:?}"))?;
    match toml::from_str(&config_file).wrap_err("could not deserialize toml from string") {
        Ok(config) => Ok((config, path.as_ref().to_path_buf())),
        Err(e) => Err(e),
    }
}

pub fn load_file_from_env<T: DeserializeOwned>(env: &str) -> Result<(T, PathBuf)> {
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
        if key_set.insert(key.clone()) {
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
    use std::sync::Mutex;

    use super::*;
    use crate::utils::TestRandomSeed;

    // Serializes all tests that read/write environment variables.
    // std::env::set_var is unsafe (Rust 1.81+) because mutating `environ`
    // while another thread reads it is UB at the OS level. Holding this
    // lock ensures our Rust threads don't race each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Sets or removes env vars for the duration of `f`, then restores the
    /// original values.  Pass `Some("val")` to set, `None` to ensure absent.
    fn with_env<R>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> R) -> R {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(&str, Option<String>)> =
            vars.iter().map(|(k, _)| (*k, std::env::var(k).ok())).collect();
        for (k, v) in vars {
            match v {
                Some(val) => unsafe { std::env::set_var(k, val) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        let result = f();
        for (k, old) in &saved {
            match old {
                Some(v) => unsafe { std::env::set_var(k, v) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        result
    }

    // Minimal TOML-deserializable type used by load_from_file / load_file_from_env
    // tests.
    #[derive(serde::Deserialize, Debug, PartialEq)]
    struct TestConfig {
        value: String,
    }

    // ── decode_string_to_map ─────────────────────────────────────────────────

    #[test]
    fn test_decode_string_to_map_single_pair() {
        let map = decode_string_to_map("ONLY=ONE").unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&ModuleId("ONLY".into())), Some(&"ONE".to_string()));
    }

    #[test]
    fn test_decode_string_to_map_empty_string() {
        // An empty string yields one token with no `=`, which is invalid.
        assert!(decode_string_to_map("").is_err());
    }

    #[test]
    fn test_decode_string_to_map_malformed_no_equals() {
        assert!(decode_string_to_map("KEYONLY").is_err());
    }

    // ── remove_duplicate_keys ────────────────────────────────────────────────

    #[test]
    fn test_remove_duplicate_keys() {
        let key1 = BlsPublicKey::test_random();
        let key2 = BlsPublicKey::test_random();
        let keys = vec![key1.clone(), key2.clone(), key1.clone()];

        let unique_keys = remove_duplicate_keys(keys);
        assert_eq!(unique_keys.len(), 2);
        assert!(unique_keys.contains(&key1));
        assert!(unique_keys.contains(&key2));
    }

    // ── load_env_var ─────────────────────────────────────────────────────────

    #[test]
    fn test_load_env_var_present() {
        with_env(&[("CB_TEST_LOAD_ENV_VAR", Some("hello"))], || {
            assert_eq!(load_env_var("CB_TEST_LOAD_ENV_VAR").unwrap(), "hello");
        });
    }

    #[test]
    fn test_load_env_var_absent() {
        with_env(&[("CB_TEST_LOAD_ENV_VAR_ABSENT", None)], || {
            let err = load_env_var("CB_TEST_LOAD_ENV_VAR_ABSENT").unwrap_err();
            assert!(err.to_string().contains("CB_TEST_LOAD_ENV_VAR_ABSENT"));
        });
    }

    // ── load_optional_env_var ────────────────────────────────────────────────

    #[test]
    fn test_load_optional_env_var_present() {
        with_env(&[("CB_TEST_OPT_VAR", Some("world"))], || {
            assert_eq!(load_optional_env_var("CB_TEST_OPT_VAR"), Some("world".to_string()));
        });
    }

    #[test]
    fn test_load_optional_env_var_absent() {
        with_env(&[("CB_TEST_OPT_VAR_ABSENT", None)], || {
            assert_eq!(load_optional_env_var("CB_TEST_OPT_VAR_ABSENT"), None);
        });
    }

    // ── load_from_file ───────────────────────────────────────────────────────

    #[test]
    fn test_load_from_file_valid() {
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"value = \"hello\"").unwrap();
        let path = file.path().to_path_buf();

        let (config, returned_path): (TestConfig, _) = load_from_file(&path).unwrap();
        assert_eq!(config.value, "hello");
        assert_eq!(returned_path, path);
    }

    #[test]
    fn test_load_from_file_missing() {
        let result: eyre::Result<(TestConfig, _)> =
            load_from_file("/nonexistent/cb_test_path/file.toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_file_invalid_toml() {
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"not valid toml !!!{{").unwrap();

        let result: eyre::Result<(TestConfig, _)> = load_from_file(file.path());
        assert!(result.is_err());
    }

    // ── load_file_from_env ───────────────────────────────────────────────────

    #[test]
    fn test_load_file_from_env_ok() {
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"value = \"from_env\"").unwrap();
        let path = file.path().to_str().unwrap().to_owned();

        with_env(&[("CB_TEST_FILE_ENV", Some(&path))], || {
            let (config, _): (TestConfig, _) = load_file_from_env("CB_TEST_FILE_ENV").unwrap();
            assert_eq!(config.value, "from_env");
        });
    }

    #[test]
    fn test_load_file_from_env_var_not_set() {
        with_env(&[("CB_TEST_FILE_ENV_ABSENT", None)], || {
            let result: eyre::Result<(TestConfig, _)> =
                load_file_from_env("CB_TEST_FILE_ENV_ABSENT");
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("CB_TEST_FILE_ENV_ABSENT"));
        });
    }

    // ── load_jwt_secrets ─────────────────────────────────────────────────────

    #[test]
    fn test_load_jwt_secrets_ok() {
        with_env(
            &[
                (ADMIN_JWT_ENV, Some("admin_secret")),
                (JWTS_ENV, Some("MODULE1=secret1,MODULE2=secret2")),
            ],
            || {
                let (admin_jwt, secrets) = load_jwt_secrets().unwrap();
                assert_eq!(admin_jwt, "admin_secret");
                assert_eq!(secrets.get(&ModuleId("MODULE1".into())), Some(&"secret1".to_string()));
                assert_eq!(secrets.get(&ModuleId("MODULE2".into())), Some(&"secret2".to_string()));
            },
        );
    }

    #[test]
    fn test_load_jwt_secrets_missing_admin_jwt() {
        with_env(&[(ADMIN_JWT_ENV, None), (JWTS_ENV, Some("MODULE1=secret1"))], || {
            let err = load_jwt_secrets().unwrap_err();
            assert!(err.to_string().contains(ADMIN_JWT_ENV));
        });
    }

    #[test]
    fn test_load_jwt_secrets_missing_jwts() {
        with_env(&[(ADMIN_JWT_ENV, Some("admin_secret")), (JWTS_ENV, None)], || {
            let err = load_jwt_secrets().unwrap_err();
            assert!(err.to_string().contains(JWTS_ENV));
        });
    }

    #[test]
    fn test_load_jwt_secrets_malformed_jwts() {
        with_env(&[(ADMIN_JWT_ENV, Some("admin_secret")), (JWTS_ENV, Some("MALFORMED"))], || {
            assert!(load_jwt_secrets().is_err());
        });
    }
}
