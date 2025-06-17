use std::path::Path;

use eyre::{Context, Result};
use serde::de::DeserializeOwned;

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

// TODO: This was only used by the old JWT loader, can it be removed now?
/*
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

    /// TODO: This was only used by the old JWT loader, can it be removed now?
    #[test]
    fn test_decode_string_to_map() {
        let raw = " KEY=VALUE , KEY2=value2 ";

        let map = decode_string_to_map(raw).unwrap();

        assert_eq!(map.get(&ModuleId("KEY".into())), Some(&"VALUE".to_string()));
        assert_eq!(map.get(&ModuleId("KEY2".into())), Some(&"value2".to_string()));
    }
}
*/
