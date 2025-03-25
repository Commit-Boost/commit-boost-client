use std::{collections::HashSet, path::Path};

use eyre::{Context, Ok, Result};
use serde::de::DeserializeOwned;

use super::MODULES_ENV;
use crate::types::ModuleId;

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

/// Loads a set of module ids from a comma separated string
pub fn load_modules() -> Result<HashSet<ModuleId>> {
    let modules = std::env::var(MODULES_ENV).wrap_err(format!("{MODULES_ENV} is not set"))?;
    Ok(modules.split(',').map(|id| ModuleId(id.into())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_modules() {
        std::env::set_var(MODULES_ENV, "module1,module2,module3");

        let modules = load_modules().unwrap();

        assert_eq!(modules.len(), 3);
        assert!(modules.contains(&ModuleId("module1".into())));
        assert!(modules.contains(&ModuleId("module2".into())));
        assert!(modules.contains(&ModuleId("module3".into())));
    }
}
