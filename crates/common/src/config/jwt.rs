use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
};

use alloy::primitives::B256;
use eyre::{bail, Result};
use serde::Deserialize;

use crate::types::ModuleId;

/// Underlying implementation of the JWT configuration that's deserialized from
/// disk.
#[derive(Deserialize)]
struct JwtConfigOnDisk {
    module_name: ModuleId,

    // One of these must be provided - they're listed here in order of precedence
    jwt_env: Option<String>,
    jwt_file: Option<PathBuf>,
    jwt_secret: Option<String>,

    signing_id: B256,
}

impl JwtConfigOnDisk {
    /// Load the JWT secret from the provides sources, in order of precedence.
    fn load_jwt_secret(&self) -> Result<String> {
        // Start with the environment variable
        let jwt_string = if let Some(jwt_env) = &self.jwt_env {
            // Load JWT secret from environment variable
            std::env::var(jwt_env).map_err(|e| {
                eyre::eyre!(
                    "Failed to read JWT secret from environment variable '{jwt_env}': {}",
                    e
                )
            })?
        } else if let Some(jwt_file) = &self.jwt_file {
            // Load JWT secret from file
            std::fs::read_to_string(jwt_file).map_err(|e| {
                eyre::eyre!("Failed to read JWT secret from file '{}': {}", jwt_file.display(), e)
            })?
        } else if let Some(jwt_secret) = &self.jwt_secret {
            // Use the provided JWT secret directly
            jwt_secret.clone()
        } else {
            bail!("No JWT secret provided");
        };

        Ok(jwt_string)
    }
}

#[derive(Deserialize)]
struct JwtConfigFile {
    modules: Vec<JwtConfigOnDisk>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JwtConfig {
    /// Human-readable name of the module.
    pub module_name: ModuleId,

    /// The JWT secret for the module to communicate with the signer module.
    pub jwt_secret: String,

    /// A unique identifier for the module, which is used when signing requests
    /// to generate signatures for this module. Must be a 32-byte hex string.
    /// A leading 0x prefix is optional.
    pub signing_id: B256,
}

impl JwtConfig {
    pub fn validate(&self) -> Result<()> {
        // Ensure the JWT secret is not empty
        if self.jwt_secret.is_empty() {
            bail!("JWT secret cannot be empty");
        }

        // Ensure the signing ID is a valid B256
        if self.signing_id.is_zero() {
            bail!("Signing ID cannot be zero");
        }

        Ok(())
    }
}

/// Load the JWT configuration from a file.
pub fn load(config_file_path: &Path) -> Result<HashMap<ModuleId, JwtConfig>> {
    // Make sure the file is legal
    if !config_file_path.is_absolute() {
        bail!("JWT config file '{}' must be an absolute path", config_file_path.display());
    }
    let config_file_path = config_file_path.canonicalize().map_err(|e| {
        eyre::eyre!(
            "Failed to canonicalize JWT config path '{}': {}",
            config_file_path.display(),
            e
        )
    })?;
    if config_file_path.extension().map_or(true, |ext| ext != "toml") {
        bail!("JWT config file '{}' must have a .toml extension", config_file_path.display());
    }
    if !config_file_path.exists() {
        bail!("JWT config file '{}' does not exist", config_file_path.display());
    }
    if !config_file_path.is_file() {
        bail!("JWT config file '{}' is not a regular file", config_file_path.display());
    }

    // Parse the JWT config file
    let mut file = std::fs::File::open(&config_file_path).map_err(|e| {
        eyre::eyre!("Failed to open JWT config file '{}': {}", config_file_path.display(), e)
    })?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let jwt_configs: JwtConfigFile = toml::from_str(&contents).map_err(|e| {
        eyre::eyre!("Failed to parse JWT config '{}': {}", config_file_path.display(), e)
    })?;

    load_impl(jwt_configs)
}

/// Implementation for loading a JWT configuration from a file.
fn load_impl(config_file: JwtConfigFile) -> Result<HashMap<ModuleId, JwtConfig>> {
    // Load the JWT secrets and validate them
    let mut jwt_configs = HashMap::new();
    for raw_config in config_file.modules {
        let jwt_secret = raw_config.load_jwt_secret()?;
        let jwt_config = JwtConfig {
            module_name: raw_config.module_name.clone(),
            jwt_secret,
            signing_id: raw_config.signing_id,
        };
        jwt_config.validate()?;

        // Make sure there are no duplicate module names
        if jwt_configs.contains_key(&raw_config.module_name) {
            bail!("Duplicate JWT configuration for module '{}'", raw_config.module_name);
        }

        // Make sure the signing ID hasn't been used before
        if jwt_configs
            .values()
            .any(|existing_config: &JwtConfig| existing_config.signing_id == jwt_config.signing_id)
        {
            bail!(
                "Duplicate signing ID '{}' for module '{}'",
                jwt_config.signing_id,
                raw_config.module_name
            );
        }

        // Safe to use
        jwt_configs.insert(raw_config.module_name, jwt_config);
    }

    Ok(jwt_configs)
}

#[cfg(test)]
mod tests {
    use alloy::primitives::b256;

    use super::*;

    #[tokio::test]
    async fn test_good_config() -> Result<()> {
        let toml_str = r#"
            [[modules]]
            module_name = "test_module"
            jwt_secret = "supersecret"
            signing_id = "0101010101010101010101010101010101010101010101010101010101010101"

            [[modules]]
            module_name = "2nd_test_module"
            jwt_secret = "another-secret"
            signing_id = "0x0202020202020202020202020202020202020202020202020202020202020202"
        "#;

        // Load the JWT configuration
        let jwt_config_file: JwtConfigFile =
            toml::from_str(toml_str).expect("Failed to deserialize JWT config");
        let jwts = load_impl(jwt_config_file)?;
        assert!(jwts.len() == 2, "Expected 2 JWT configurations");

        // Check the first module
        let module_id_1 = ModuleId("test_module".to_string());
        let module_1 = jwts.get(&module_id_1).expect("Missing 'test_module' in JWT configs");
        assert_eq!(module_1.module_name, module_id_1, "Module name mismatch for 'test_module'");
        assert_eq!(
            module_1.jwt_secret,
            "supersecret".to_string(),
            "JWT secret mismatch for 'test_module'"
        );
        assert_eq!(
            module_1.signing_id,
            b256!("0101010101010101010101010101010101010101010101010101010101010101"),
            "Signing ID mismatch for 'test_module'"
        );

        // Check the second module
        let module_id_2 = ModuleId("2nd_test_module".to_string());
        assert!(jwts.contains_key(&module_id_2), "Missing '2nd_test_module' in JWT configs");
        let module_2 = jwts.get(&module_id_2).expect("Missing '2nd_test_module' in JWT configs");
        assert_eq!(module_2.module_name, module_id_2, "Module name mismatch for '2nd_test_module'");
        assert_eq!(
            module_2.jwt_secret,
            "another-secret".to_string(),
            "JWT secret mismatch for '2nd_test_module'"
        );
        assert_eq!(
            module_2.signing_id,
            b256!("0202020202020202020202020202020202020202020202020202020202020202"),
            "Signing ID mismatch for '2nd_test_module'"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_jwt_from_env() -> Result<()> {
        let jwt = "supersecret-env";
        let jwt_env = "CB_TEST_MODULE_JTW";
        let toml_str = r#"
            [[modules]]
            module_name = "test_module"
            jwt_env = "CB_TEST_MODULE_JTW"
            signing_id = "0101010101010101010101010101010101010101010101010101010101010101"
        "#;

        // Set the environment variable
        std::env::set_var(jwt_env, jwt);
        struct EnvVarGuard {
            env_name: &'static str,
        }
        impl Drop for EnvVarGuard {
            fn drop(&mut self) {
                std::env::remove_var(self.env_name);
            }
        }

        // Load the JWT configuration
        let jwts: HashMap<ModuleId, JwtConfig>;
        {
            let _env_guard = EnvVarGuard { env_name: jwt_env };
            let jwt_config_file: JwtConfigFile =
                toml::from_str(toml_str).expect("Failed to deserialize JWT config");
            jwts = load_impl(jwt_config_file)?;
        }
        assert!(jwts.len() == 1, "Expected 1 JWT configuration");

        // Check the module
        let module_id = ModuleId("test_module".to_string());
        let module = jwts.get(&module_id).expect("Missing 'test_module' in JWT configs");
        assert_eq!(module.module_name, module_id, "Module name mismatch for 'test_module'");
        assert_eq!(module.jwt_secret, jwt.to_string(), "JWT secret mismatch for 'test_module'");
        assert_eq!(
            module.signing_id,
            b256!("0101010101010101010101010101010101010101010101010101010101010101"),
            "Signing ID mismatch for 'test_module'"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_jwt_from_file() -> Result<()> {
        let jwt = "supersecret-file";
        let cwd = std::env::current_dir()?;
        let mut jwt_file_path = cwd.join("../../tests/data/module-jwt.txt");
        jwt_file_path = jwt_file_path.canonicalize()?;
        let toml_str = format!(
            r#"
            [[modules]]
            module_name = "test_module"
            jwt_file = "{}"
            signing_id = "0101010101010101010101010101010101010101010101010101010101010101"
        "#,
            jwt_file_path.display()
        );

        // Load the JWT configuration
        let jwt_config_file: JwtConfigFile =
            toml::from_str(&toml_str).expect("Failed to deserialize JWT config");
        let jwts = load_impl(jwt_config_file)?;
        assert!(jwts.len() == 1, "Expected 1 JWT configuration");

        // Check the module
        let module_id = ModuleId("test_module".to_string());
        let module = jwts.get(&module_id).expect("Missing 'test_module' in JWT configs");
        assert_eq!(module.module_name, module_id, "Module name mismatch for 'test_module'");
        assert_eq!(module.jwt_secret, jwt.to_string(), "JWT secret mismatch for 'test_module'");
        assert_eq!(
            module.signing_id,
            b256!("0101010101010101010101010101010101010101010101010101010101010101"),
            "Signing ID mismatch for 'test_module'"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_duplicate_module_names() -> Result<()> {
        let toml_str = r#"
            [[modules]]
            module_name = "test_module"
            jwt_secret = "supersecret"
            signing_id = "0101010101010101010101010101010101010101010101010101010101010101"

            [[modules]]
            module_name = "test_module"  # Duplicate name
            jwt_secret = "another-secret"
            signing_id = "0202020202020202020202020202020202020202020202020202020202020202"
        "#;
        let jwt_config_file: JwtConfigFile =
            toml::from_str(toml_str).expect("Failed to deserialize JWT config");
        let result = load_impl(jwt_config_file);
        assert!(result.is_err(), "Expected error due to duplicate module names");
        if let Err(e) = result {
            assert_eq!(&e.to_string(), "Duplicate JWT configuration for module 'test_module'");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_duplicate_signing_ids() -> Result<()> {
        let toml_str = r#"
            [[modules]]
            module_name = "test_module"
            jwt_secret = "supersecret"
            signing_id = "0101010101010101010101010101010101010101010101010101010101010101"

            [[modules]]
            module_name = "2nd_test_module"
            jwt_secret = "another-secret"
            signing_id = "0101010101010101010101010101010101010101010101010101010101010101"  # Duplicate signing ID
        "#;
        let jwt_config_file: JwtConfigFile =
            toml::from_str(toml_str).expect("Failed to deserialize JWT config");
        let result = load_impl(jwt_config_file);
        assert!(result.is_err(), "Expected error due to duplicate signing IDs");
        if let Err(e) = result {
            assert_eq!(&e.to_string(),"Duplicate signing ID '0x0101010101010101010101010101010101010101010101010101010101010101' for module '2nd_test_module'");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_missing_jwt_secret() -> Result<()> {
        let toml_str = r#"
            [[modules]]
            module_name = "test_module"
            signing_id = "0101010101010101010101010101010101010101010101010101010101010101"
        "#;
        let jwt_config_file: JwtConfigFile =
            toml::from_str(toml_str).expect("Failed to deserialize JWT config");
        let result = load_impl(jwt_config_file);
        assert!(result.is_err(), "Expected error due to missing JWT secret");
        if let Err(e) = result {
            assert_eq!(&e.to_string(), "No JWT secret provided");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_empty_jwt_secret() -> Result<()> {
        let cfg = JwtConfig {
            module_name: ModuleId("test_module".to_string()),
            jwt_secret: "".to_string(),
            signing_id: b256!("0101010101010101010101010101010101010101010101010101010101010101"),
        };

        let result = cfg.validate();
        assert!(result.is_err(), "Expected error due to empty JWT secret");
        if let Err(e) = result {
            assert_eq!(&e.to_string(), "JWT secret cannot be empty");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_zero_signing_id() -> Result<()> {
        let cfg = JwtConfig {
            module_name: ModuleId("test_module".to_string()),
            jwt_secret: "supersecret".to_string(),
            signing_id: b256!("0000000000000000000000000000000000000000000000000000000000000000"),
        };
        let result = cfg.validate();
        assert!(result.is_err(), "Expected error due to zero signing ID");
        if let Err(e) = result {
            assert_eq!(&e.to_string(), "Signing ID cannot be zero");
        }
        Ok(())
    }
}
