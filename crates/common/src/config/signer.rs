use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use alloy::primitives::B256;
use docker_image::DockerImage;
use eyre::{bail, ensure, Context, OptionExt, Result};
use serde::{Deserialize, Serialize};
use tonic::transport::{Certificate, Identity};
use url::Url;

use super::{
    load_optional_env_var, utils::load_env_var, CommitBoostConfig, SIGNER_ENDPOINT_ENV,
    SIGNER_IMAGE_DEFAULT, SIGNER_JWT_AUTH_FAIL_LIMIT_DEFAULT, SIGNER_JWT_AUTH_FAIL_LIMIT_ENV,
    SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_DEFAULT, SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_ENV,
    SIGNER_PORT_DEFAULT,
};
use crate::{
    config::{
        load_jwt_secrets, DIRK_CA_CERT_ENV, DIRK_CERT_ENV, DIRK_DIR_SECRETS_ENV, DIRK_KEY_ENV,
    },
    signer::{ProxyStore, SignerLoader},
    types::{Chain, ModuleId},
    utils::{default_host, default_u16, default_u32},
};

/// The signing configuration for a commitment module.
#[derive(Clone, Debug, PartialEq)]
pub struct ModuleSigningConfig {
    /// Human-readable name of the module.
    pub module_name: ModuleId,

    /// The JWT secret for the module to communicate with the signer module.
    pub jwt_secret: String,

    /// A unique identifier for the module, which is used when signing requests
    /// to generate signatures for this module. Must be a 32-byte hex string.
    /// A leading 0x prefix is optional.
    pub signing_id: B256,
}

impl ModuleSigningConfig {
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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SignerConfig {
    /// Host address to listen for signer API calls on
    #[serde(default = "default_host")]
    pub host: Ipv4Addr,
    /// Port to listen for signer API calls on
    #[serde(default = "default_u16::<SIGNER_PORT_DEFAULT>")]
    pub port: u16,
    /// Docker image of the module
    #[serde(default = "default_signer_image")]
    pub docker_image: String,

    /// Number of JWT auth failures before rate limiting an endpoint
    /// If set to 0, no rate limiting will be applied
    #[serde(default = "default_u32::<SIGNER_JWT_AUTH_FAIL_LIMIT_DEFAULT>")]
    pub jwt_auth_fail_limit: u32,

    /// Duration in seconds to rate limit an endpoint after the JWT auth failure
    /// limit has been reached
    #[serde(default = "default_u32::<SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_DEFAULT>")]
    pub jwt_auth_fail_timeout_seconds: u32,

    /// Inner type-specific configuration
    #[serde(flatten)]
    pub inner: SignerType,
}

impl SignerConfig {
    /// Validate the signer config
    pub async fn validate(&self) -> Result<()> {
        // Port must be positive
        ensure!(self.port > 0, "Port must be positive");

        // The Docker tag must parse
        ensure!(!self.docker_image.is_empty(), "Docker image is empty");
        ensure!(
            DockerImage::parse(&self.docker_image).is_ok(),
            format!("Invalid Docker image: {}", self.docker_image)
        );

        Ok(())
    }
}

fn default_signer_image() -> String {
    SIGNER_IMAGE_DEFAULT.to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct DirkHostConfig {
    /// Domain name of the server to use in TLS verification
    pub server_name: Option<String>,
    /// Complete URL of the Dirk server
    pub url: Url,
    /// Wallets to load consensus keys from
    pub wallets: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SignerType {
    /// Local signer module
    Local {
        /// Which keys to load
        loader: SignerLoader,
        /// How to store keys
        store: Option<ProxyStore>,
    },
    /// Remote signer module with compatible API like Web3Signer
    Remote {
        /// Complete URL of the base API endpoint
        url: Url,
    },
    /// Dirk remote signer module
    Dirk {
        /// List of Dirk hosts with their accounts
        hosts: Vec<DirkHostConfig>,
        /// Path to the client certificate
        cert_path: PathBuf,
        /// Path to the client key
        key_path: PathBuf,
        /// Path to where the account passwords are stored
        secrets_path: PathBuf,
        /// Path to the CA certificate
        ca_cert_path: Option<PathBuf>,
        /// How to store proxy key delegations
        /// ERC2335 is not supported with Dirk signer
        store: Option<ProxyStore>,
    },
}

#[derive(Clone, Debug)]
pub struct DirkConfig {
    pub hosts: Vec<DirkHostConfig>,
    pub client_cert: Identity,
    pub secrets_path: PathBuf,
    pub cert_auth: Option<Certificate>,
}

#[derive(Debug, Clone)]
pub struct StartSignerConfig {
    pub chain: Chain,
    pub loader: Option<SignerLoader>,
    pub store: Option<ProxyStore>,
    pub endpoint: SocketAddr,
    pub mod_signing_configs: HashMap<ModuleId, ModuleSigningConfig>,
    pub admin_secret: String,
    pub jwt_auth_fail_limit: u32,
    pub jwt_auth_fail_timeout_seconds: u32,
    pub dirk: Option<DirkConfig>,
}

impl StartSignerConfig {
    pub fn load_from_env() -> Result<Self> {
        let config = CommitBoostConfig::from_env_path()?;

        let (admin_secret, jwt_secrets) = load_jwt_secrets()?;

        // Load the module signing configs
        let mod_signing_configs = load_module_signing_configs(&config, &jwt_secrets)
            .wrap_err("Failed to load module signing configs")?;

        let signer_config = config.signer.ok_or_eyre("Signer config is missing")?;

        // Load the server endpoint first from the env var if present, otherwise the
        // config
        let endpoint = if let Some(endpoint) = load_optional_env_var(SIGNER_ENDPOINT_ENV) {
            endpoint.parse()?
        } else {
            SocketAddr::from((signer_config.host, signer_config.port))
        };

        // Load the JWT auth fail limit the same way
        let jwt_auth_fail_limit =
            if let Some(limit) = load_optional_env_var(SIGNER_JWT_AUTH_FAIL_LIMIT_ENV) {
                limit.parse()?
            } else {
                signer_config.jwt_auth_fail_limit
            };

        // Load the JWT auth fail timeout the same way
        let jwt_auth_fail_timeout_seconds = if let Some(timeout) =
            load_optional_env_var(SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_ENV)
        {
            timeout.parse()?
        } else {
            signer_config.jwt_auth_fail_timeout_seconds
        };

        match signer_config.inner {
            SignerType::Local { loader, store, .. } => Ok(StartSignerConfig {
                chain: config.chain,
                loader: Some(loader),
                endpoint,
                mod_signing_configs,
                admin_secret,
                jwt_auth_fail_limit,
                jwt_auth_fail_timeout_seconds,
                store,
                dirk: None,
            }),

            SignerType::Dirk {
                hosts,
                cert_path,
                key_path,
                secrets_path,
                ca_cert_path,
                store,
                ..
            } => {
                let cert_path = load_env_var(DIRK_CERT_ENV).map(PathBuf::from).unwrap_or(cert_path);
                let key_path = load_env_var(DIRK_KEY_ENV).map(PathBuf::from).unwrap_or(key_path);
                let secrets_path =
                    load_env_var(DIRK_DIR_SECRETS_ENV).map(PathBuf::from).unwrap_or(secrets_path);
                let ca_cert_path =
                    load_env_var(DIRK_CA_CERT_ENV).map(PathBuf::from).ok().or(ca_cert_path);

                if let Some(ProxyStore::ERC2335 { .. }) = store {
                    bail!("ERC2335 store is not supported with Dirk signer")
                }

                Ok(StartSignerConfig {
                    chain: config.chain,
                    endpoint,
                    mod_signing_configs,
                    admin_secret,
                    jwt_auth_fail_limit,
                    jwt_auth_fail_timeout_seconds,
                    loader: None,
                    store,
                    dirk: Some(DirkConfig {
                        hosts,
                        client_cert: Identity::from_pem(
                            std::fs::read_to_string(cert_path)?,
                            std::fs::read_to_string(key_path)?,
                        ),
                        secrets_path,
                        cert_auth: match ca_cert_path {
                            Some(path) => {
                                Some(Certificate::from_pem(std::fs::read_to_string(path)?))
                            }
                            None => None,
                        },
                    }),
                })
            }

            SignerType::Remote { .. } => {
                bail!("Remote signer configured")
            }
        }
    }
}

/// Loads the signing configurations for each module defined in the Commit Boost
/// config, coupling them with their JWT secrets and handling any potential
/// duplicates or missing values.
pub fn load_module_signing_configs(
    config: &CommitBoostConfig,
    jwt_secrets: &HashMap<ModuleId, String>,
) -> Result<HashMap<ModuleId, ModuleSigningConfig>> {
    let mut mod_signing_configs = HashMap::new();
    let modules = config.modules.as_ref().ok_or_eyre("No modules defined in the config")?;

    let mut seen_jwt_secrets = HashMap::new();
    let mut seen_signing_ids = HashMap::new();
    for module in modules {
        // Validate the module ID
        ensure!(!module.id.is_empty(), "Module ID cannot be empty");

        // Make sure it hasn't been used yet
        ensure!(
            !mod_signing_configs.contains_key(&module.id),
            "Duplicate module config detected: ID {} is already used",
            module.id
        );

        // Make sure the JWT secret is present
        let jwt_secret = match jwt_secrets.get(&module.id) {
            Some(secret) => secret.clone(),
            None => bail!("JWT secret for module {} is missing", module.id),
        };
        // Create the module signing config and validate it
        let module_signing_config = ModuleSigningConfig {
            module_name: module.id.clone(),
            jwt_secret,
            signing_id: module.signing_id,
        };
        module_signing_config
            .validate()
            .wrap_err(format!("Invalid signing config for module {}", module.id))?;

        // Check for duplicates in JWT secrets and signing IDs
        if let Some(existing_module) =
            seen_jwt_secrets.insert(module_signing_config.jwt_secret.clone(), &module.id)
        {
            bail!("Duplicate JWT secret detected for modules {} and {}", existing_module, module.id)
        };
        if let Some(existing_module) =
            seen_signing_ids.insert(module_signing_config.signing_id, &module.id)
        {
            bail!("Duplicate signing ID detected for modules {} and {}", existing_module, module.id)
        };

        mod_signing_configs.insert(module.id.clone(), module_signing_config);
    }

    Ok(mod_signing_configs)
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{b256, Uint};

    use super::*;
    use crate::config::{LogsSettings, ModuleKind, PbsConfig, StaticModuleConfig, StaticPbsConfig};

    async fn get_base_config() -> CommitBoostConfig {
        CommitBoostConfig {
            chain: Chain::Hoodi,
            relays: vec![],
            pbs: StaticPbsConfig {
                docker_image: String::from(""),
                pbs_config: PbsConfig {
                    host: Ipv4Addr::new(127, 0, 0, 1),
                    port: 0,
                    relay_check: false,
                    wait_all_registrations: false,
                    timeout_get_header_ms: 0,
                    timeout_get_payload_ms: 0,
                    timeout_register_validator_ms: 0,
                    skip_sigverify: false,
                    min_bid_wei: Uint::<256, 4>::from(0),
                    late_in_slot_time_ms: 0,
                    extra_validation_enabled: false,
                    rpc_url: None,
                    http_timeout_seconds: 30,
                    register_validator_retry_limit: 3,
                },
                with_signer: true,
            },
            muxes: None,
            modules: Some(vec![]),
            signer: None,
            metrics: None,
            logs: LogsSettings::default(),
        }
    }

    async fn create_module_config(id: ModuleId, signing_id: B256) -> StaticModuleConfig {
        StaticModuleConfig {
            id: id.clone(),
            signing_id,
            docker_image: String::from(""),
            env: None,
            env_file: None,
            kind: ModuleKind::Commit,
        }
    }

    #[tokio::test]
    async fn test_good_config() -> Result<()> {
        let mut cfg = get_base_config().await;
        let first_module_id = ModuleId("test_module".to_string());
        let first_signing_id =
            b256!("0101010101010101010101010101010101010101010101010101010101010101");
        let second_module_id = ModuleId("2nd_test_module".to_string());
        let second_signing_id =
            b256!("0202020202020202020202020202020202020202020202020202020202020202");

        cfg.modules = Some(vec![
            create_module_config(first_module_id.clone(), first_signing_id).await,
            create_module_config(second_module_id.clone(), second_signing_id).await,
        ]);

        let jwts = HashMap::from([
            (first_module_id.clone(), "supersecret".to_string()),
            (second_module_id.clone(), "another-secret".to_string()),
        ]);

        // Load the mod signing configuration
        let mod_signing_configs = load_module_signing_configs(&cfg, &jwts)
            .wrap_err("Failed to load module signing configs")?;
        assert!(mod_signing_configs.len() == 2, "Expected 2 mod signing configurations");

        // Check the first module
        let module_1 = mod_signing_configs
            .get(&first_module_id)
            .unwrap_or_else(|| panic!("Missing '{first_module_id}' in mod signing configs"));
        assert_eq!(module_1.module_name, first_module_id, "Module name mismatch for 'test_module'");
        assert_eq!(
            module_1.jwt_secret, jwts[&first_module_id],
            "JWT secret mismatch for '{first_module_id}'"
        );
        assert_eq!(
            module_1.signing_id, first_signing_id,
            "Signing ID mismatch for '{first_module_id}'"
        );

        // Check the second module
        let module_2 = mod_signing_configs
            .get(&second_module_id)
            .unwrap_or_else(|| panic!("Missing '{second_module_id}' in mod signing configs"));
        assert_eq!(
            module_2.module_name, second_module_id,
            "Module name mismatch for '{second_module_id}'"
        );
        assert_eq!(
            module_2.jwt_secret, jwts[&second_module_id],
            "JWT secret mismatch for '{second_module_id}'"
        );
        assert_eq!(
            module_2.signing_id, second_signing_id,
            "Signing ID mismatch for '{second_module_id}'"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_duplicate_module_names() -> Result<()> {
        let mut cfg = get_base_config().await;
        let first_module_id = ModuleId("test_module".to_string());
        let first_signing_id =
            b256!("0101010101010101010101010101010101010101010101010101010101010101");
        let second_module_id = ModuleId("2nd_test_module".to_string());
        let second_signing_id =
            b256!("0202020202020202020202020202020202020202020202020202020202020202");

        cfg.modules = Some(vec![
            create_module_config(first_module_id.clone(), first_signing_id).await,
            create_module_config(first_module_id.clone(), second_signing_id).await, /* Duplicate
                                                                                     * module
                                                                                     * name */
        ]);

        let jwts = HashMap::from([
            (first_module_id.clone(), "supersecret".to_string()),
            (second_module_id.clone(), "another-secret".to_string()),
        ]);

        // Make sure there was an error
        let result = load_module_signing_configs(&cfg, &jwts);
        assert!(result.is_err(), "Expected error due to duplicate module names");
        if let Err(e) = result {
            assert_eq!(
                e.to_string(),
                format!("Duplicate module config detected: ID {first_module_id} is already used")
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_duplicate_jwt_secrets() -> Result<()> {
        let mut cfg = get_base_config().await;
        let first_module_id = ModuleId("test_module".to_string());
        let first_signing_id =
            b256!("0101010101010101010101010101010101010101010101010101010101010101");
        let second_module_id = ModuleId("2nd_test_module".to_string());
        let second_signing_id =
            b256!("0202020202020202020202020202020202020202020202020202020202020202");

        cfg.modules = Some(vec![
            create_module_config(first_module_id.clone(), first_signing_id).await,
            create_module_config(second_module_id.clone(), second_signing_id).await,
        ]);

        let jwts = HashMap::from([
            (first_module_id.clone(), "supersecret".to_string()),
            (second_module_id.clone(), "supersecret".to_string()), /* Duplicate JWT secret */
        ]);

        // Make sure there was an error
        let result = load_module_signing_configs(&cfg, &jwts);
        assert!(result.is_err(), "Expected error due to duplicate JWT secrets");
        if let Err(e) = result {
            assert_eq!(
                e.to_string(),
                format!(
                    "Duplicate JWT secret detected for modules {first_module_id} and {second_module_id}",
                )
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_duplicate_signing_ids() -> Result<()> {
        let mut cfg = get_base_config().await;
        let first_module_id = ModuleId("test_module".to_string());
        let first_signing_id =
            b256!("0101010101010101010101010101010101010101010101010101010101010101");
        let second_module_id = ModuleId("2nd_test_module".to_string());

        cfg.modules = Some(vec![
            create_module_config(first_module_id.clone(), first_signing_id).await,
            create_module_config(second_module_id.clone(), first_signing_id).await, /* Duplicate signing ID */
        ]);

        let jwts = HashMap::from([
            (first_module_id.clone(), "supersecret".to_string()),
            (second_module_id.clone(), "another-secret".to_string()),
        ]);

        // Make sure there was an error
        let result = load_module_signing_configs(&cfg, &jwts);
        assert!(result.is_err(), "Expected error due to duplicate signing IDs");
        if let Err(e) = result {
            assert_eq!(
                e.to_string(),
                format!(
                    "Duplicate signing ID detected for modules {first_module_id} and {second_module_id}",
                )
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_missing_jwt_secret() -> Result<()> {
        let mut cfg = get_base_config().await;
        let first_module_id = ModuleId("test_module".to_string());
        let first_signing_id =
            b256!("0101010101010101010101010101010101010101010101010101010101010101");
        let second_module_id = ModuleId("2nd_test_module".to_string());
        let second_signing_id =
            b256!("0202020202020202020202020202020202020202020202020202020202020202");

        cfg.modules = Some(vec![
            create_module_config(first_module_id.clone(), first_signing_id).await,
            create_module_config(second_module_id.clone(), second_signing_id).await,
        ]);

        let jwts = HashMap::from([(second_module_id.clone(), "another-secret".to_string())]);

        // Make sure there was an error
        let result = load_module_signing_configs(&cfg, &jwts);
        assert!(result.is_err(), "Expected error due to missing JWT secret");
        if let Err(e) = result {
            assert_eq!(
                e.to_string(),
                format!("JWT secret for module {first_module_id} is missing")
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_empty_jwt_secret() -> Result<()> {
        let mut cfg = get_base_config().await;
        let first_module_id = ModuleId("test_module".to_string());
        let first_signing_id =
            b256!("0101010101010101010101010101010101010101010101010101010101010101");

        cfg.modules =
            Some(vec![create_module_config(first_module_id.clone(), first_signing_id).await]);

        let jwts = HashMap::from([(first_module_id.clone(), "".to_string())]);

        // Make sure there was an error
        let result = load_module_signing_configs(&cfg, &jwts);
        assert!(result.is_err(), "Expected error due to empty JWT secret");
        if let Err(e) = result {
            assert!(format!("{:?}", e).contains("JWT secret cannot be empty"));
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_zero_signing_id() -> Result<()> {
        let mut cfg = get_base_config().await;
        let first_module_id = ModuleId("test_module".to_string());
        let first_signing_id =
            b256!("0000000000000000000000000000000000000000000000000000000000000000");

        cfg.modules =
            Some(vec![create_module_config(first_module_id.clone(), first_signing_id).await]);

        let jwts = HashMap::from([(first_module_id.clone(), "supersecret".to_string())]);

        // Make sure there was an error
        let result = load_module_signing_configs(&cfg, &jwts);
        assert!(result.is_err(), "Expected error due to zero signing ID");
        if let Err(e) = result {
            assert!(format!("{:?}", e).contains("Signing ID cannot be zero"));
        }
        Ok(())
    }
}
