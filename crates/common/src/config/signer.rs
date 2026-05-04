use std::{
    collections::HashMap,
    fmt::Display,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    path::PathBuf,
};

use alloy::primitives::B256;
use docker_image::DockerImage;
use eyre::{Context, OptionExt, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tonic::transport::{Certificate, Identity};
use url::Url;

use super::{
    CommitBoostConfig, SIGNER_ENDPOINT_ENV, SIGNER_JWT_AUTH_FAIL_LIMIT_DEFAULT,
    SIGNER_JWT_AUTH_FAIL_LIMIT_ENV, SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_DEFAULT,
    SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_ENV, SIGNER_PORT_DEFAULT, SIGNER_TLS_CERTIFICATE_NAME,
    SIGNER_TLS_CERTIFICATES_PATH_ENV, SIGNER_TLS_KEY_NAME, load_jwt_secrets, load_optional_env_var,
    utils::load_env_var,
};
use crate::{
    config::{
        COMMIT_BOOST_IMAGE_DEFAULT, DIRK_CA_CERT_ENV, DIRK_CERT_ENV, DIRK_DIR_SECRETS_ENV,
        DIRK_KEY_ENV,
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
        if self.jwt_secret.is_empty() {
            bail!("JWT secret cannot be empty");
        }

        if self.signing_id.is_zero() {
            bail!("Signing ID cannot be zero");
        }

        Ok(())
    }
}

/// Mode to use for TLS support when starting the signer service
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "path", rename_all = "snake_case")]
pub enum TlsMode {
    /// Don't use TLS (regular HTTP)
    Insecure,

    /// Use TLS with a certificate and key file in the provided directory
    Certificate(PathBuf),
}

/// Reverse proxy setup, used to extract real client's IP
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ReverseProxyHeaderSetup {
    #[default]
    None,
    Unique {
        header: String,
    },
    Rightmost {
        header: String,
        trusted_count: NonZeroUsize,
    },
}

impl Display for ReverseProxyHeaderSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReverseProxyHeaderSetup::None => write!(f, "None"),
            ReverseProxyHeaderSetup::Unique { header } => {
                write!(f, "\"{header} (unique)\"")
            }
            ReverseProxyHeaderSetup::Rightmost { header, trusted_count } => {
                let n = trusted_count.get();
                let suffix = match (n % 100, n % 10) {
                    (11..=13, _) => "th",
                    (_, 1) => "st",
                    (_, 2) => "nd",
                    (_, 3) => "rd",
                    _ => "th",
                };
                write!(f, "\"{header} ({trusted_count}{suffix} from the right)\"")
            }
        }
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
    /// limit has been reached. This also defines the interval at which failed
    /// attempts are regularly checked and expired ones are cleaned up.
    #[serde(default = "default_u32::<SIGNER_JWT_AUTH_FAIL_TIMEOUT_SECONDS_DEFAULT>")]
    pub jwt_auth_fail_timeout_seconds: u32,

    /// Mode to use for TLS support.
    /// If using Certificate mode, this must include a path to the TLS
    /// certificates directory (with a `cert.pem` and a `key.pem` file).
    #[serde(default = "default_tls_mode")]
    pub tls_mode: TlsMode,

    /// Reverse proxy setup to extract real client's IP
    #[serde(default)]
    pub reverse_proxy: ReverseProxyHeaderSetup,

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
    COMMIT_BOOST_IMAGE_DEFAULT.to_string()
}

fn default_tls_mode() -> TlsMode {
    TlsMode::Insecure // To make the default use TLS, do
    // TlsMode::Certificate(PathBuf::from("./certs"))
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
        /// Limits the maximum size of a decoded gRPC response.
        /// Default is 4MB (from tonic bindings)
        max_response_size_bytes: Option<usize>,
    },
}

#[derive(Clone, Debug)]
pub struct DirkConfig {
    pub hosts: Vec<DirkHostConfig>,
    pub client_cert: Identity,
    pub secrets_path: PathBuf,
    pub cert_auth: Option<Certificate>,
    pub max_response_size_bytes: Option<usize>,
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
    pub tls_certificates: Option<(Vec<u8>, Vec<u8>)>,
    pub reverse_proxy: ReverseProxyHeaderSetup,
}

impl StartSignerConfig {
    pub fn load_from_env() -> Result<Self> {
        let (config, _) = CommitBoostConfig::from_env_path()?;

        let (admin_secret, jwt_secrets) = load_jwt_secrets()?;

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

        // Load the TLS certificates if requested, generating self-signed ones if
        // necessary
        let tls_certificates = match signer_config.tls_mode {
            TlsMode::Insecure => None,
            TlsMode::Certificate(path) => {
                let certs_path = load_env_var(SIGNER_TLS_CERTIFICATES_PATH_ENV)
                    .map(PathBuf::from)
                    .unwrap_or(path);
                let cert_path = certs_path.join(SIGNER_TLS_CERTIFICATE_NAME);
                let key_path = certs_path.join(SIGNER_TLS_KEY_NAME);
                Some((std::fs::read(cert_path)?, std::fs::read(key_path)?))
            }
        };

        let reverse_proxy = signer_config.reverse_proxy;

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
                tls_certificates,
                reverse_proxy,
            }),

            SignerType::Dirk {
                hosts,
                cert_path,
                key_path,
                secrets_path,
                ca_cert_path,
                store,
                max_response_size_bytes,
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
                        max_response_size_bytes,
                    }),
                    tls_certificates,
                    reverse_proxy,
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
        ensure!(!module.id.is_empty(), "Module ID cannot be empty");

        ensure!(
            !mod_signing_configs.contains_key(&module.id),
            "Duplicate module config detected: ID {} is already used",
            module.id
        );

        let jwt_secret = match jwt_secrets.get(&module.id) {
            Some(secret) => secret.clone(),
            None => bail!("JWT secret for module {} is missing", module.id),
        };
        let module_signing_config = ModuleSigningConfig {
            module_name: module.id.clone(),
            jwt_secret,
            signing_id: module.signing_id,
        };
        module_signing_config
            .validate()
            .wrap_err(format!("Invalid signing config for module {}", module.id))?;

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
    use std::num::NonZeroUsize;

    use alloy::primitives::{Uint, b256};

    use super::*;
    use crate::config::{
        COMMIT_BOOST_IMAGE_DEFAULT, LogsSettings, ModuleKind, PbsConfig, StaticModuleConfig,
        StaticPbsConfig,
    };

    // Wrapper needed because TOML requires a top-level struct (can't serialize
    // a bare enum).
    #[derive(Serialize, Deserialize, Debug)]
    struct TlsWrapper {
        tls_mode: TlsMode,
    }

    fn make_local_signer_config(tls_mode: TlsMode) -> SignerConfig {
        SignerConfig {
            host: Ipv4Addr::LOCALHOST,
            port: 20000,
            docker_image: COMMIT_BOOST_IMAGE_DEFAULT.to_string(),
            jwt_auth_fail_limit: 3,
            jwt_auth_fail_timeout_seconds: 300,
            tls_mode,
            reverse_proxy: ReverseProxyHeaderSetup::None,
            inner: SignerType::Local {
                loader: SignerLoader::File { key_path: PathBuf::from("/keys.json") },
                store: None,
            },
        }
    }

    async fn get_config_with_signer(tls_mode: TlsMode) -> CommitBoostConfig {
        let mut cfg = get_base_config().await;
        cfg.signer = Some(make_local_signer_config(tls_mode));
        cfg
    }

    async fn get_base_config() -> CommitBoostConfig {
        CommitBoostConfig {
            chain: Chain::Hoodi,
            relays: vec![],
            pbs: StaticPbsConfig {
                docker_image: String::from("cb-fake-repo/fake-cb:latest"),
                pbs_config: PbsConfig {
                    host: Ipv4Addr::LOCALHOST,
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
                    validator_registration_batch_size: None,
                    mux_registry_refresh_interval_seconds: 5,
                    ssv_node_api_url: Url::parse("https://example.net").unwrap(),
                    ssv_public_api_url: Url::parse("https://example.net").unwrap(),
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

    // ── TlsMode serde ────────────────────────────────────────────────────────

    #[test]
    fn test_tls_mode_insecure_roundtrip() -> Result<()> {
        let original = TlsWrapper { tls_mode: TlsMode::Insecure };
        let toml_str = toml::to_string(&original)?;
        let parsed: TlsWrapper = toml::from_str(&toml_str)?;
        assert!(matches!(parsed.tls_mode, TlsMode::Insecure));
        Ok(())
    }

    #[test]
    fn test_tls_mode_certificate_roundtrip() -> Result<()> {
        let path = PathBuf::from("/certs");
        let original = TlsWrapper { tls_mode: TlsMode::Certificate(path.clone()) };
        let toml_str = toml::to_string(&original)?;
        let parsed: TlsWrapper = toml::from_str(&toml_str)?;
        match parsed.tls_mode {
            TlsMode::Certificate(p) => assert_eq!(p, path),
            TlsMode::Insecure => panic!("Expected Certificate variant"),
        }
        Ok(())
    }

    #[test]
    fn test_tls_mode_insecure_from_toml() -> Result<()> {
        let toml_str = r#"
            [tls_mode]
            type = "insecure"
        "#;
        let parsed: TlsWrapper = toml::from_str(toml_str)?;
        assert!(matches!(parsed.tls_mode, TlsMode::Insecure));
        Ok(())
    }

    #[test]
    fn test_tls_mode_certificate_from_toml() -> Result<()> {
        let toml_str = r#"
            [tls_mode]
            type = "certificate"
            path = "/custom/certs"
        "#;
        let parsed: TlsWrapper = toml::from_str(toml_str)?;
        match parsed.tls_mode {
            TlsMode::Certificate(p) => assert_eq!(p, PathBuf::from("/custom/certs")),
            TlsMode::Insecure => panic!("Expected Certificate variant"),
        }
        Ok(())
    }

    // ── signer_uses_tls ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_signer_uses_tls_no_signer() {
        let cfg = get_base_config().await;
        assert!(!cfg.signer_uses_tls());
    }

    #[tokio::test]
    async fn test_signer_uses_tls_insecure() {
        let cfg = get_config_with_signer(TlsMode::Insecure).await;
        assert!(!cfg.signer_uses_tls());
    }

    #[tokio::test]
    async fn test_signer_uses_tls_certificate() {
        let cfg = get_config_with_signer(TlsMode::Certificate(PathBuf::from("/certs"))).await;
        assert!(cfg.signer_uses_tls());
    }

    // ── signer_certs_path ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_signer_certs_path_no_signer() {
        let cfg = get_base_config().await;
        assert!(cfg.signer_certs_path().is_none());
    }

    #[tokio::test]
    async fn test_signer_certs_path_insecure() {
        let cfg = get_config_with_signer(TlsMode::Insecure).await;
        assert!(cfg.signer_certs_path().is_none());
    }

    #[tokio::test]
    async fn test_signer_certs_path_certificate() {
        let certs_path = PathBuf::from("/my/certs");
        let cfg = get_config_with_signer(TlsMode::Certificate(certs_path.clone())).await;
        assert_eq!(cfg.signer_certs_path(), Some(&certs_path));
    }

    // ── signer_server_url ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_signer_server_url_no_signer_uses_default_port() {
        let cfg = get_base_config().await;
        assert_eq!(cfg.signer_server_url(12345), "http://cb_signer:12345");
    }

    #[tokio::test]
    async fn test_signer_server_url_insecure_uses_http() {
        let cfg = get_config_with_signer(TlsMode::Insecure).await;
        assert_eq!(cfg.signer_server_url(9999), "http://cb_signer:20000");
    }

    #[tokio::test]
    async fn test_signer_server_url_certificate_uses_https() {
        let cfg = get_config_with_signer(TlsMode::Certificate(PathBuf::from("/certs"))).await;
        assert_eq!(cfg.signer_server_url(9999), "https://cb_signer:20000");
    }

    #[tokio::test]
    async fn test_signer_server_url_remote_returned_as_is() {
        let remote_url = Url::parse("https://remote-signer.example.com:8080").unwrap();
        let mut cfg = get_base_config().await;
        cfg.signer = Some(SignerConfig {
            host: Ipv4Addr::new(127, 0, 0, 1),
            port: 20000,
            docker_image: COMMIT_BOOST_IMAGE_DEFAULT.to_string(),
            jwt_auth_fail_limit: 3,
            jwt_auth_fail_timeout_seconds: 300,
            tls_mode: TlsMode::Insecure,
            reverse_proxy: ReverseProxyHeaderSetup::None,
            inner: SignerType::Remote { url: remote_url.clone() },
        });
        assert_eq!(cfg.signer_server_url(9999), remote_url.to_string());
    }

    // ── ReverseProxyHeaderSetup Display ──────────────────────────────────────

    #[test]
    fn test_reverse_proxy_display_none() {
        assert_eq!(ReverseProxyHeaderSetup::None.to_string(), "None");
    }

    #[test]
    fn test_reverse_proxy_display_unique() {
        let rp = ReverseProxyHeaderSetup::Unique { header: "X-Forwarded-For".to_string() };
        assert_eq!(rp.to_string(), r#""X-Forwarded-For (unique)""#);
    }

    #[test]
    fn test_reverse_proxy_display_rightmost_1st() {
        let rp = ReverseProxyHeaderSetup::Rightmost {
            header: "X-Real-IP".to_string(),
            trusted_count: NonZeroUsize::new(1).unwrap(),
        };
        assert_eq!(rp.to_string(), r#""X-Real-IP (1st from the right)""#);
    }

    #[test]
    fn test_reverse_proxy_display_rightmost_2nd() {
        let rp = ReverseProxyHeaderSetup::Rightmost {
            header: "X-Real-IP".to_string(),
            trusted_count: NonZeroUsize::new(2).unwrap(),
        };
        assert_eq!(rp.to_string(), r#""X-Real-IP (2nd from the right)""#);
    }

    #[test]
    fn test_reverse_proxy_display_rightmost_3rd() {
        let rp = ReverseProxyHeaderSetup::Rightmost {
            header: "X-Real-IP".to_string(),
            trusted_count: NonZeroUsize::new(3).unwrap(),
        };
        assert_eq!(rp.to_string(), r#""X-Real-IP (3rd from the right)""#);
    }

    #[test]
    fn test_reverse_proxy_display_rightmost_nth() {
        let rp = ReverseProxyHeaderSetup::Rightmost {
            header: "CF-Connecting-IP".to_string(),
            trusted_count: NonZeroUsize::new(5).unwrap(),
        };
        assert_eq!(rp.to_string(), r#""CF-Connecting-IP (5th from the right)""#);
    }
}
