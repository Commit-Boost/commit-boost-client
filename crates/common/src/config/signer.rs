use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use eyre::{bail, OptionExt, Result};
use serde::{Deserialize, Serialize};
use tonic::transport::{Certificate, Identity};
use url::Url;

use super::{
    load_jwt_secrets, load_optional_env_var, utils::load_env_var, CommitBoostConfig,
    SIGNER_ENDPOINT_ENV, SIGNER_IMAGE_DEFAULT,
};
use crate::{
    config::{DIRK_CA_CERT_ENV, DIRK_CERT_ENV, DIRK_DIR_SECRETS_ENV, DIRK_KEY_ENV},
    signer::{ProxyStore, SignerLoader, DEFAULT_SIGNER_PORT},
    types::{Chain, ModuleId},
    utils::{default_host, default_u16},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SignerConfig {
    /// Host address to listen for signer API calls on
    #[serde(default = "default_host")]
    pub host: Ipv4Addr,
    /// Port to listen for signer API calls on
    #[serde(default = "default_u16::<DEFAULT_SIGNER_PORT>")]
    pub port: u16,
    /// Docker image of the module
    #[serde(default = "default_signer")]
    pub docker_image: String,
    /// Inner type-specific configuration
    #[serde(flatten)]
    pub inner: SignerType,
}

fn default_signer() -> String {
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
    pub jwts: HashMap<ModuleId, String>,
    pub dirk: Option<DirkConfig>,
}

impl StartSignerConfig {
    pub fn load_from_env() -> Result<Self> {
        let config = CommitBoostConfig::from_env_path()?;

        let jwts = load_jwt_secrets()?;

        let signer_config = config.signer.ok_or_eyre("Signer config is missing")?;

        // Load the server endpoint first from the env var if present, otherwise the
        // config
        let endpoint = if let Some(endpoint) = load_optional_env_var(SIGNER_ENDPOINT_ENV) {
            endpoint.parse()?
        } else {
            SocketAddr::from((signer_config.host, signer_config.port))
        };

        match signer_config.inner {
            SignerType::Local { loader, store, .. } => Ok(StartSignerConfig {
                chain: config.chain,
                loader: Some(loader),
                endpoint,
                jwts,
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
                    jwts,
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
