use std::path::PathBuf;

use bimap::BiHashMap;
use eyre::{bail, OptionExt, Result};
use serde::{Deserialize, Serialize};
use tonic::transport::{Certificate, Identity};
use url::Url;

use super::{
    constants::SIGNER_IMAGE_DEFAULT,
    utils::{load_env_var, load_jwts},
    CommitBoostConfig, SIGNER_PORT_ENV,
};
use crate::{
    config::{DIRK_CA_CERT_ENV, DIRK_CERT_ENV, DIRK_DIR_SECRETS_ENV, DIRK_KEY_ENV},
    signer::{ProxyStore, SignerLoader},
    types::{Chain, Jwt, ModuleId},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SignerConfig {
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
    /// Accounts used as consensus keys
    pub accounts: Vec<String>,
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
        /// Whether to unlock the accounts in case they are locked
        #[serde(default)]
        unlock: bool,
        /// How to store proxy keys
        store: Option<ProxyStore>,
    },
}

#[derive(Clone, Debug)]
pub struct DirkConfig {
    pub hosts: Vec<DirkHostConfig>,
    pub client_cert: Identity,
    pub secrets_path: PathBuf,
    pub cert_auth: Option<Certificate>,
    pub unlock: bool,
}

#[derive(Debug, Clone)]
pub struct StartSignerConfig {
    pub chain: Chain,
    pub loader: Option<SignerLoader>,
    pub store: Option<ProxyStore>,
    pub server_port: u16,
    pub jwts: BiHashMap<ModuleId, Jwt>,
    pub dirk: Option<DirkConfig>,
}

impl StartSignerConfig {
    pub fn load_from_env() -> Result<Self> {
        let config = CommitBoostConfig::from_env_path()?;

        let jwts = load_jwts()?;
        let server_port = load_env_var(SIGNER_PORT_ENV)?.parse()?;

        let signer = config.signer.ok_or_eyre("Signer config is missing")?.inner;

        match signer {
            SignerType::Local { loader, store, .. } => Ok(StartSignerConfig {
                chain: config.chain,
                loader: Some(loader),
                server_port,
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
                unlock,
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
                    server_port,
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
                        unlock,
                    }),
                })
            }

            SignerType::Remote { .. } => {
                bail!("Remote signer configured")
            }
        }
    }
}
