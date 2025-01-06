use std::path::PathBuf;

use bimap::BiHashMap;
use eyre::{bail, Result};
use serde::{Deserialize, Serialize};
use tonic::transport::{Certificate, Identity};
use tracing::info;
use url::Url;

use super::{
    constants::SIGNER_IMAGE_DEFAULT,
    utils::{load_env_var, load_jwts},
    CommitBoostConfig, SIGNER_PORT_ENV,
};
use crate::{
    config::{SIGNER_DIRK_CA_CERT_ENV, SIGNER_DIRK_CERT_ENV, SIGNER_DIRK_KEY_ENV},
    signer::{ProxyStore, SignerLoader},
    types::{Chain, Jwt, ModuleId},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SignerConfig {
    /// Local signer module
    Local {
        /// Docker image of the module
        #[serde(default = "default_signer")]
        docker_image: String,
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
    Dirk {
        /// Docker image of the module
        #[serde(default = "default_signer")]
        docker_image: String,
        /// Complete URL of a Dirk gateway
        url: Url,
        /// Path to the client certificate
        cert_path: PathBuf,
        /// Path to the client key
        key_path: PathBuf,
        /// Wallets to use. Each wallet should have a `wallet/consensus` account
        wallets: Vec<String>,
        /// Path to the CA certificate
        ca_cert_path: Option<PathBuf>,
        /// Domain name of the server to use in TLS verification
        server_domain: Option<String>,
    },
}

fn default_signer() -> String {
    SIGNER_IMAGE_DEFAULT.to_string()
}

#[derive(Clone, Debug)]
pub struct DirkConfig {
    pub url: Url,
    pub wallets: Vec<String>,
    pub client_cert: Identity,
    pub cert_auth: Option<Certificate>,
    pub server_domain: Option<String>,
}

#[derive(Debug)]
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
        info!("Loading from env");
        let config = CommitBoostConfig::from_env_path()?;

        let jwts = load_jwts()?;
        let server_port = load_env_var(SIGNER_PORT_ENV)?.parse()?;

        match config.signer {
            Some(SignerConfig::Local { loader, store, .. }) => Ok(StartSignerConfig {
                chain: config.chain,
                loader: Some(loader),
                server_port,
                jwts,
                store,
                dirk: None,
            }),
            Some(SignerConfig::Dirk {
                url,
                cert_path,
                key_path,
                wallets,
                ca_cert_path,
                server_domain,
                ..
            }) => {
                let cert_path =
                    load_env_var(SIGNER_DIRK_CERT_ENV).map(PathBuf::from).unwrap_or(cert_path);
                let key_path =
                    load_env_var(SIGNER_DIRK_KEY_ENV).map(PathBuf::from).unwrap_or(key_path);
                let ca_cert_path =
                    load_env_var(SIGNER_DIRK_CA_CERT_ENV).map(PathBuf::from).ok().or(ca_cert_path);

                Ok(StartSignerConfig {
                    chain: config.chain,
                    server_port,
                    jwts,
                    loader: None,
                    store: None,
                    dirk: Some(DirkConfig {
                        url,
                        wallets,
                        client_cert: Identity::from_pem(
                            std::fs::read_to_string(cert_path)?,
                            std::fs::read_to_string(key_path)?,
                        ),
                        cert_auth: match ca_cert_path {
                            Some(path) => {
                                Some(Certificate::from_pem(std::fs::read_to_string(path)?))
                            }
                            None => None,
                        },
                        server_domain,
                    }),
                })
            }
            Some(SignerConfig::Remote { .. }) => bail!("Remote signer configured"),
            None => bail!("Signer config is missing"),
        }
    }
}
