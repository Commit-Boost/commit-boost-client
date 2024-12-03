use bimap::BiHashMap;
use eyre::Result;
use serde::{Deserialize, Serialize};

use super::{
    constants::SIGNER_IMAGE_DEFAULT,
    utils::{load_env_var, load_jwts},
    CommitBoostConfig, SIGNER_PORT_ENV,
};
use crate::{
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
    /// Remote signer module with compatible API
    Remote {
        /// Complete url of the base API endpoint
        url: String,
    },
}

fn default_signer() -> String {
    SIGNER_IMAGE_DEFAULT.to_string()
}

#[derive(Debug)]
pub struct StartSignerConfig {
    pub chain: Chain,
    pub loader: SignerLoader,
    pub store: Option<ProxyStore>,
    pub server_port: u16,
    pub jwts: BiHashMap<ModuleId, Jwt>,
}

impl StartSignerConfig {
    pub fn load_from_env() -> Result<Self> {
        let config = CommitBoostConfig::from_env_path()?;

        let jwts = load_jwts()?;
        let server_port = load_env_var(SIGNER_PORT_ENV)?.parse()?;

        match config.signer {
            Some(SignerConfig::Local { loader, store, .. }) => {
                Ok(StartSignerConfig { chain: config.chain, loader, server_port, jwts, store })
            }
            Some(SignerConfig::Remote { .. }) => Err(eyre::eyre!("Remote signer configured")),
            None => Err(eyre::eyre!("Signer config is missing")),
        }
    }
}
