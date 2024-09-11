use bimap::BiHashMap;
use eyre::Result;
use serde::{Deserialize, Serialize};

use super::{
    constants::{SIGNER_IMAGE_DEFAULT, SIGNER_SERVER_ENV},
    utils::{load_env_var, load_jwts},
    CommitBoostConfig,
};
use crate::{
    loader::SignerLoader,
    types::{Chain, Jwt, ModuleId},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignerConfig {
    /// Docker image of the module
    #[serde(default = "default_signer")]
    pub docker_image: String,
    /// Which keys to load
    pub loader: SignerLoader,
}

fn default_signer() -> String {
    SIGNER_IMAGE_DEFAULT.to_string()
}

#[derive(Debug)]
pub struct StartSignerConfig {
    pub chain: Chain,
    pub loader: SignerLoader,
    pub server_port: u16,
    pub jwts: BiHashMap<ModuleId, Jwt>,
}

impl StartSignerConfig {
    pub fn load_from_env() -> Result<Self> {
        let config = CommitBoostConfig::from_env_path()?;

        let jwts = load_jwts()?;
        let server_port = load_env_var(SIGNER_SERVER_ENV)?.parse()?;

        Ok(StartSignerConfig {
            chain: config.chain,
            loader: config.signer.expect("Signer config is missing").loader,
            server_port,
            jwts,
        })
    }
}
