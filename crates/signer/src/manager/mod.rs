use cb_common::{commit::request::ConsensusProxyMap, types::ModuleId};
use dirk::DirkManager;
use local::LocalSigningManager;

use crate::error::SignerModuleError;

pub mod dirk;
pub mod local;

#[derive(Clone)]
pub enum SigningManager {
    Local(LocalSigningManager),
    Dirk(DirkManager),
}

impl SigningManager {
    /// Amount of consensus signers available
    pub async fn available_consensus_signers(&self) -> eyre::Result<usize> {
        match self {
            SigningManager::Local(local_manager) => Ok(local_manager.consensus_pubkeys().len()),
            SigningManager::Dirk(dirk_manager) => Ok(dirk_manager.consensus_pubkeys().await.len()),
        }
    }

    /// Amount of proxy signers available
    pub async fn available_proxy_signers(&self) -> eyre::Result<usize> {
        match self {
            SigningManager::Local(local_manager) => {
                let proxies = local_manager.proxies();
                Ok(proxies.bls_signers.len() + proxies.ecdsa_signers.len())
            }
            SigningManager::Dirk(dirk_manager) => Ok(dirk_manager.proxies().await.len()),
        }
    }

    pub async fn get_consensus_proxy_maps(
        &self,
        module_id: &ModuleId,
    ) -> Result<Vec<ConsensusProxyMap>, SignerModuleError> {
        match self {
            SigningManager::Local(local_manager) => {
                local_manager.get_consensus_proxy_maps(module_id)
            }
            SigningManager::Dirk(dirk_manager) => {
                Ok(dirk_manager.get_consensus_proxy_maps(module_id))
            }
        }
    }
}
