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
    pub fn available_consensus_signers(&self) -> usize {
        match self {
            SigningManager::Local(local_manager) => local_manager.consensus_pubkeys().len(),
            SigningManager::Dirk(dirk_manager) => dirk_manager.available_consensus_signers(),
        }
    }

    /// Amount of proxy signers available
    pub fn available_proxy_signers(&self) -> usize {
        match self {
            SigningManager::Local(local_manager) => local_manager.available_proxy_signers(),
            SigningManager::Dirk(dirk_manager) => dirk_manager.available_proxy_signers(),
        }
    }

    pub fn get_consensus_proxy_maps(
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
