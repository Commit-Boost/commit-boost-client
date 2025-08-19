use alloy::{
    primitives::{Address, B256},
    rpc::types::beacon::BlsSignature,
};
use serde::{Deserialize, Serialize};

use crate::signer::{BlsPublicKey, EcdsaSignature};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlsSignResponse {
    pub pubkey: BlsPublicKey,
    pub object_root: B256,
    pub module_signing_id: B256,
    pub signature: BlsSignature,
}

impl BlsSignResponse {
    pub fn new(
        pubkey: BlsPublicKey,
        object_root: B256,
        module_signing_id: B256,
        signature: BlsSignature,
    ) -> Self {
        Self { pubkey, object_root, module_signing_id, signature }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcdsaSignResponse {
    pub address: Address,
    pub object_root: B256,
    pub module_signing_id: B256,
    pub signature: EcdsaSignature,
}

impl EcdsaSignResponse {
    pub fn new(
        address: Address,
        object_root: B256,
        module_signing_id: B256,
        signature: EcdsaSignature,
    ) -> Self {
        Self { address, object_root, module_signing_id, signature }
    }
}
