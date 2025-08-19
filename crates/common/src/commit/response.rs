use alloy::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

use crate::{
    signer::EcdsaSignature,
    types::{BlsPublicKey, BlsSignature},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlsSignResponse {
    pub pubkey: BlsPublicKey,
    pub object_root: B256,
    pub module_signing_id: B256,
    pub nonce: u64,
    pub chain_id: U256,
    pub signature: BlsSignature,
}

impl BlsSignResponse {
    pub fn new(
        pubkey: BlsPublicKey,
        object_root: B256,
        module_signing_id: B256,
        nonce: u64,
        chain_id: U256,
        signature: BlsSignature,
    ) -> Self {
        Self { pubkey, object_root, module_signing_id, nonce, chain_id, signature }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcdsaSignResponse {
    pub address: Address,
    pub object_root: B256,
    pub module_signing_id: B256,
    pub nonce: u64,
    pub chain_id: U256,
    pub signature: EcdsaSignature,
}

impl EcdsaSignResponse {
    pub fn new(
        address: Address,
        object_root: B256,
        module_signing_id: B256,
        nonce: u64,
        chain_id: U256,
        signature: EcdsaSignature,
    ) -> Self {
        Self { address, object_root, module_signing_id, nonce, chain_id, signature }
    }
}
