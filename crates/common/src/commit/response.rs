use std::{fmt, fmt::Display};

use alloy::{
    hex,
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

impl Display for BlsSignResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BLS Signature(pubkey: {}, object_root: {}, module_id: {}, signature: {})",
            self.pubkey,
            hex::encode_prefixed(self.object_root),
            self.module_signing_id,
            hex::encode_prefixed(self.signature)
        )
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

impl Display for EcdsaSignResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ECDSA Signature(address: {}, object_root: {}, module_id: {}, signature: 0x{})",
            self.address,
            hex::encode_prefixed(self.object_root),
            self.module_signing_id,
            self.signature
        )
    }
}
