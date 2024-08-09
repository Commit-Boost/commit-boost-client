use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{error::BlstErrorWrapper, signature::verify_signed_builder_message, types::Chain};

// TODO: might need to adapt the SignedProxyDelegation so that it goes through
// web3 signer
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ProxyDelegation {
    pub delegator: BlsPublicKey,
    pub proxy: BlsPublicKey,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SignedProxyDelegation {
    pub message: ProxyDelegation,
    /// Signature of message with the delegator keypair
    pub signature: BlsSignature,
}

impl SignedProxyDelegation {
    pub fn validate(&self, chain: Chain) -> Result<(), BlstErrorWrapper> {
        verify_signed_builder_message(
            chain,
            &self.message.delegator,
            &self.message,
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub pubkey: BlsPublicKey,
    pub is_proxy: bool,
    pub object_root: [u8; 32],
}

impl SignRequest {
    pub fn new(pubkey: BlsPublicKey, is_proxy: bool, object_root: [u8; 32]) -> SignRequest {
        Self { pubkey, is_proxy, object_root }
    }

    pub fn builder(pubkey: BlsPublicKey) -> Self {
        Self::new(pubkey, false, [0; 32])
    }

    pub fn is_proxy(self) -> Self {
        Self { is_proxy: true, ..self }
    }

    pub fn with_root(self, object_root: [u8; 32]) -> Self {
        Self { object_root, ..self }
    }

    pub fn with_msg(self, msg: &impl TreeHash) -> Self {
        self.with_root(msg.tree_hash_root().0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateProxyRequest {
    pub pubkey: BlsPublicKey,
}

impl GenerateProxyRequest {
    pub fn new(pubkey: BlsPublicKey) -> Self {
        GenerateProxyRequest { pubkey }
    }
}
