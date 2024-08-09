use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{error::BlstErrorWrapper, signature::verify_signed_builder_message, signer::GenericPubkey, types::Chain};

// TODO: might need to adapt the SignedProxyDelegation so that it goes through
// web3 signer
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ProxyDelegation {
    pub delegator: BlsPublicKey,
    pub proxy: GenericPubkey,
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

// TODO(David): Consider splitting `SignRequest` into two: ConsensusSignRequest and ProxySignRequest
//  for better type safety (avoid the Vec<u8> generalisation) and avoid the is_proxy flag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub pubkey: Vec<u8>, // TODO(David): Vec<u8> might not be the most memory inefficient, think about something on the stack
    pub is_proxy: bool,
    pub object_root: [u8; 32],
}

impl SignRequest {
    pub fn new(
        pubkey: Vec<u8>,
        is_proxy: bool,
        object_root: [u8; 32],
    ) -> SignRequest {
        Self { pubkey, is_proxy, object_root }
    }

    pub fn builder(pubkey: Vec<u8>) -> Self {
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
    pub consensus_pubkey: BlsPublicKey,
    pub scheme: EncryptionScheme,
}

impl GenerateProxyRequest {
    pub fn new(consensus_pubkey: BlsPublicKey, scheme: EncryptionScheme) -> Self {
        GenerateProxyRequest { consensus_pubkey, scheme }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EncryptionScheme {
    Bls,
    Ecdsa,
}
