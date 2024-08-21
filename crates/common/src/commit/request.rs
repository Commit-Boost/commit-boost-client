use std::fmt;

use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    error::BlstErrorWrapper, signature::verify_signed_builder_message, signer::{schemes::ecdsa::EcdsaPublicKey, GenericPubkey},
    types::Chain,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ProxyDelegation {
    pub delegator: BlsPublicKey,
    pub proxy: GenericPubkey,
}

impl fmt::Display for ProxyDelegation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Delegator: {}\nProxy: {}", self.delegator, self.proxy)
    }
}

// TODO: might need to adapt the SignedProxyDelegation so that it goes through
// web3 signer
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

impl fmt::Display for SignedProxyDelegation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\nSignature: {}", self.message, self.signature)
    }
}

// TODO(David): This struct shouldn't be visible in the client SDK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignRequest {
    Consensus(SignConsensusRequest),
    Proxy(SignProxyRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignConsensusRequest {
    pub pubkey: BlsPublicKey,
    pub object_root: [u8; 32],
}

impl SignConsensusRequest {
    pub fn new(pubkey: BlsPublicKey, object_root: [u8; 32]) -> Self {
        Self { pubkey, object_root }
    }

    pub fn builder(pubkey: BlsPublicKey) -> Self {
        Self::new(pubkey, [0; 32])
    }

    pub fn with_root(self, object_root: [u8; 32]) -> Self {
        Self { object_root, ..self }
    }

    pub fn with_msg(self, msg: &impl TreeHash) -> Self {
        self.with_root(msg.tree_hash_root().0)
    }
}

//TODO(David): Shouldn't be visible from the client SDK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignProxyRequest {
    pub pubkey: GenericPubkey,
    pub object_root: [u8; 32],
}

impl SignProxyRequest {
    pub fn new(pubkey: GenericPubkey, object_root: [u8; 32]) -> Self {
        Self { pubkey, object_root }
    }

    pub fn builder(pubkey: GenericPubkey) -> Self {
        Self::new(pubkey, [0; 32])
    }

    pub fn with_root(self, object_root: [u8; 32]) -> Self {
        Self { object_root, ..self }
    }

    pub fn with_msg(self, msg: &impl TreeHash) -> Self {
        self.with_root(msg.tree_hash_root().0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignProxyEcdsaRequest {
    pub pubkey: EcdsaPublicKey,
    pub object_root: [u8; 32],
}

impl SignProxyEcdsaRequest {
    pub fn new(pubkey: EcdsaPublicKey, object_root: [u8; 32]) -> Self {
        Self { pubkey, object_root }
    }

    pub fn builder(pubkey: EcdsaPublicKey) -> Self {
        Self::new(pubkey, [0; 32])
    }

    pub fn with_root(self, object_root: [u8; 32]) -> Self {
        Self { object_root, ..self }
    }

    pub fn with_msg(self, msg: &impl TreeHash) -> Self {
        self.with_root(msg.tree_hash_root().0)
    }
}

impl From<SignProxyEcdsaRequest> for SignProxyRequest {
    fn from(value: SignProxyEcdsaRequest) -> Self {
        Self { pubkey: GenericPubkey::Ecdsa(value.pubkey), object_root: value.object_root }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignProxyBlsRequest {
    pub pubkey: BlsPublicKey,
    pub object_root: [u8; 32],
}

impl SignProxyBlsRequest {
    pub fn new(pubkey: BlsPublicKey, object_root: [u8; 32]) -> Self {
        Self { pubkey, object_root }
    }

    pub fn builder(pubkey: BlsPublicKey) -> Self {
        Self::new(pubkey, [0; 32])
    }

    pub fn with_root(self, object_root: [u8; 32]) -> Self {
        Self { object_root, ..self }
    }

    pub fn with_msg(self, msg: &impl TreeHash) -> Self {
        self.with_root(msg.tree_hash_root().0)
    }
}

impl From<SignProxyBlsRequest> for SignProxyRequest {
    fn from(value: SignProxyBlsRequest) -> Self {
        Self { pubkey: GenericPubkey::Bls(value.pubkey), object_root: value.object_root }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EncryptionScheme {
    #[serde(rename = "bls")]
    Bls,
    #[serde(rename = "ecdsa")]
    Ecdsa,
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
