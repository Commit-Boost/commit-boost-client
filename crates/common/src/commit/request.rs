use std::fmt::{self, Debug, Display, LowerHex};

use alloy::rpc::types::beacon::BlsSignature;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    error::BlstErrorWrapper,
    signature::verify_signed_builder_message,
    signer::schemes::{bls::BlsPublicKey, ecdsa::EcdsaPublicKey},
    types::Chain,
};

pub trait PublicKey:
    AsRef<[u8]> + Debug + Clone + Copy + Encode + Decode + TreeHash + Display + LowerHex
{
}

impl PublicKey for EcdsaPublicKey {}

impl PublicKey for BlsPublicKey {}

// GENERIC PROXY DELEGATION
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ProxyDelegation<T: PublicKey> {
    pub delegator: BlsPublicKey,
    pub proxy: T,
}

pub type ProxyDelegationBls = ProxyDelegation<BlsPublicKey>;
pub type ProxyDelegationEcdsa = ProxyDelegation<EcdsaPublicKey>;

impl<T: PublicKey> fmt::Display for ProxyDelegation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Delegator: {}\nProxy: {}", self.delegator, self.proxy)
    }
}

// TODO: might need to adapt the SignedProxyDelegation so that it goes through
// web3 signer
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SignedProxyDelegation<T: PublicKey> {
    pub message: ProxyDelegation<T>,
    /// Signature of message with the delegator keypair
    pub signature: BlsSignature,
}

pub type SignedProxyDelegationBls = SignedProxyDelegation<BlsPublicKey>;
pub type SignedProxyDelegationEcdsa = SignedProxyDelegation<EcdsaPublicKey>;

impl<T: PublicKey> SignedProxyDelegation<T> {
    pub fn validate(&self, chain: Chain) -> Result<(), BlstErrorWrapper> {
        verify_signed_builder_message(
            chain,
            &self.message.delegator,
            &self.message,
            &self.signature,
        )
    }
}

impl<T: PublicKey> fmt::Display for SignedProxyDelegation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\nSignature: {}", self.message, self.signature)
    }
}

// TODO(David): This struct shouldn't be visible in the client SDK
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignRequest {
    Consensus(SignConsensusRequest),
    ProxyBls(SignProxyRequest<BlsPublicKey>),
    ProxyEcdsa(SignProxyRequest<EcdsaPublicKey>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignConsensusRequest {
    pub pubkey: BlsPublicKey,
    #[serde(with = "alloy::hex::serde")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignProxyRequest<T: PublicKey> {
    pub pubkey: T,
    #[serde(with = "alloy::hex::serde")]
    pub object_root: [u8; 32],
}

impl<T: PublicKey> SignProxyRequest<T> {
    pub fn new(pubkey: T, object_root: [u8; 32]) -> Self {
        Self { pubkey, object_root }
    }

    pub fn builder(pubkey: T) -> Self {
        Self::new(pubkey, [0; 32])
    }

    pub fn with_root(self, object_root: [u8; 32]) -> Self {
        Self { object_root, ..self }
    }

    pub fn with_msg(self, msg: &impl TreeHash) -> Self {
        self.with_root(msg.tree_hash_root().0)
    }
}

impl From<SignProxyRequest<EcdsaPublicKey>> for SignRequest {
    fn from(value: SignProxyRequest<EcdsaPublicKey>) -> Self {
        Self::ProxyEcdsa(value)
    }
}
impl From<SignProxyRequest<BlsPublicKey>> for SignRequest {
    fn from(value: SignProxyRequest<BlsPublicKey>) -> Self {
        Self::ProxyBls(value)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EncryptionScheme {
    #[serde(rename = "bls")]
    Bls,
    #[serde(rename = "ecdsa")]
    Ecdsa,
}

// TODO(David): This struct shouldn't be visible in the client SDK
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
