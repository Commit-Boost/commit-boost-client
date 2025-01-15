use std::{
    fmt::{self, Debug, Display, LowerHex},
    str::FromStr,
};

use alloy::{hex, rpc::types::beacon::BlsSignature};
use derive_more::derive::From;
use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    constants::COMMIT_BOOST_DOMAIN,
    error::BlstErrorWrapper,
    signature::verify_signed_message,
    signer::{BlsPublicKey, EcdsaPublicKey},
    types::Chain,
};

pub trait PublicKey: AsRef<[u8]> + Debug + Clone + Copy + TreeHash + Display + LowerHex {}

impl PublicKey for EcdsaPublicKey {}

impl PublicKey for BlsPublicKey {}

// GENERIC PROXY DELEGATION
#[derive(Debug, Clone, Copy, Serialize, Deserialize, TreeHash)]
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
        verify_signed_message(
            chain,
            &self.message.delegator,
            &self.message,
            &self.signature,
            COMMIT_BOOST_DOMAIN,
        )
    }
}

impl<T: PublicKey> fmt::Display for SignedProxyDelegation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\nSignature: {}", self.message, self.signature)
    }
}

// TODO(David): This struct shouldn't be visible to module authors
#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignRequest {
    Consensus(SignConsensusRequest),
    ProxyBls(SignProxyRequest<BlsPublicKey>),
    ProxyEcdsa(SignProxyRequest<EcdsaPublicKey>),
}

impl Display for SignRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignRequest::Consensus(req) => write!(
                f,
                "Consensus(pubkey: {}, object_root: {})",
                req.pubkey,
                hex::encode(req.object_root)
            ),
            SignRequest::ProxyBls(req) => write!(
                f,
                "BLS(pubkey: {}, object_root: {})",
                req.pubkey,
                hex::encode(req.object_root)
            ),
            SignRequest::ProxyEcdsa(req) => write!(
                f,
                "ECDSA(pubkey: {}, object_root: {})",
                req.pubkey,
                hex::encode(req.object_root)
            ),
        }
    }
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EncryptionScheme {
    #[serde(rename = "bls")]
    Bls,
    #[serde(rename = "ecdsa")]
    Ecdsa,
}

impl Display for EncryptionScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionScheme::Bls => write!(f, "bls"),
            EncryptionScheme::Ecdsa => write!(f, "ecdsa"),
        }
    }
}

impl FromStr for EncryptionScheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bls" => Ok(EncryptionScheme::Bls),
            "ecdsa" => Ok(EncryptionScheme::Ecdsa),
            _ => Err(format!("Unknown scheme: {s}")),
        }
    }
}

// TODO(David): This struct shouldn't be visible to module authors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateProxyRequest {
    #[serde(rename = "pubkey")]
    pub consensus_pubkey: BlsPublicKey,
    pub scheme: EncryptionScheme,
}

impl GenerateProxyRequest {
    pub fn new(consensus_pubkey: BlsPublicKey, scheme: EncryptionScheme) -> Self {
        GenerateProxyRequest { consensus_pubkey, scheme }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetPubkeysResponse {
    pub keys: Vec<ConsensusProxyMap>,
}

/// Map of consensus pubkeys to proxies
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConsensusProxyMap {
    pub consensus: BlsPublicKey,
    pub proxy_bls: Vec<BlsPublicKey>,
    pub proxy_ecdsa: Vec<EcdsaPublicKey>,
}

impl ConsensusProxyMap {
    pub fn new(consensus: BlsPublicKey) -> Self {
        Self { consensus, proxy_bls: vec![], proxy_ecdsa: vec![] }
    }
}
