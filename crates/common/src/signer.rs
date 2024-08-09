use std::{any::Any, error::Error};

use alloy::{primitives::FixedBytes, rpc::types::beacon::{BlsPublicKey, BlsSignature}};
use blst::min_pk::{PublicKey, SecretKey as BlsSecretKey};
use derive_more::derive::{Deref, From};
use eyre::{Context, Result};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    commit::request::SignedProxyDelegation, error::BlstErrorWrapper, signature::{random_secret, sign_builder_message, sign_builder_root, sign_message, verify_signature}, types::Chain, utils::blst_pubkey_to_alloy
};

pub trait SecretKey {
    type PubKey: AsRef<[u8]> + Clone;
    type Signature: AsRef<[u8]> + Clone;
    type VerificationError: Error;

    fn new_random() -> Self;
    fn new_from_bytes(bytes: &[u8]) -> Result<Self> where Self: Sized;
    fn pubkey(&self) -> Self::PubKey;
    fn sign(&self, msg: &[u8; 32]) -> Self::Signature;
    fn sign_msg(&self, msg: &impl TreeHash) -> Self::Signature {
        self.sign(&msg.tree_hash_root().0)
    }

    fn verify_signature(pubkey: &Self::PubKey, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::VerificationError>;

    // UTILITY METHODS
    fn to_generic_pubkey(pubkey: Self::PubKey) -> GenericPubkey;
    fn to_generic_proxy_signer(proxy_signer: ProxySigner<Self>) -> GenericProxySigner where Self: Sized;
}

impl SecretKey for BlsSecretKey {
    type PubKey = BlsPublicKey;
    type Signature = BlsSignature;
    type VerificationError = BlstErrorWrapper;

    fn new_random() -> Self {
        random_secret()
    }

    fn new_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(BlsSecretKey::from_bytes(bytes).map_err(BlstErrorWrapper::from)?)
    }

    fn pubkey(&self) -> Self::PubKey {
        blst_pubkey_to_alloy(&self.sk_to_pk())
    }

    fn sign(&self, msg: &[u8; 32]) -> Self::Signature {
        sign_message(self, msg)
    }

    fn verify_signature(
        pubkey: &Self::PubKey,
        msg: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::VerificationError> {
        verify_signature(pubkey, msg, signature)
    }

    // UTILITY METHODS
    fn to_generic_pubkey(pubkey: Self::PubKey) -> GenericPubkey {
        GenericPubkey::Bls(pubkey)
    }

    fn to_generic_proxy_signer(proxy_signer: ProxySigner<Self>) -> GenericProxySigner where Self: Sized {
        GenericProxySigner::Bls(proxy_signer)
    }
}

#[derive(Clone)]
pub enum Signer<T: SecretKey = BlsSecretKey> {
    Local(T),
}

impl<T: SecretKey> Signer<T> {
    pub fn new_random() -> Self {
        Signer::Local(T::new_random())
    }

    pub fn new_from_bytes(bytes: &[u8]) -> Result<Self> {
        T::new_from_bytes(bytes).map(Self::Local)
    }

    pub fn pubkey(&self) -> T::PubKey {
        match self {
            Signer::Local(secret) => secret.pubkey(),
        }
    }

    pub async fn sign(&self, chain: Chain, object_root: [u8; 32]) -> T::Signature {
        match self {
            Signer::Local(sk) => sign_builder_root(chain, sk, object_root),
        }
    }

    pub async fn sign_msg(&self, chain: Chain, msg: &impl TreeHash) -> T::Signature {
        self.sign(chain, msg.tree_hash_root().0).await
    }

    pub async fn verify_signature(
        pubkey: &T::PubKey,
        msg: &[u8],
        signature: &T::Signature,
    ) -> Result<(), T::VerificationError> {
        T::verify_signature(pubkey, msg, signature)
    }
}

// #[derive(Clone)]
// #[non_exhaustive]
// pub enum GenericSigner { // TODO: Name better
//     Bls(Signer<BlsSecretKey>),
//     // Ecdsa(Signer<EcdsaSecretKey>), // TODO: Add ecdsa
// }

// impl GenericSigner {
//     pub fn pubkey(&self) -> Vec<u8> {
//         match self {
//             GenericSigner::Bls(bls_signer) => bls_signer.pubkey().to_vec(),
//         }
//     }

//     pub async fn sign(&self, chain: Chain, object_root: [u8; 32]) -> Vec<u8> {
//         match self {
//             GenericSigner::Bls(bls_signer) => bls_signer.sign(chain, object_root).await.to_vec(),
//         }
//     }

//     pub async fn sign_msg(&self, chain: Chain, msg: &impl TreeHash) -> Vec<u8> {
//         self.sign(chain, msg.tree_hash_root().0).await
//     }
// }


// For extra safety and to avoid risking signing malicious messages, use a proxy
// setup: proposer creates a new ephemeral keypair which will be used to sign
// commit messages, it also signs a ProxyDelegation associating the new keypair
// with its consensus pubkey When a new commit module starts, pass the
// ProxyDelegation msg and then sign all future commit messages with the proxy
// key for slashing the faulty message + proxy delegation can be used
// Signed using builder domain

#[derive(Clone, Deref)]
pub struct ProxySigner<T: SecretKey> {
    #[deref]
    signer: Signer<T>,
    delegation: SignedProxyDelegation,
}

impl<T: SecretKey> ProxySigner<T> {
    pub fn new(signer: Signer<T>, delegation: SignedProxyDelegation) -> Self {
        Self { signer, delegation }
    }
}

#[derive(From)]
#[non_exhaustive]
pub enum GenericProxySigner {
    Bls(ProxySigner<BlsSecretKey>)
}

impl GenericProxySigner {
    pub fn pubkey(&self) -> /*Vec<u8>*/ GenericPubkey {
        match self {
            GenericProxySigner::Bls(proxy_signer) => GenericPubkey::Bls(proxy_signer.pubkey()),
        }
    }

    pub async fn sign(&self, chain: Chain, object_root: [u8; 32]) -> Vec<u8> {
        match self {
            GenericProxySigner::Bls(proxy_signer) => proxy_signer.sign(chain, object_root).await.to_vec(),
        }
    }

    pub fn delegation(&self) -> SignedProxyDelegation {
        match self {
            GenericProxySigner::Bls(proxy_signer) => proxy_signer.delegation,
        }
    }

    pub async fn verify_signature(
        &self,
        msg: &[u8],
        signature: &[u8],
    ) -> eyre::Result<()> {
        self.pubkey().verify_signature(msg, signature)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[non_exhaustive]
pub enum GenericPubkey {
    Bls(<BlsSecretKey as SecretKey>::PubKey)
}

impl GenericPubkey {
    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> eyre::Result<()> {
        match self {
            GenericPubkey::Bls(bls_pubkey) => {
                Ok(<BlsSecretKey as SecretKey>::verify_signature(bls_pubkey, msg, signature.try_into().context("Invalid signature length for BLS.")?)?)
            },
        }
    }
}

impl AsRef<[u8]> for GenericPubkey {
    fn as_ref(&self) -> &[u8] {
        match self {
            GenericPubkey::Bls(bls_pubkey) => bls_pubkey.as_ref(),
        }
    }
}


impl tree_hash::TreeHash for GenericPubkey {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unimplemented!("Enum should never be packed")
    }

    fn tree_hash_packing_factor() -> usize {
        unimplemented!("Enum should never be packed")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        match self {
            GenericPubkey::Bls(ref inner) => inner.tree_hash_root(),
        }
    }
}
