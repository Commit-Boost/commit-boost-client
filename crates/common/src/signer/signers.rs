use derive_more::derive::{Deref, From};
use eyre::Result;
use tree_hash::TreeHash;

use super::{
    schemes::{bls::BlsSecretKey, ecdsa::EcdsaSecretKey},
    GenericPubkey, SecretKey,
};
use crate::{commit::request::SignedProxyDelegation, signature::sign_builder_root, types::Chain};

// TODO(David): remove the default type arg
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
}

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
pub enum GenericProxySigner {
    Bls(ProxySigner<BlsSecretKey>),
    Ecdsa(ProxySigner<EcdsaSecretKey>),
}

impl GenericProxySigner {
    pub fn pubkey(&self) -> GenericPubkey {
        match self {
            GenericProxySigner::Bls(proxy_signer) => GenericPubkey::Bls(proxy_signer.pubkey()),
            GenericProxySigner::Ecdsa(proxy_signer) => GenericPubkey::Ecdsa(proxy_signer.pubkey()),
        }
    }

    pub fn delegation(&self) -> SignedProxyDelegation {
        match self {
            GenericProxySigner::Bls(proxy_signer) => proxy_signer.delegation,
            GenericProxySigner::Ecdsa(proxy_signer) => proxy_signer.delegation,
        }
    }

    pub async fn sign(&self, chain: Chain, object_root: [u8; 32]) -> Vec<u8> {
        match self {
            GenericProxySigner::Bls(proxy_signer) => {
                proxy_signer.sign(chain, object_root).await.to_vec()
            }
            GenericProxySigner::Ecdsa(proxy_signer) => {
                proxy_signer.sign(chain, object_root).await.encoded.to_vec()
            }
        }
    }

    pub async fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> eyre::Result<()> {
        self.pubkey().verify_signature(msg, signature)
    }
}
