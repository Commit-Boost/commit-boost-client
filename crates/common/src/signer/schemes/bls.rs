use alloy::primitives::B256;
use tree_hash::TreeHash;

use crate::{
    signature::sign_commit_boost_root,
    types::{BlsPublicKey, BlsSecretKey, BlsSignature, Chain},
};

#[derive(Clone)]
pub enum BlsSigner {
    Local(BlsSecretKey),
}

impl BlsSigner {
    pub fn new_random() -> Self {
        Self::Local(random_secret())
    }

    pub fn new_from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
        let secret =
            BlsSecretKey::deserialize(bytes).map_err(|_| eyre::eyre!("invalid secret key"))?;
        Ok(Self::Local(secret))
    }

    pub fn pubkey(&self) -> BlsPublicKey {
        match self {
            BlsSigner::Local(secret) => secret.public_key(),
        }
    }

    pub fn secret(&self) -> [u8; 32] {
        match self {
            BlsSigner::Local(secret) => secret.serialize().as_bytes().try_into().unwrap(),
        }
    }

    pub async fn sign(&self, chain: Chain, object_root: B256) -> BlsSignature {
        match self {
            BlsSigner::Local(sk) => sign_commit_boost_root(chain, sk, object_root),
        }
    }

    pub async fn sign_msg(&self, chain: Chain, msg: &impl TreeHash) -> BlsSignature {
        self.sign(chain, msg.tree_hash_root()).await
    }
}

pub fn random_secret() -> BlsSecretKey {
    BlsSecretKey::random()
}

pub fn verify_bls_signature(pubkey: &BlsPublicKey, msg: B256, signature: &BlsSignature) -> bool {
    signature.verify(pubkey, msg)
}
