use eyre::Result;
use tree_hash::TreeHash;

use super::{BlsSecretKey, SecretKey};
use crate::{signature::sign_builder_root, types::Chain};

pub type ConsensusSigner = Signer<BlsSecretKey>;

#[derive(Clone)]
pub enum Signer<T: SecretKey> {
    Local(T),
}

impl<T: SecretKey> Signer<T> {
    pub fn new_random() -> Self {
        Signer::Local(T::new_random())
    }

    pub fn new_from_bytes(bytes: &[u8]) -> Result<Self> {
        T::new_from_bytes(bytes).map(Self::Local)
    }

    pub fn pubkey(&self) -> T::PublicKey {
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
