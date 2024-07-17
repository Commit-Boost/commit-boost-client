use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
use blst::min_pk::SecretKey;
use tree_hash::TreeHash;

use crate::{
    signature::{random_secret, sign_builder_message},
    types::Chain,
    utils::blst_pubkey_to_alloy,
};

#[derive(Clone)]
pub enum Signer {
    Local(SecretKey),
}

impl Signer {
    pub fn new_random() -> Self {
        Signer::Local(random_secret())
    }

    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let secret_key = SecretKey::from_bytes(bytes).unwrap();
        Self::Local(secret_key)
    }

    pub fn pubkey(&self) -> BlsPublicKey {
        match self {
            Signer::Local(secret) => blst_pubkey_to_alloy(&secret.sk_to_pk()),
        }
    }

    pub async fn sign(&self, chain: Chain, object_root: &[u8; 32]) -> BlsSignature {
        match self {
            Signer::Local(sk) => sign_builder_message(chain, sk, object_root),
        }
    }

    pub async fn sign_msg(&self, chain: Chain, msg: &impl TreeHash) -> BlsSignature {
        match self {
            Signer::Local(sk) => {
                let object_root = msg.tree_hash_root();
                sign_builder_message(chain, sk, &object_root.0)
            }
        }
    }
}
