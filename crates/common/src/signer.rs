use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use blst::min_pk::SecretKey;

use crate::{ObjectTreeHash, signature::{random_secret, sign_builder_message}, types::Chain, utils::blst_pubkey_to_alloy};

pub enum Signer {
    Plain(SecretKey),
}

impl Signer {
    pub fn new_random() -> Self {
        Signer::Plain(random_secret())
    }

    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let secret_key = SecretKey::from_bytes(bytes).unwrap();
        Self::Plain(secret_key)
    }

    pub fn pubkey(&self) -> BlsPublicKey {
        match self {
            Signer::Plain(secret) => blst_pubkey_to_alloy(&secret.sk_to_pk()),
        }
    }

    pub async fn sign(&self, chain: Chain, object_root: &[u8; 32]) -> BlsSignature {
        match self {
            Signer::Plain(sk) => sign_builder_message(chain, sk, object_root),
        }
    }

    pub async fn sign_msg(&self, chain: Chain, msg: &impl ObjectTreeHash) -> BlsSignature {
        match self {
            Signer::Plain(sk) => {
                let object_root = msg.tree_hash();
                sign_builder_message(chain, sk, &object_root.0)
            },
        }
    }
}
