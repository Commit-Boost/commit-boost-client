use alloy::rpc::types::beacon::{
    constants::BLS_DST_SIG, BlsPublicKey as BlsPublicKeyInner, BlsSignature,
};
use blst::BLST_ERROR;
use derive_more::derive::{Deref, Display, From, Into, LowerHex};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    error::BlstErrorWrapper, signature::sign_builder_root, signer::GenericPubkey, types::Chain,
    utils::blst_pubkey_to_alloy,
};

pub type BlsSecretKey = blst::min_pk::SecretKey;

// std traits
#[derive(Debug, Clone, Copy, LowerHex, Display, PartialEq, Eq, Hash)]
// serde, ssz, tree_hash
#[derive(Serialize, Deserialize, Encode, Decode, TreeHash)]
#[ssz(struct_behaviour = "transparent")]
// derive_more
#[derive(Deref, From, Into)]
pub struct BlsPublicKey {
    inner: BlsPublicKeyInner,
}

impl AsRef<[u8]> for BlsPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Clone)]
pub enum BlsSigner {
    Local(BlsSecretKey),
}

impl BlsSigner {
    pub fn new_random() -> Self {
        Self::Local(random_secret())
    }

    pub fn new_from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
        let secret = BlsSecretKey::from_bytes(bytes).map_err(BlstErrorWrapper::from)?;
        Ok(Self::Local(secret))
    }

    pub fn pubkey(&self) -> BlsPublicKey {
        match self {
            BlsSigner::Local(secret) => blst_pubkey_to_alloy(&secret.sk_to_pk()).into(),
        }
    }

    pub async fn sign(&self, chain: Chain, object_root: [u8; 32]) -> BlsSignature {
        match self {
            BlsSigner::Local(sk) => sign_builder_root(chain, sk, object_root),
        }
    }

    pub async fn sign_msg(&self, chain: Chain, msg: &impl TreeHash) -> BlsSignature {
        self.sign(chain, msg.tree_hash_root().0).await
    }
}

fn random_secret() -> BlsSecretKey {
    use rand::RngCore;

    let mut rng = rand::thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    match BlsSecretKey::key_gen(&ikm, &[]) {
        Ok(key) => key,
        // Key material is always valid (32 `u8`s), so `key_gen` can't return Err.
        Err(_) => unreachable!(),
    }
}

// TODO(David): Refine the boundaries between our wrapper `BlsPublicKey` type
// and alloy's `BlsPublicKey`. This stinks right now...
pub fn verify_bls_signature(
    pubkey: &BlsPublicKeyInner,
    msg: &[u8],
    signature: &BlsSignature,
) -> Result<(), BlstErrorWrapper> {
    use crate::utils::{alloy_pubkey_to_blst, alloy_sig_to_blst};

    let pubkey = alloy_pubkey_to_blst(pubkey)?;
    let signature = alloy_sig_to_blst(signature)?;

    let res = signature.verify(true, msg, BLS_DST_SIG, &[], &pubkey, true);
    if res == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(res.into())
    }
}

impl From<BlsPublicKey> for GenericPubkey {
    fn from(value: BlsPublicKey) -> Self {
        GenericPubkey::Bls(value)
    }
}
