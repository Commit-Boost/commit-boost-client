use alloy::rpc::types::beacon::{constants::BLS_DST_SIG, BlsPublicKey, BlsSignature};
use blst::BLST_ERROR;
use tree_hash::TreeHash;

use crate::{
    error::BlstErrorWrapper, signature::sign_builder_root, signer::GenericPubkey, types::Chain, utils::blst_pubkey_to_alloy
};

pub type BlsSecretKey = blst::min_pk::SecretKey;

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
            BlsSigner::Local(secret) => blst_pubkey_to_alloy(&secret.sk_to_pk()),
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

// impl SecretKey for BlsSecretKey {
//     // type PublicKey = BlsPublicKey;
//     // type Signature = BlsSignature;

//     // fn new_random() -> Self {
//     //     use rand::RngCore;

//     //     let mut rng = rand::thread_rng();
//     //     let mut ikm = [0u8; 32];
//     //     rng.fill_bytes(&mut ikm);

//     //     match BlsSecretKey::key_gen(&ikm, &[]) {
//     //         Ok(key) => key,
//     //         // Key material is always valid (32 `u8`s), so `key_gen` can't return Err.
//     //         Err(_) => unreachable!(),
//     //     }
//     // }

//     fn new_from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
//         Ok(BlsSecretKey::from_bytes(bytes).map_err(BlstErrorWrapper::from)?)
//     }

//     fn pubkey(&self) -> Self::PublicKey {
//         blst_pubkey_to_alloy(&self.sk_to_pk())
//     }

//     fn sign(&self, msg: &[u8]) -> Self::Signature {
//         let signature = self.sign(msg, BLS_DST_SIG, &[]).to_bytes();
//         BlsSignature::from_slice(&signature)
//     }
// }

pub fn verify_bls_signature(pubkey: &BlsPublicKey, msg: &[u8], signature: &BlsSignature) -> Result<(), BlstErrorWrapper> {
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

// impl Verifier<BlsSecretKey> for Pubkey<BlsSecretKey> {
//     type VerificationError = BlstErrorWrapper;

//     fn verify_signature(
//         &self,
//         msg: &[u8],
//         signature: &<BlsSecretKey as SecretKey>::Signature,
//     ) -> Result<(), Self::VerificationError> {
//         use crate::utils::{alloy_pubkey_to_blst, alloy_sig_to_blst};

//         let pubkey = alloy_pubkey_to_blst(self)?;
//         let signature = alloy_sig_to_blst(signature)?;

//         let res = signature.verify(true, msg, BLS_DST_SIG, &[], &pubkey, true);
//         if res == BLST_ERROR::BLST_SUCCESS {
//             Ok(())
//         } else {
//             Err(res.into())
//         }
//     }
// }

impl From<BlsPublicKey> for GenericPubkey {
    fn from(value: BlsPublicKey) -> Self {
        GenericPubkey::Bls(value)
    }
}
