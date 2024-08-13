use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};

use crate::{
    error::BlstErrorWrapper,
    signature::{sign_message, verify_signature},
    signer::{GenericPubkey, SecretKey},
    utils::blst_pubkey_to_alloy,
};

pub type BlsSecretKey = blst::min_pk::SecretKey;

impl SecretKey for BlsSecretKey {
    type PubKey = BlsPublicKey;
    type Signature = BlsSignature;
    type VerificationError = BlstErrorWrapper;

    fn new_random() -> Self {
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

    fn new_from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
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
}

impl From<BlsPublicKey> for GenericPubkey {
    fn from(value: BlsPublicKey) -> Self {
        GenericPubkey::Bls(value)
    }
}
