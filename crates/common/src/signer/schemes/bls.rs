use alloy::rpc::types::beacon::{constants::BLS_DST_SIG, BlsPublicKey, BlsSignature};
use blst::BLST_ERROR;

use crate::{
    error::BlstErrorWrapper,
    signer::{GenericPubkey, Pubkey, SecretKey, Verifier},
    utils::blst_pubkey_to_alloy,
};

pub type BlsSecretKey = blst::min_pk::SecretKey;

impl SecretKey for BlsSecretKey {
    type PublicKey = BlsPublicKey;
    type Signature = BlsSignature;

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

    fn pubkey(&self) -> Self::PublicKey {
        blst_pubkey_to_alloy(&self.sk_to_pk())
    }

    fn sign(&self, msg: &[u8]) -> Self::Signature {
        let signature = self.sign(msg, BLS_DST_SIG, &[]).to_bytes();
        BlsSignature::from_slice(&signature)
    }
}

impl Verifier<BlsSecretKey> for Pubkey<BlsSecretKey> {
    type VerificationError = BlstErrorWrapper;

    fn verify_signature(
        &self,
        msg: &[u8],
        signature: &<BlsSecretKey as SecretKey>::Signature,
    ) -> Result<(), Self::VerificationError> {
        use crate::utils::{alloy_pubkey_to_blst, alloy_sig_to_blst};

        let pubkey = alloy_pubkey_to_blst(self)?;
        let signature = alloy_sig_to_blst(signature)?;

        let res = signature.verify(true, msg, BLS_DST_SIG, &[], &pubkey, true);
        if res == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(res.into())
        }
    }
}

impl From<BlsPublicKey> for GenericPubkey {
    fn from(value: BlsPublicKey) -> Self {
        GenericPubkey::Bls(value)
    }
}
