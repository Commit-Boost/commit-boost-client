use std::{
    error::Error,
    fmt::{self, LowerHex},
};

use eyre::Context;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;

pub mod schemes;
pub mod signers;

pub use schemes::{bls::BlsSecretKey, ecdsa::EcdsaSecretKey};
pub use signers::Signer;

pub type Pubkey<T> = <T as SecretKey>::PublicKey;

pub trait SecretKey {
    type PublicKey: AsRef<[u8]> + Clone + Verifier<Self>;
    type Signature: AsRef<[u8]> + Clone;

    fn new_random() -> Self;
    fn new_from_bytes(bytes: &[u8]) -> eyre::Result<Self>
    where
        Self: Sized;
    fn pubkey(&self) -> Self::PublicKey;
    fn sign(&self, msg: &[u8]) -> Self::Signature;
    fn sign_msg(&self, msg: &impl TreeHash) -> Self::Signature {
        self.sign(&msg.tree_hash_root().0)
    }
}

pub trait Verifier<T: SecretKey>
where
    T: ?Sized,
{
    type VerificationError: Error;

    fn verify_signature(
        &self,
        msg: &[u8],
        signature: &T::Signature,
    ) -> Result<(), Self::VerificationError>;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
pub enum GenericPubkey {
    Bls(Pubkey<BlsSecretKey>),
    Ecdsa(Pubkey<EcdsaSecretKey>),
}

impl GenericPubkey {
    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> eyre::Result<()> {
        match self {
            GenericPubkey::Bls(bls_pubkey) => {
                let sig = signature.try_into().context("Invalid signature length for BLS.")?;
                Ok(bls_pubkey.verify_signature(msg, &sig)?)
            }
            GenericPubkey::Ecdsa(ecdsa_pubkey) => {
                let sig = signature.try_into().context("Invalid signature for ECDSA.")?;
                Ok(ecdsa_pubkey.verify_signature(msg, &sig)?)
            }
        }
    }
}

impl AsRef<[u8]> for GenericPubkey {
    fn as_ref(&self) -> &[u8] {
        match self {
            GenericPubkey::Bls(bls_pubkey) => bls_pubkey.as_ref(),
            GenericPubkey::Ecdsa(ecdsa_pubkey) => ecdsa_pubkey.as_ref(),
        }
    }
}

impl LowerHex for GenericPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;

        let pubkey_bytes = match self {
            GenericPubkey::Bls(bls) => bls.as_ref(),
            GenericPubkey::Ecdsa(ecdsa) => ecdsa.as_ref(),
        };

        for byte in pubkey_bytes {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl fmt::Display for GenericPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:x}")
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
            GenericPubkey::Ecdsa(ref inner) => inner.tree_hash_root(),
        }
    }
}
