use std::{
    error::Error,
    fmt::{self, LowerHex},
};

use eyre::{Context, Result};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;

pub mod schemes;
pub mod signers;

pub use schemes::{bls::BlsSecretKey, ecdsa::EcdsaSecretKey};
pub use signers::{GenericProxySigner, ProxySigner, Signer};

pub type PubKey<T> = <T as SecretKey>::PubKey;

pub trait SecretKey {
    type PubKey: AsRef<[u8]> + Clone;
    type Signature: AsRef<[u8]> + Clone;
    type VerificationError: Error;

    fn new_random() -> Self;
    fn new_from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
    fn pubkey(&self) -> Self::PubKey;
    fn sign(&self, msg: &[u8; 32]) -> Self::Signature;
    fn sign_msg(&self, msg: &impl TreeHash) -> Self::Signature {
        self.sign(&msg.tree_hash_root().0)
    }

    fn verify_signature(
        pubkey: &Self::PubKey,
        msg: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::VerificationError>;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
pub enum GenericPubkey {
    Bls(PubKey<BlsSecretKey>),
    Ecdsa(PubKey<EcdsaSecretKey>),
}

impl GenericPubkey {
    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> eyre::Result<()> {
        match self {
            GenericPubkey::Bls(bls_pubkey) => Ok(<BlsSecretKey as SecretKey>::verify_signature(
                bls_pubkey,
                msg,
                signature.try_into().context("Invalid signature length for BLS.")?,
            )?),
            GenericPubkey::Ecdsa(ecdsa_pubkey) => {
                let sig = signature.try_into().context("Invalid signature for ECDSA.")?;
                Ok(<EcdsaSecretKey as SecretKey>::verify_signature(ecdsa_pubkey, msg, &sig)?)
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
