use std::fmt::{self, LowerHex};

use alloy::rpc::types::beacon::BlsPublicKey;
use eyre::Context;
use schemes::{bls::verify_bls_signature, ecdsa::verify_ecdsa_signature};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

pub mod schemes;
#[allow(clippy::module_inception)]
mod signer;

pub use schemes::{
    bls::BlsSecretKey,
    ecdsa::{EcdsaPublicKey, EcdsaSecretKey, EcdsaSignature},
};
pub use signer::{BlsSigner, ConsensusSigner, EcdsaSigner};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
pub enum GenericPubkey {
    Bls(BlsPublicKey),
    Ecdsa(EcdsaPublicKey),
}

impl GenericPubkey {
    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> eyre::Result<()> {
        match self {
            GenericPubkey::Bls(bls_pubkey) => {
                let sig = signature.try_into().context("Invalid signature length for BLS.")?;
                Ok(verify_bls_signature(bls_pubkey, msg, &sig)?)
            }
            GenericPubkey::Ecdsa(ecdsa_pubkey) => {
                let sig = signature.try_into().context("Invalid signature for ECDSA.")?;
                Ok(verify_ecdsa_signature(ecdsa_pubkey, msg, &sig)?)
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

impl TryFrom<GenericPubkey> for BlsPublicKey {
    type Error = ();

    fn try_from(value: GenericPubkey) -> Result<Self, Self::Error> {
        match value {
            GenericPubkey::Bls(bls_pubkey) => Ok(bls_pubkey),
            GenericPubkey::Ecdsa(_) => Err(()),
        }
    }
}

impl TryFrom<GenericPubkey> for EcdsaPublicKey {
    type Error = ();

    fn try_from(value: GenericPubkey) -> Result<Self, Self::Error> {
        match value {
            GenericPubkey::Bls(_) => Err(()),
            GenericPubkey::Ecdsa(ecdsa_pubkey) => Ok(ecdsa_pubkey),
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
