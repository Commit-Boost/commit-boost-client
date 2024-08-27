use core::fmt;
use std::hash::Hash;

use derive_more::derive::{Deref, From, Into};
use generic_array::GenericArray;
use k256::ecdsa::{Signature as EcdsaSignatureInner, VerifyingKey as EcdsaPublicKeyInner};
use serde::{Deserialize, Serialize};
use serde_utils::hex;
use ssz_types::{
    typenum::{U33, U64},
    FixedVector,
};
use tree_hash::TreeHash;

use crate::{signature::compute_signing_root, signer::GenericPubkey, types::Chain};

pub type EcdsaSecretKey = k256::ecdsa::SigningKey;

type CompressedPublicKey = GenericArray<u8, U33>;

#[derive(Debug, Clone, Copy, From, Into, Serialize, Deserialize, PartialEq, Eq, Deref, Hash)]
pub struct EcdsaPublicKey {
    encoded: CompressedPublicKey,
}

impl EcdsaPublicKey {
    /// Size of the public key in bytes. We store the SEC1 encoded affine point
    /// compressed, thus 33 bytes.
    const SIZE: usize = 33;
}

impl TreeHash for EcdsaPublicKey {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        // NOTE:
        // Unnecessary copying into a `FixedVector` just for its `tree_hash_root`
        // implementation.  If this becomes a performance issue, we could use
        // `ssz_types::tree_hash::vec_tree_hash_root`,  which is unfortunately
        // not public.
        let vec = self.encoded.to_vec();
        FixedVector::<u8, U33>::from(vec).tree_hash_root()
    }
}

impl ssz::Encode for EcdsaPublicKey {
    #[inline]
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_bytes_len(&self) -> usize {
        Self::SIZE
    }

    #[inline]
    fn ssz_fixed_len() -> usize {
        Self::SIZE
    }

    #[inline]
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.encoded)
    }

    #[inline]
    fn as_ssz_bytes(&self) -> Vec<u8> {
        self.encoded.to_vec()
    }
}

impl ssz::Decode for EcdsaPublicKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        Self::SIZE
    }

    fn from_ssz_bytes(bytes: &[u8]) -> std::result::Result<Self, ssz::DecodeError> {
        if bytes.len() != Self::SIZE {
            return Err(ssz::DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: Self::SIZE,
            });
        }

        let mut fixed_array = [0_u8; Self::SIZE];
        fixed_array.copy_from_slice(bytes);

        Ok(EcdsaPublicKey { encoded: fixed_array.into() })
    }
}

impl From<EcdsaPublicKeyInner> for EcdsaPublicKey {
    fn from(value: EcdsaPublicKeyInner) -> Self {
        let encoded: [u8; Self::SIZE] = value.to_encoded_point(true).as_bytes().try_into().unwrap();

        EcdsaPublicKey { encoded: encoded.into() }
    }
}

impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.encoded
    }
}

impl fmt::LowerHex for EcdsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))?;
        Ok(())
    }
}

impl fmt::Display for EcdsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:x}")
    }
}

// TODO(David): Hex encode when Ser/De
#[derive(Clone, Deref, Serialize, Deserialize)]
pub struct EcdsaSignature {
    encoded: GenericArray<u8, U64>,
}

impl From<EcdsaSignatureInner> for EcdsaSignature {
    fn from(value: EcdsaSignatureInner) -> Self {
        Self { encoded: value.to_bytes() }
    }
}

impl AsRef<[u8]> for EcdsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.encoded
    }
}

impl TryFrom<&[u8]> for EcdsaSignature {
    type Error = k256::ecdsa::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(EcdsaSignatureInner::from_slice(value)?.into())
    }
}

impl fmt::LowerHex for EcdsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))?;
        Ok(())
    }
}

impl fmt::Display for EcdsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:x}")
    }
}

// SIGNER
#[derive(Clone)]
pub enum EcdsaSigner {
    Local(EcdsaSecretKey),
}

impl EcdsaSigner {
    pub fn new_random() -> Self {
        Self::Local(EcdsaSecretKey::random(&mut rand::thread_rng()))
    }

    pub fn new_from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
        let secret = EcdsaSecretKey::from_slice(bytes)?;
        Ok(Self::Local(secret))
    }

    pub fn pubkey(&self) -> EcdsaPublicKey {
        match self {
            EcdsaSigner::Local(secret) => EcdsaPublicKeyInner::from(secret).into(),
        }
    }

    pub async fn sign(&self, chain: Chain, object_root: [u8; 32]) -> EcdsaSignature {
        match self {
            EcdsaSigner::Local(sk) => {
                let domain = chain.builder_domain();
                let signing_root = compute_signing_root(object_root, domain);
                k256::ecdsa::signature::Signer::<EcdsaSignatureInner>::sign(sk, &signing_root)
                    .into()
            }
        }
    }

    pub async fn sign_msg(&self, chain: Chain, msg: &impl TreeHash) -> EcdsaSignature {
        self.sign(chain, msg.tree_hash_root().0).await
    }
}

pub fn verify_ecdsa_signature(
    pubkey: &EcdsaPublicKey,
    msg: &[u8],
    signature: &EcdsaSignature,
) -> Result<(), k256::ecdsa::Error> {
    use k256::ecdsa::signature::Verifier;
    let ecdsa_pubkey = EcdsaPublicKeyInner::from_sec1_bytes(&pubkey.encoded)?;
    let ecdsa_sig = EcdsaSignatureInner::from_bytes(signature)?;
    ecdsa_pubkey.verify(msg, &ecdsa_sig)
}

impl From<EcdsaPublicKey> for GenericPubkey {
    fn from(value: EcdsaPublicKey) -> Self {
        GenericPubkey::Ecdsa(value)
    }
}
