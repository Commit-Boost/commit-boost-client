use std::hash::Hash;

use derive_more::derive::Into;
use eyre::Result;
use generic_array::GenericArray;
use k256::{
    ecdsa::{Signature as EcdsaSignatureInner, VerifyingKey as EcdsaPublicKeyInner},
    AffinePoint,
};
use serde::{Deserialize, Serialize};
use ssz_types::{typenum::U33, FixedVector};
use tree_hash::TreeHash;

use crate::signer::{GenericPubkey, PubKey, SecretKey};

pub type EcdsaSecretKey = k256::ecdsa::SigningKey;
type EcdsaCompressedKey = GenericArray<u8, U33>;

#[derive(Debug, Clone, Copy, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "JSONEcdsaPublicKey")]
pub struct EcdsaPublicKey {
    #[serde(skip_serializing)]
    inner: EcdsaPublicKeyInner,
    encoded: EcdsaCompressedKey,
}

impl EcdsaPublicKey {
    /// Size of the public key in bytes. We store the SEC1 encoded affine point
    /// compressed, thus 33 bytes.
    const SIZE: usize = 33;

    pub fn new(inner: EcdsaPublicKeyInner) -> Self {
        use elliptic_curve::sec1::ToEncodedPoint;

        let affine: &AffinePoint = inner.as_ref();
        let encoded: [u8; Self::SIZE] =
            affine.to_encoded_point(true).as_bytes().try_into().unwrap();

        let encoded = GenericArray::from_array(encoded);

        EcdsaPublicKey { inner, encoded }
    }

    pub fn new_from_bytes(encoded: Vec<u8>) -> Result<Self, k256::ecdsa::Error> {
        let inner = EcdsaPublicKeyInner::from_sec1_bytes(&encoded)?;
        let encoded = GenericArray::from_array::<{ Self::SIZE }>(encoded.try_into().unwrap());
        Ok(Self { inner, encoded })
    }

    fn new_from_bytes_infallible(encoded: [u8; Self::SIZE]) -> Self {
        Self {
            inner: EcdsaPublicKeyInner::from_sec1_bytes(&encoded).unwrap(),
            encoded: GenericArray::from_array(encoded),
        }
    }
}

impl Hash for EcdsaPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encoded.hash(state);
    }
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
        let vec = self.encoded.into_array::<{ Self::SIZE }>().to_vec();
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

        Ok(EcdsaPublicKey::new_from_bytes_infallible(fixed_array))
    }
}

impl TryFrom<Vec<u8>> for EcdsaPublicKey {
    type Error = k256::ecdsa::Error;

    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        Self::new_from_bytes(value)
    }
}

impl From<EcdsaCompressedKey> for EcdsaPublicKey {
    fn from(value: EcdsaCompressedKey) -> Self {
        Self::new_from_bytes_infallible(value.into())
    }
}

#[derive(Deserialize)]
struct JSONEcdsaPublicKey {
    encoded: EcdsaCompressedKey,
}

impl From<JSONEcdsaPublicKey> for EcdsaPublicKey {
    fn from(value: JSONEcdsaPublicKey) -> Self {
        Self::from(value.encoded)
    }
}

impl From<EcdsaPublicKeyInner> for EcdsaPublicKey {
    fn from(value: EcdsaPublicKeyInner) -> Self {
        EcdsaPublicKey::new(value)
    }
}

impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.encoded
    }
}

#[derive(Clone)]
pub struct EcdsaSignature {
    inner: EcdsaSignatureInner,
    // TODO(David): Maybe prefer `GenericArray<u8, U64>` for explicit fixed size.
    pub(in crate::signer) encoded: Vec<u8>,
}

impl EcdsaSignature {
    pub fn new(inner: EcdsaSignatureInner) -> Self {
        Self { inner, encoded: inner.to_vec() }
    }
}

impl From<EcdsaSignatureInner> for EcdsaSignature {
    fn from(value: EcdsaSignatureInner) -> Self {
        Self::new(value)
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

impl SecretKey for EcdsaSecretKey {
    type PubKey = EcdsaPublicKey;

    type Signature = EcdsaSignature;

    type VerificationError = k256::ecdsa::Error;

    fn new_random() -> Self {
        EcdsaSecretKey::random(&mut rand::thread_rng())
    }

    fn new_from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(EcdsaSecretKey::from_slice(bytes)?)
    }

    fn pubkey(&self) -> Self::PubKey {
        EcdsaPublicKeyInner::from(self).into()
    }

    fn sign(&self, msg: &[u8; 32]) -> Self::Signature {
        k256::ecdsa::signature::Signer::<EcdsaSignatureInner>::sign(self, msg).into()
    }

    fn verify_signature(
        pubkey: &Self::PubKey,
        msg: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::VerificationError> {
        use k256::ecdsa::signature::Verifier;
        pubkey.inner.verify(msg, &signature.inner)
    }
}

impl From<EcdsaPublicKey> for GenericPubkey {
    fn from(value: PubKey<EcdsaSecretKey>) -> Self {
        GenericPubkey::Ecdsa(value)
    }
}
