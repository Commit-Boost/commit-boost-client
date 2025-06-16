use alloy::primitives::B256;

pub mod keccak;

/// A trait for hashers that can provide unique signing hashes for incoming
/// signing requests.
pub trait SigningHasher: Clone {
    /// Hashes an object root from a signing request and the unique signing ID
    /// for the requesting module.
    fn hash(&self, object_root: &B256, signing_id: &B256) -> B256;
}
