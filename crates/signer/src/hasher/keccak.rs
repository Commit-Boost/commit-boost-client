use alloy::primitives::{Keccak256, B256};

use super::SigningHasher;

///  A hasher that uses Keccak256 for signing request hashes.
#[derive(Clone)]
pub struct KeccakHasher {}

impl KeccakHasher {
    /// Creates a new KeccakHasher instance.
    pub fn new() -> Self {
        Self {}
    }
}

impl SigningHasher for KeccakHasher {
    /// Hashes an object root from a signing request and the unique signing ID
    /// for the requesting module into a hash that can be used to sign the
    /// request.
    fn hash(&self, object_root: &B256, signing_id: &B256) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(object_root);
        hasher.update(signing_id);
        hasher.finalize()
    }
}
