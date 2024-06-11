
pub mod config;
pub mod pbs;
pub mod signature;
pub mod signer;
pub mod types;
pub mod utils;
pub mod constants;

pub const SIGNER_LISTEN_ADDR: &str = "SIGNER_LISTEN_ADDR";

pub trait ObjectTreeHash {
    fn tree_hash(&self) -> tree_hash::Hash256;
}

impl<T: tree_hash::TreeHash + ?Sized> ObjectTreeHash for T {
    fn tree_hash(&self) -> tree_hash::Hash256 {
        self.tree_hash_root()
    }
}

impl ObjectTreeHash for Box<dyn ObjectTreeHash + Send + Sync> {
    fn tree_hash(&self) -> tree_hash::Hash256 {
        self.as_ref().tree_hash()
    }
}