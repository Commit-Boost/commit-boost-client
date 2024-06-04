use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use blst::BLST_ERROR;
use cb_common::types::Chain;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tokio::sync::oneshot;
use tree_hash::{Hash256, TreeHash};
use tree_hash_derive::TreeHash;

use crate::signature::verify_signed_builder_message;

// TODO: might need to adapt the SignedProxyDelegation so that it goes through web3 signer
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ProxyDelegation {
    pub delegator: BlsPublicKey,
    pub proxy: BlsPublicKey,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SignedProxyDelegation {
    pub message: ProxyDelegation,
    /// Signature of message with the delegator keypair
    pub signature: BlsSignature,
}

impl SignedProxyDelegation {
    pub fn validate(&self, chain: Chain) -> Result<(), BLST_ERROR> {
        verify_signed_builder_message(
            chain,
            &self.message.delegator,
            &self.message,
            &self.signature,
        )
    }
}

pub struct SignRequest {
    pub id: String,
    pub pubkey: BlsPublicKey,
    pub is_proxy: bool,
    pub msg: Box<dyn ObjectTreeHash + 'static + Send + Sync>,
    pub ans: oneshot::Sender<eyre::Result<BlsSignature>>,
}

impl SignRequest {
    pub fn new(
        id: impl Into<String>,
        pubkey: BlsPublicKey,
        msg: impl ObjectTreeHash + 'static + Send + Sync,
    ) -> (SignRequest, oneshot::Receiver<eyre::Result<BlsSignature>>) {
        let (tx, rx) = oneshot::channel();
        let req = Self { id: id.into(), pubkey, is_proxy: false, msg: Box::new(msg), ans: tx };

        (req, rx)
    }

    pub fn new_proxy(
        id: impl Into<String>,
        pubkey: BlsPublicKey,
        msg: impl ObjectTreeHash + 'static + Send + Sync,
    ) -> (Self, oneshot::Receiver<eyre::Result<BlsSignature>>) {
        let (tx, rx) = oneshot::channel();
        let req = Self { id: id.into(), pubkey, is_proxy: true, msg: Box::new(msg), ans: tx };

        (req, rx)
    }
}

pub trait ObjectTreeHash {
    fn tree_hash(&self) -> Hash256;
}

impl<T: TreeHash + ?Sized> ObjectTreeHash for T {
    fn tree_hash(&self) -> Hash256 {
        self.tree_hash_root()
    }
}

impl ObjectTreeHash for Box<dyn ObjectTreeHash + Send + Sync> {
    fn tree_hash(&self) -> Hash256 {
        self.as_ref().tree_hash()
    }
}
