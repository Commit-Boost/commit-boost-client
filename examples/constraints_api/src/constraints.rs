use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use alloy::primitives::TxHash;
use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use cb_common::pbs::{DenebSpec, EthSpec, Transaction};
use tracing::trace;

use crate::types::{ConstraintsMessage, HashTreeRoot};

pub(crate) struct ConstraintsWithProofData {
    pub message: ConstraintsMessage,
    /// List of transaction hashes and corresponding hash tree roots. Same order
    /// as the transactions in the `message`.
    pub transactions: Vec<(TxHash, HashTreeRoot)>,
}

/// A concurrent cache of constraints.
#[derive(Clone)]
pub(crate) struct ConstraintsCache {
    cache: Arc<RwLock<HashMap<u64, Vec<ConstraintsWithProofData>>>>,
}

impl ConstraintsCache {
    pub fn new() -> Self {
        Self { cache: Default::default() }
    }

    /// Checks if the constraints for the given slot conflict with the existing constraints.
    /// Will check for:
    /// - Multiple permutations of bundles with the same transactions
    /// - Multiple bundles with ToB flag
    pub fn conflicts_with(&self, slot: &u64, constraints: &ConstraintsMessage) -> bool {
        todo!("Implement this, we don't want to insert conflicting orders from the same validator for the same slot")
    }

    /// Inserts the constraints for the given slot. Also decodes the raw transactions to save their
    /// transaction hashes and hash tree roots for later use. Will first check for conflicts, and return
    /// false if there are any.
    pub fn insert(&self, slot: u64, constraints: ConstraintsMessage) -> bool {
        if self.conflicts_with(&slot, &constraints) {
            return false;
        }

        let mut transactions = Vec::with_capacity(constraints.transactions.len());

        for tx in &constraints.transactions {
            let tx_hash = *TxEnvelope::decode_2718(&mut tx.as_ref())
                .expect("Valid transaction encoding")
                .tx_hash();

            let tx_root = tree_hash::TreeHash::tree_hash_root(&Transaction::<
                <DenebSpec as EthSpec>::MaxBytesPerTransaction,
            >::from(tx.to_vec()));

            trace!(?tx_hash, ?tx_root, "Decoded constraint tx");

            transactions.push((tx_hash, tx_root));
        }

        // Wrap the constraints message with the transaction info
        let message_with_txs = ConstraintsWithProofData { message: constraints, transactions };

        if let Some(cs) = self.cache.write().unwrap().get_mut(&slot) {
            cs.push(message_with_txs);
        } else {
            self.cache.write().unwrap().insert(slot, vec![message_with_txs]);
        }

        true
    }

    /// Removes all constraints before the given slot.
    pub fn remove_before(&self, slot: u64) {
        self.cache.write().unwrap().retain(|k, _| *k >= slot);
    }

    /// Gets and removes the constraints for the given slot.
    pub fn remove(&self, slot: u64) -> Option<Vec<ConstraintsWithProofData>> {
        self.cache.write().unwrap().remove(&slot)
    }
}
