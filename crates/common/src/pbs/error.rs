use alloy::{
    primitives::{B256, U256},
    rpc::types::beacon::BlsPublicKey,
};
use thiserror::Error;

use crate::error::BlstErrorWrapper;

#[derive(Debug, Error)]
pub enum PbsError {
    #[error("axum error: {0:?}")]
    AxumError(#[from] axum::Error),

    #[error("reqwest error: {0:?}")]
    Reqwest(#[from] reqwest::Error),

    #[error("json decode error: {err:?}, raw: {raw}")]
    JsonDecode { err: serde_json::Error, raw: String },

    #[error("relay response error. Code: {code}, err: {error_msg}")]
    RelayResponse { error_msg: String, code: u16 },

    #[error("response size exceeds max size: max: {max} raw: {raw}")]
    PayloadTooLarge { max: usize, raw: String },

    #[error("failed validating relay response: {0}")]
    Validation(#[from] ValidationError),

    #[error("URL parsing error: {0}")]
    UrlParsing(#[from] url::ParseError),
}

impl PbsError {
    pub fn is_timeout(&self) -> bool {
        matches!(self, PbsError::Reqwest(err) if err.is_timeout())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("empty blockhash")]
    EmptyBlockhash,

    #[error("pubkey mismatch: expected {expected} got {got}")]
    PubkeyMismatch { expected: BlsPublicKey, got: BlsPublicKey },

    #[error("parent hash mismatch: expected {expected} got {got}")]
    ParentHashMismatch { expected: B256, got: B256 },

    #[error("block hash mismatch: expected {expected} got {got}")]
    BlockHashMismatch { expected: B256, got: B256 },

    #[error("mismatch in KZG commitments: exepcted_blobs: {expected_blobs} got_blobs: {got_blobs} got_commitments: {got_commitments} got_proofs: {got_proofs}")]
    KzgCommitments {
        expected_blobs: usize,
        got_blobs: usize,
        got_commitments: usize,
        got_proofs: usize,
    },

    #[error("mismatch in KZG blob commitment: expected: {expected} got: {got} index: {index}")]
    KzgMismatch { expected: String, got: String, index: usize },

    #[error("bid below minimum: min: {min} got {got}")]
    BidTooLow { min: U256, got: U256 },

    #[error("empty tx root")]
    EmptyTxRoot,

    #[error("failed signature verification: {0:?}")]
    Sigverify(#[from] BlstErrorWrapper),

    #[error("wrong timestamp: expected {expected} got {got}")]
    TimestampMismatch { expected: u64, got: u64 },

    #[error("wrong block number: parent: {parent} header: {header}")]
    BlockNumberMismatch { parent: u64, header: u64 },

    #[error("invalid gas limit: parent: {parent} header: {header}")]
    GasLimit { parent: u64, header: u64 },
}
