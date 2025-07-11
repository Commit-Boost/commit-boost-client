use alloy::primitives::{B256, U256};
use thiserror::Error;

use crate::{pbs::BlsPublicKey, utils::ResponseReadError};

#[derive(Debug, Error)]
pub enum PbsError {
    #[error("axum error: {0:?}")]
    AxumError(#[from] axum::Error),

    #[error("reqwest error: {0:?}")]
    Reqwest(#[from] reqwest::Error),

    #[error("json decode error: {err:?}, raw: {raw}")]
    JsonDecode { err: serde_json::Error, raw: String },

    #[error("{0}")]
    ReadResponse(#[from] ResponseReadError),

    #[error("relay response error. Code: {code}, err: {error_msg:?}")]
    RelayResponse { error_msg: String, code: u16 },

    #[error("failed validating relay response: {0}")]
    Validation(#[from] ValidationError),

    #[error("URL parsing error: {0}")]
    UrlParsing(#[from] url::ParseError),
}

impl PbsError {
    pub fn is_timeout(&self) -> bool {
        matches!(self, PbsError::Reqwest(err) if err.is_timeout())
    }

    /// Whether the error is retryable in requests to relays
    pub fn should_retry(&self) -> bool {
        match self {
            PbsError::Reqwest(err) => {
                // Retry on timeout or connection error
                err.is_timeout() || err.is_connect()
            }
            PbsError::RelayResponse { code, .. } => match *code {
                500..509 => true,   // Retry on server errors
                400 | 429 => false, // Do not retry if rate limited or bad request
                _ => false,
            },
            _ => false,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("empty blockhash")]
    EmptyBlockhash,

    #[error("pubkey mismatch: expected {expected} got {got}")]
    PubkeyMismatch { expected: Box<BlsPublicKey>, got: Box<BlsPublicKey> },

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

    #[error("failed signature verification")]
    Sigverify,

    #[error("wrong timestamp: expected {expected} got {got}")]
    TimestampMismatch { expected: u64, got: u64 },

    #[error("wrong block number: parent: {parent} header: {header}")]
    BlockNumberMismatch { parent: u64, header: u64 },

    #[error("invalid gas limit: parent: {parent} header: {header}")]
    GasLimit { parent: u64, header: u64 },

    #[error("payload mismatch: request: {request} response: {response}")]
    PayloadVersionMismatch { request: &'static str, response: &'static str },
}
