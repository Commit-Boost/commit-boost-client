use alloy::primitives::{B256, U256};
use lh_types::ForkName;
use thiserror::Error;

use crate::{types::BlsPublicKeyBytes, wire::ResponseReadError};

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

    #[error("tokio join error: {0}")]
    TokioJoinError(#[from] tokio::task::JoinError),

    #[error("SSZ error: {0}")]
    SszError(#[from] SszValueError),
}

impl PbsError {
    pub fn is_timeout(&self) -> bool {
        matches!(self, PbsError::Reqwest(err) if err.is_timeout())
    }

    /// Extract the HTTP status code from relay-originated errors.
    fn relay_status_code(&self) -> Option<u16> {
        match self {
            PbsError::RelayResponse { code, .. } => Some(*code),
            PbsError::ReadResponse(ResponseReadError::NonSuccess { status_code, .. }) => {
                Some(*status_code)
            }
            _ => None,
        }
    }

    /// Whether the error is retryable in requests to relays
    pub fn should_retry(&self) -> bool {
        match self {
            PbsError::Reqwest(err) => err.is_timeout() || err.is_connect(),
            _ => matches!(self.relay_status_code(), Some(500..=508)),
        }
    }

    pub fn is_not_found(&self) -> bool {
        self.relay_status_code() == Some(404)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("empty blockhash")]
    EmptyBlockhash,

    #[error("pubkey mismatch: expected {expected} got {got}")]
    PubkeyMismatch { expected: BlsPublicKeyBytes, got: BlsPublicKeyBytes },

    #[error("parent hash mismatch: expected {expected} got {got}")]
    ParentHashMismatch { expected: B256, got: B256 },

    #[error("block hash mismatch: expected {expected} got {got}")]
    BlockHashMismatch { expected: B256, got: B256 },

    #[error(
        "mismatch in KZG commitments: expected_blobs: {expected_blobs} got_blobs: {got_blobs} got_commitments: {got_commitments} got_proofs: {got_proofs}"
    )]
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

    #[error("unsupported fork")]
    UnsupportedFork,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SszValueError {
    #[error("invalid payload length: required {required} but payload was {actual}")]
    InvalidPayloadLength { required: usize, actual: usize },

    #[error("unsupported fork: {name}")]
    UnsupportedFork { name: ForkName },
}
