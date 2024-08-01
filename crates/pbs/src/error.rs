use alloy::{
    primitives::{B256, U256},
    rpc::types::beacon::BlsPublicKey,
};
use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;
use cb_common::BlstErrorWrapper;

#[derive(Debug)]
/// Errors that the PbsService returns to client
pub enum PbsClientError {
    NoResponse,
    NoPayload,
}

impl PbsClientError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            PbsClientError::NoResponse => StatusCode::SERVICE_UNAVAILABLE,
            PbsClientError::NoPayload => StatusCode::BAD_GATEWAY,
        }
    }
}

impl IntoResponse for PbsClientError {
    fn into_response(self) -> axum::response::Response {
        let msg = match self {
            PbsClientError::NoResponse => "no response from relays",
            PbsClientError::NoPayload => "no payload from relays",
        };

        (self.status_code(), msg).into_response()
    }
}

#[derive(Debug, Error)]
pub enum PbsError {
    #[error("axum error: {0}")]
    AxumError(#[from] axum::Error),

    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("serde decode error: {0}")]
    SerdeDecodeError(#[from] serde_json::Error),

    #[error("relay response error. Code: {code}, err: {error_msg}")]
    RelayResponse { error_msg: String, code: u16 },

    #[error("failed validating relay response: {0}")]
    Validation(#[from] ValidationError),
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
}
