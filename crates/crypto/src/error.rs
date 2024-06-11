use alloy_rpc_types_beacon::BlsPublicKey;
use axum::response::IntoResponse;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("unknown consensus signer: {0}")]
    UnknownConsensusSigner(BlsPublicKey),

    #[error("unknown proxy signer: {0}")]
    UnknownProxySigner(BlsPublicKey),
}

impl IntoResponse for SignError {
    fn into_response(self) -> axum::response::Response {
        todo!()
    }
}
