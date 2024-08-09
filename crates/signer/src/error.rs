use alloy::{hex, rpc::types::beacon::BlsPublicKey};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignerModuleError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("unknown consensus signer: 0x{}", hex::encode(.0))]
    UnknownConsensusSigner(Vec<u8>),

    // TODO(David): Think about better formatting, maybe a custom type instead of Vec<u8>
    #[error("unknown proxy signer: 0x{}", hex::encode(.0))]
    UnknownProxySigner(Vec<u8>),
}

impl IntoResponse for SignerModuleError {
    fn into_response(self) -> Response {
        let status = match self {
            SignerModuleError::Unauthorized => StatusCode::UNAUTHORIZED,
            SignerModuleError::UnknownConsensusSigner(_) => StatusCode::NOT_FOUND,
            SignerModuleError::UnknownProxySigner(_) => StatusCode::NOT_FOUND,
        };

        (status, self.to_string()).into_response()
    }
}
