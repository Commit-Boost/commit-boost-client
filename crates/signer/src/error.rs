use alloy::hex;
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

    #[error("unknown proxy signer: 0x{}", hex::encode(.0))]
    UnknownProxySigner(Vec<u8>),

    #[error("internal error {0}")]
    Internal(String),
}

impl IntoResponse for SignerModuleError {
    fn into_response(self) -> Response {
        let status = match self {
            SignerModuleError::Unauthorized => StatusCode::UNAUTHORIZED,
            SignerModuleError::UnknownConsensusSigner(_) => StatusCode::NOT_FOUND,
            SignerModuleError::UnknownProxySigner(_) => StatusCode::NOT_FOUND,
            SignerModuleError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, self.to_string()).into_response()
    }
}
