use alloy_rpc_types_beacon::BlsPublicKey;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignerModuleError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("unknown module id: {0}")]
    UnknownModuleId(String),

    #[error("unknown consensus signer: {0}")]
    UnknownConsensusSigner(BlsPublicKey),

    #[error("unknown proxy signer: {0}")]
    UnknownProxySigner(BlsPublicKey),
}

impl IntoResponse for SignerModuleError {
    fn into_response(self) -> Response {
        let status = match self {
            SignerModuleError::Unauthorized => StatusCode::UNAUTHORIZED,
            SignerModuleError::UnknownModuleId(_) => StatusCode::NOT_FOUND,
            SignerModuleError::UnknownConsensusSigner(_) => StatusCode::NOT_FOUND,
            SignerModuleError::UnknownProxySigner(_) => StatusCode::NOT_FOUND,
        };

        (status, self.to_string()).into_response()
    }
}
