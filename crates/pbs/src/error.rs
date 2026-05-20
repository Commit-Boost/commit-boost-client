use axum::{http::StatusCode, response::IntoResponse};
use cb_common::wire::BodyDeserializeError;
use thiserror::Error;

#[derive(Debug, Error)]
/// Errors that the PbsService returns to client
pub enum PbsClientError {
    #[error("no response from relays")]
    NoResponse,
    #[error("no payload from relays")]
    NoPayload,
    #[error("internal server error")]
    Internal,
    #[error("failed to deserialize body: {0}")]
    DecodeError(#[from] BodyDeserializeError),
}

impl PbsClientError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            PbsClientError::NoResponse => StatusCode::BAD_GATEWAY,
            PbsClientError::NoPayload => StatusCode::BAD_GATEWAY,
            PbsClientError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            PbsClientError::DecodeError(_) => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for PbsClientError {
    fn into_response(self) -> axum::response::Response {
        let msg = match &self {
            PbsClientError::NoResponse => "no response from relays".to_string(),
            PbsClientError::NoPayload => "no payload from relays".to_string(),
            PbsClientError::Internal => "internal server error".to_string(),
            PbsClientError::DecodeError(e) => format!("error decoding request: {e}"),
        };

        (self.status_code(), msg).into_response()
    }
}
