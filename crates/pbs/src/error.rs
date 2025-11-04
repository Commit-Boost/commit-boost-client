use axum::{http::StatusCode, response::IntoResponse};

#[derive(Debug)]
/// Errors that the PbsService returns to client
pub enum PbsClientError {
    NoResponse,
    NoPayload,
    Internal,
    DecodeError(String),
    RelayError(String),
}

impl PbsClientError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            PbsClientError::NoResponse => StatusCode::BAD_GATEWAY,
            PbsClientError::NoPayload => StatusCode::BAD_GATEWAY,
            PbsClientError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            PbsClientError::DecodeError(_) => StatusCode::BAD_REQUEST,
            PbsClientError::RelayError(_) => StatusCode::FAILED_DEPENDENCY,
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
            PbsClientError::RelayError(e) => format!("error processing relay response: {e}"),
        };

        (self.status_code(), msg).into_response()
    }
}
