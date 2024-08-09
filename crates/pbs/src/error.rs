use axum::{http::StatusCode, response::IntoResponse};

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
