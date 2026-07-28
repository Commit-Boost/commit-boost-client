use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cb_common::wire::{AcceptedEncodingsError, BodyDeserializeError};
use serde::Serialize;
use thiserror::Error;

/// The Builder API `ErrorMessage` error body: JSON `{code, message}`, where
/// `code` is the HTTP status.
#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: u16,
    message: String,
}

#[derive(Debug, Error)]
/// Errors that the PbsService returns to client
pub enum PbsClientError {
    #[error("no response from relays")]
    NoResponse,
    #[error("auth data does not match a configured builder")]
    AuthDataMismatch,
    #[error("missing or invalid timing headers")]
    MissingTimingHeader,
    #[error("auth slot does not match the request path")]
    AuthSlotMismatch,
    #[error("auth slot has already passed")]
    AuthSlotPassed,
    #[error("the addressed builder rejected the request with {code}")]
    BuilderRejected { code: u16 },
    #[error("auth signature verification failed")]
    AuthSigVerify,
    #[error("submitted block is not a Gloas block")]
    NotGloasBlock,
    #[error("no payload from relays")]
    NoPayload,
    #[error("internal server error")]
    Internal,
    #[error("failed to deserialize body: {0}")]
    DecodeError(#[from] BodyDeserializeError),
    #[error("invalid accept types: {0}")]
    HeaderError(#[from] AcceptedEncodingsError),
}

impl PbsClientError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            PbsClientError::NoResponse => StatusCode::BAD_GATEWAY,
            PbsClientError::AuthDataMismatch => StatusCode::BAD_REQUEST,
            PbsClientError::MissingTimingHeader => StatusCode::BAD_REQUEST,
            PbsClientError::AuthSlotMismatch => StatusCode::BAD_REQUEST,
            PbsClientError::AuthSlotPassed => StatusCode::BAD_REQUEST,
            // A lone addressed builder's own status is propagated: 400/401 from
            // the preferences endpoint, or any non-202 the winning builder
            // returned on submit. An out-of-range code falls back to 502.
            PbsClientError::BuilderRejected { code } => {
                StatusCode::from_u16(*code).unwrap_or(StatusCode::BAD_GATEWAY)
            }
            PbsClientError::AuthSigVerify => StatusCode::UNAUTHORIZED,
            PbsClientError::NotGloasBlock => StatusCode::BAD_REQUEST,
            PbsClientError::NoPayload => StatusCode::BAD_GATEWAY,
            PbsClientError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            PbsClientError::DecodeError(BodyDeserializeError::UnsupportedMediaType) => {
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            }
            PbsClientError::DecodeError(_) => StatusCode::BAD_REQUEST,
            PbsClientError::HeaderError(_) => StatusCode::NOT_ACCEPTABLE,
        }
    }
}

impl IntoResponse for PbsClientError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let message = match &self {
            PbsClientError::NoResponse => "no response from relays".to_string(),
            PbsClientError::AuthDataMismatch => {
                "Invalid SignedRequestAuthV1: auth.message.data does not match the value agreed with this builder".to_string()
            }
            PbsClientError::MissingTimingHeader => {
                "Invalid request: Date-Milliseconds and X-Timeout-Ms headers are required".to_string()
            }
            PbsClientError::AuthSlotMismatch => {
                "Invalid SignedRequestAuthV1: auth.message.slot does not match the proposal slot in the request path".to_string()
            }
            PbsClientError::AuthSlotPassed => {
                "Invalid SignedRequestAuthV1: auth.message.slot has already passed".to_string()
            }
            // The builder's own body is never forwarded: it is untrusted and may be
            // arbitrarily large
            PbsClientError::BuilderRejected { code } => {
                format!("The addressed builder rejected the submission with status {code}")
            }
            PbsClientError::AuthSigVerify => {
                "Invalid SignedRequestAuthV1: signature verification failed".to_string()
            }
            PbsClientError::NotGloasBlock => {
                "Invalid signed beacon block: only Gloas blocks are supported".to_string()
            }
            PbsClientError::NoPayload => "no payload from relays".to_string(),
            PbsClientError::Internal => "internal server error".to_string(),
            PbsClientError::DecodeError(e) => format!("error decoding request: {e}"),
            PbsClientError::HeaderError(e) => format!("header error: {e}"),
        };

        // Return the spec's JSON `ErrorMessage` rather than plain text so clients
        // can parse the error per the Builder API.
        (status, Json(ErrorResponse { code: status.as_u16(), message })).into_response()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn unsupported_media_type_maps_to_415() {
        assert_eq!(
            PbsClientError::DecodeError(BodyDeserializeError::UnsupportedMediaType).status_code(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        );
    }

    #[test]
    fn other_decode_errors_map_to_400() {
        assert_eq!(
            PbsClientError::DecodeError(BodyDeserializeError::MissingVersionHeader).status_code(),
            StatusCode::BAD_REQUEST,
        );
    }

    #[test]
    fn auth_errors_map_to_spec_status_codes() {
        assert_eq!(PbsClientError::AuthSlotMismatch.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(PbsClientError::AuthSigVerify.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            PbsClientError::DecodeError(BodyDeserializeError::MissingBody).status_code(),
            StatusCode::BAD_REQUEST,
        );
    }

    #[tokio::test]
    async fn error_response_is_json_with_code_and_message() {
        let err = PbsClientError::NoPayload;
        let status = err.status_code();
        let resp = err.into_response();

        assert_eq!(resp.status(), status);
        let content_type = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("application/json"),
            "error content-type must be JSON, got: {content_type}"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], status.as_u16());
        assert_eq!(json["message"], "no payload from relays");
    }
}
