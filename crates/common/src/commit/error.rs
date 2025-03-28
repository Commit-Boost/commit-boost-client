#[derive(Debug, thiserror::Error)]
pub enum SignerClientError {
    #[error("reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("invalid header value: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),

    #[error("failed request: status {status}; message: \"{error_msg}\"")]
    FailedRequest { status: u16, error_msg: String },

    #[error("serde decode error: {0}")]
    SerdeDecodeError(#[from] serde_json::Error),

    #[error("url parse error: {0}")]
    ParseError(#[from] url::ParseError),

    #[error("JWT error: {0}")]
    JWTError(#[from] eyre::Error),
}
