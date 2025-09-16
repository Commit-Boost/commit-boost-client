#[cfg(test)]
use std::cell::Cell;
use std::{
    fmt::Display,
    net::Ipv4Addr,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::{hex, primitives::U256};
use axum::{
    extract::{FromRequest, Request},
    http::HeaderValue,
    response::{IntoResponse, Response as AxumResponse},
};
use bytes::Bytes;
use futures::StreamExt;
use headers_accept::Accept;
pub use lh_types::ForkName;
use lh_types::test_utils::{SeedableRng, TestRandom, XorShiftRng};
use rand::{Rng, distr::Alphanumeric};
use reqwest::{
    Response,
    header::{ACCEPT, CONTENT_TYPE, HeaderMap},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use ssz::{Decode, Encode};
use thiserror::Error;
use tracing::Level;
use tracing_appender::{non_blocking::WorkerGuard, rolling::Rotation};
use tracing_subscriber::{
    EnvFilter,
    fmt::{Layer, format::Format},
    prelude::*,
};

use crate::{
    config::LogsSettings,
    constants::SIGNER_JWT_EXPIRATION,
    pbs::HEADER_VERSION_VALUE,
    types::{BlsPublicKey, Chain, Jwt, JwtClaims, ModuleId},
};

const APPLICATION_JSON: &str = "application/json";
const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
const WILDCARD: &str = "*/*";

const MILLIS_PER_SECOND: u64 = 1_000;
pub const CONSENSUS_VERSION_HEADER: &str = "Eth-Consensus-Version";

#[derive(Debug, Error)]
pub enum ResponseReadError {
    #[error(
        "response size exceeds max size; max: {max}, content_length: {content_length}, raw: {raw}"
    )]
    PayloadTooLarge { max: usize, content_length: usize, raw: String },

    #[error("error reading response stream: {0}")]
    ReqwestError(#[from] reqwest::Error),
}

#[cfg(test)]
thread_local! {
    static IGNORE_CONTENT_LENGTH: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub fn set_ignore_content_length(val: bool) {
    IGNORE_CONTENT_LENGTH.with(|f| f.set(val));
}

#[cfg(test)]
fn should_ignore_content_length() -> bool {
    IGNORE_CONTENT_LENGTH.with(|f| f.get())
}

/// Reads the body of a response as a chunked stream, ensuring the size does not
/// exceed `max_size`.
pub async fn read_chunked_body_with_max(
    res: Response,
    max_size: usize,
) -> Result<Vec<u8>, ResponseReadError> {
    // Get the content length from the response headers
    #[cfg(not(test))]
    let content_length = res.content_length();

    #[cfg(test)]
    let mut content_length = res.content_length();

    #[cfg(test)]
    if should_ignore_content_length() {
        // Used for testing purposes to ignore content length
        content_length = None;
    }

    // Break if content length is provided but it's too big
    if let Some(length) = content_length &&
        length as usize > max_size
    {
        return Err(ResponseReadError::PayloadTooLarge {
            max: max_size,
            content_length: length as usize,
            raw: String::new(), // raw content is not available here
        });
    }

    let mut stream = res.bytes_stream();
    let mut response_bytes = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if response_bytes.len() + chunk.len() > max_size {
            // avoid spamming logs if the message is too large
            response_bytes.truncate(1024);
            return Err(ResponseReadError::PayloadTooLarge {
                max: max_size,
                content_length: content_length.unwrap_or(0) as usize,
                raw: String::from_utf8_lossy(&response_bytes).into_owned(),
            });
        }

        response_bytes.extend_from_slice(&chunk);
    }

    Ok(response_bytes)
}

pub fn timestamp_of_slot_start_sec(slot: u64, chain: Chain) -> u64 {
    chain.genesis_time_sec() + slot * chain.slot_time_sec()
}
pub fn timestamp_of_slot_start_millis(slot: u64, chain: Chain) -> u64 {
    timestamp_of_slot_start_sec(slot, chain) * MILLIS_PER_SECOND
}
pub fn ms_into_slot(slot: u64, chain: Chain) -> u64 {
    let slot_start_ms = timestamp_of_slot_start_millis(slot, chain);
    utcnow_ms().saturating_sub(slot_start_ms)
}

/// Seconds
pub fn utcnow_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
/// Millis
pub fn utcnow_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}
/// Micros
pub fn utcnow_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}
/// Nanos
pub fn utcnow_ns() -> u64 {
    // safe until ~2554
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

pub const WEI_PER_ETH: u64 = 1_000_000_000_000_000_000;
pub fn eth_to_wei(eth: f64) -> U256 {
    U256::from((eth * WEI_PER_ETH as f64).floor())
}

// Serde
/// Test that the encoding and decoding works, returns the decoded struct
pub fn test_encode_decode<T: Serialize + DeserializeOwned>(d: &str) -> T {
    let decoded = serde_json::from_str::<T>(d).expect("deserialize");

    // re-encode to make sure that different formats are ignored
    let encoded = serde_json::to_string(&decoded).unwrap();
    let original_v: Value = serde_json::from_str(d).unwrap();
    let encoded_v: Value = serde_json::from_str(&encoded).unwrap();

    if original_v != encoded_v {
        println!("ORIGINAL: {original_v}");
        println!("ENCODED: {encoded_v}");
        panic!("encode mismatch");
    }

    decoded
}

pub fn test_encode_decode_ssz<T: Encode + Decode>(d: &[u8]) -> T {
    let decoded = T::from_ssz_bytes(d).expect("deserialize");
    let encoded = T::as_ssz_bytes(&decoded);

    assert_eq!(encoded, d);

    decoded
}

pub mod as_eth_str {
    use alloy::primitives::{
        U256,
        utils::{format_ether, parse_ether},
    };
    use serde::Deserialize;

    use super::eth_to_wei;

    pub fn serialize<S>(data: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = format_ether(*data);
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrF64 {
            Str(String),
            F64(f64),
        }

        let value = StringOrF64::deserialize(deserializer)?;
        let wei = match value {
            StringOrF64::Str(s) => {
                parse_ether(&s).map_err(|_| serde::de::Error::custom("invalid eth amount"))?
            }
            StringOrF64::F64(f) => eth_to_wei(f),
        };

        Ok(wei)
    }
}

pub const fn default_u64<const U: u64>() -> u64 {
    U
}

pub const fn default_u32<const U: u32>() -> u32 {
    U
}

pub const fn default_u16<const U: u16>() -> u16 {
    U
}

pub const fn default_bool<const U: bool>() -> bool {
    U
}

pub const fn default_host() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}

pub const fn default_u256() -> U256 {
    U256::ZERO
}

// LOGGING
pub fn initialize_tracing_log(
    module_id: &str,
    settings: LogsSettings,
) -> eyre::Result<(Option<WorkerGuard>, Option<WorkerGuard>)> {
    let format = Format::default().with_target(false).compact();

    let mut stdout_guard = None;
    let mut file_guard = None;
    let mut layers = Vec::new();

    if settings.stdout.enabled {
        let config = settings.stdout;

        let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
        stdout_guard = Some(guard);

        let filter = format_crates_filter(Level::INFO.as_str(), config.level.as_str());
        let format = format.clone().with_ansi(config.color);
        if config.use_json {
            let layer = Layer::default()
                .event_format(format)
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(false)
                .with_writer(writer)
                .with_filter(filter)
                .boxed();

            layers.push(layer);
        } else {
            let layer = Layer::default()
                .event_format(format)
                .with_writer(writer)
                .with_filter(filter)
                .boxed();

            layers.push(layer);
        }
    };

    if settings.file.enabled {
        let config = settings.file;

        let mut builder =
            tracing_appender::rolling::Builder::new().filename_prefix(module_id.to_lowercase());
        if let Some(value) = config.max_files {
            builder = builder.max_log_files(value);
        }
        let file_appender = builder
            .rotation(Rotation::DAILY)
            .build(config.dir_path)
            .expect("failed building rolling file appender");
        let (writer, guard) = tracing_appender::non_blocking(file_appender);
        file_guard = Some(guard);

        let filter = format_crates_filter(Level::INFO.as_str(), config.level.as_str());
        let format = format.clone().with_ansi(false);
        if config.use_json {
            let layer = Layer::default()
                .event_format(format)
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(false)
                .with_writer(writer)
                .with_filter(filter)
                .boxed();

            layers.push(layer);
        } else {
            let layer = Layer::default()
                .event_format(format)
                .with_writer(writer)
                .with_filter(filter)
                .boxed();

            layers.push(layer);
        }
    };

    tracing_subscriber::registry().with(layers).init();

    Ok((stdout_guard, file_guard))
}

// all commit boost crates
// TODO: this can probably done without unwrap
fn format_crates_filter(default_level: &str, crates_level: &str) -> EnvFilter {
    let s = format!(
        "{default_level},cb_signer={crates_level},cb_pbs={crates_level},cb_common={crates_level},cb_metrics={crates_level}",
    );
    s.parse().unwrap()
}

pub fn print_logo() {
    println!(
        r#"   ______                          _ __     ____                   __
  / ____/___  ____ ___  ____ ___  (_) /_   / __ )____  ____  _____/ /_
 / /   / __ \/ __ `__ \/ __ `__ \/ / __/  / __  / __ \/ __ \/ ___/ __/
/ /___/ /_/ / / / / / / / / / / / / /_   / /_/ / /_/ / /_/ (__  ) /_
\____/\____/_/ /_/ /_/_/ /_/ /_/_/\__/  /_____/\____/\____/____/\__/
                                                                      "#
    )
}

/// Create a JWT for the given module id with expiration
pub fn create_jwt(module_id: &ModuleId, secret: &str) -> eyre::Result<Jwt> {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &JwtClaims {
            module: module_id.to_string(),
            exp: jsonwebtoken::get_current_timestamp() + SIGNER_JWT_EXPIRATION,
        },
        &jsonwebtoken::EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(Into::into)
    .map(Jwt::from)
}

/// Decode a JWT and return the module id. IMPORTANT: This function does not
/// validate the JWT, it only obtains the module id from the claims.
pub fn decode_jwt(jwt: Jwt) -> eyre::Result<ModuleId> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.insecure_disable_signature_validation();

    let module = jsonwebtoken::decode::<JwtClaims>(
        jwt.as_str(),
        &jsonwebtoken::DecodingKey::from_secret(&[]),
        &validation,
    )?
    .claims
    .module
    .into();

    Ok(module)
}

/// Validate a JWT with the given secret
pub fn validate_jwt(jwt: Jwt, secret: &str) -> eyre::Result<()> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.leeway = 10;

    jsonwebtoken::decode::<JwtClaims>(
        jwt.as_str(),
        &jsonwebtoken::DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )
    .map(|_| ())
    .map_err(From::from)
}

/// Generates a random string
pub fn random_jwt_secret() -> String {
    rand::rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect()
}

/// Returns the user agent from the request headers or an empty string if not
/// present
pub fn get_user_agent(req_headers: &HeaderMap) -> String {
    req_headers
        .get(reqwest::header::USER_AGENT)
        .and_then(|ua| ua.to_str().ok().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Adds the commit boost version to the existing user agent
pub fn get_user_agent_with_version(req_headers: &HeaderMap) -> eyre::Result<HeaderValue> {
    let ua = get_user_agent(req_headers);
    Ok(HeaderValue::from_str(&format!("commit-boost/{HEADER_VERSION_VALUE} {ua}"))?)
}

/// Parse the ACCEPT header to get the type of response to encode the body with,
/// defaulting to JSON if missing. Returns an error if malformed or unsupported
/// types are requested. Supports requests with multiple ACCEPT headers or
/// headers with multiple media types.
pub fn get_accept_type(req_headers: &HeaderMap) -> eyre::Result<EncodingType> {
    let accept = Accept::from_str(
        req_headers.get(ACCEPT).and_then(|value| value.to_str().ok()).unwrap_or(APPLICATION_JSON),
    )
    .map_err(|e| eyre::eyre!("invalid accept header: {e}"))?;

    if accept.media_types().count() == 0 {
        // No valid media types found, default to JSON
        return Ok(EncodingType::Json);
    }

    // Get the SSZ and JSON media types if present
    let mut ssz_type = false;
    let mut json_type = false;
    let mut unsupported_type = false;
    accept.media_types().for_each(|mt| match mt.essence().to_string().as_str() {
        APPLICATION_OCTET_STREAM => ssz_type = true,
        APPLICATION_JSON | WILDCARD => json_type = true,
        _ => unsupported_type = true,
    });

    // If SSZ is present, prioritize it
    if ssz_type {
        return Ok(EncodingType::Ssz);
    }
    // If there aren't any unsupported types, use JSON
    if !unsupported_type {
        return Ok(EncodingType::Json);
    }
    Err(eyre::eyre!("unsupported accept type"))
}

/// Parse CONTENT TYPE header to get the encoding type of the body, defaulting
/// to JSON if missing or malformed.
pub fn get_content_type(req_headers: &HeaderMap) -> EncodingType {
    EncodingType::from_str(
        req_headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or(APPLICATION_JSON),
    )
    .unwrap_or(EncodingType::Json)
}

/// Parse CONSENSUS_VERSION header
pub fn get_consensus_version_header(req_headers: &HeaderMap) -> Option<ForkName> {
    ForkName::from_str(
        req_headers
            .get(CONSENSUS_VERSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or(""),
    )
    .ok()
}

/// Enum for types that can be used to encode incoming request bodies or
/// outgoing response bodies
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncodingType {
    /// Body is UTF-8 encoded as JSON
    Json,

    /// Body is raw bytes representing an SSZ object
    Ssz,
}

impl std::fmt::Display for EncodingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodingType::Json => write!(f, "application/json"),
            EncodingType::Ssz => write!(f, "application/octet-stream"),
        }
    }
}

impl FromStr for EncodingType {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "application/json" | "" => Ok(EncodingType::Json),
            "application/octet-stream" => Ok(EncodingType::Ssz),
            _ => Err(format!("unsupported encoding type: {value}")),
        }
    }
}

pub enum BodyDeserializeError {
    SerdeJsonError(serde_json::Error),
    SszDecodeError(ssz::DecodeError),
    UnsupportedMediaType,
}

impl Display for BodyDeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyDeserializeError::SerdeJsonError(e) => write!(f, "JSON deserialization error: {e}"),
            BodyDeserializeError::SszDecodeError(e) => {
                write!(f, "SSZ deserialization error: {e:?}")
            }
            BodyDeserializeError::UnsupportedMediaType => write!(f, "unsupported media type"),
        }
    }
}

pub async fn deserialize_body<T>(
    headers: &HeaderMap,
    body: Bytes,
) -> Result<T, BodyDeserializeError>
where
    T: serde::de::DeserializeOwned + ssz::Decode + 'static,
{
    if headers.contains_key(CONTENT_TYPE) {
        return match get_content_type(headers) {
            EncodingType::Json => {
                serde_json::from_slice::<T>(&body).map_err(BodyDeserializeError::SerdeJsonError)
            }
            EncodingType::Ssz => {
                T::from_ssz_bytes(&body).map_err(BodyDeserializeError::SszDecodeError)
            }
        };
    }

    Err(BodyDeserializeError::UnsupportedMediaType)
}

#[must_use]
#[derive(Debug, Clone, Default)]
pub struct RawRequest {
    pub body_bytes: Bytes,
}

impl<S> FromRequest<S> for RawRequest
where
    S: Send + Sync,
{
    type Rejection = AxumResponse;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, _state).await.map_err(IntoResponse::into_response)?;
        Ok(Self { body_bytes: bytes })
    }
}

#[cfg(unix)]
pub async fn wait_for_signal() -> eyre::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }

    Ok(())
}

#[cfg(windows)]
pub async fn wait_for_signal() -> eyre::Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

pub trait TestRandomSeed: TestRandom {
    fn test_random() -> Self
    where
        Self: Sized,
    {
        let mut rng = XorShiftRng::from_entropy();
        Self::random_for_test(&mut rng)
    }
}

impl<T: TestRandom> TestRandomSeed for T {}

pub fn bls_pubkey_from_hex(hex: &str) -> eyre::Result<BlsPublicKey> {
    let Ok(bytes) = hex::decode(hex) else {
        eyre::bail!("invalid hex pubkey: {hex}");
    };

    let pubkey = BlsPublicKey::deserialize(&bytes)
        .map_err(|e| eyre::eyre!("invalid hex pubkey: {hex}: {e:?}"))?;

    Ok(pubkey)
}

#[cfg(test)]
pub fn bls_pubkey_from_hex_unchecked(hex: &str) -> BlsPublicKey {
    bls_pubkey_from_hex(hex).unwrap()
}

#[cfg(test)]
mod test {
    use super::{create_jwt, decode_jwt, validate_jwt};
    use crate::types::{Jwt, ModuleId};

    #[test]
    fn test_jwt_validation() {
        // Check valid JWT
        let jwt = create_jwt(&ModuleId("DA_COMMIT".to_string()), "secret").unwrap();
        let module_id = decode_jwt(jwt.clone()).unwrap();
        assert_eq!(module_id, ModuleId("DA_COMMIT".to_string()));
        let response = validate_jwt(jwt, "secret");
        assert!(response.is_ok());

        // Check expired JWT
        let expired_jwt = Jwt::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NDI5OTU5NDYsIm1vZHVsZSI6IkRBX0NPTU1JVCJ9.iiq4Z2ed2hk3c3c-cn2QOQJWE5XUOc5BoaIPT-I8q-s".to_string());
        let response = validate_jwt(expired_jwt, "secret");
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().to_string(), "ExpiredSignature");

        // Check invalid signature JWT
        let invalid_jwt = Jwt::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NDI5OTU5NDYsIm1vZHVsZSI6IkRBX0NPTU1JVCJ9.w9WYdDNzgDjYTvjBkk4GGzywGNBYPxnzU2uJWzPUT1s".to_string());
        let response = validate_jwt(invalid_jwt, "secret");
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().to_string(), "InvalidSignature");
    }
}
