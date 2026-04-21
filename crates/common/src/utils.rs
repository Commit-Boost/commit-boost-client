#[cfg(feature = "testing-flags")]
use std::cell::Cell;
use std::{
    collections::HashMap,
    fmt::Display,
    net::Ipv4Addr,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::{
    hex,
    primitives::{U256, keccak256},
};
use axum::http::HeaderValue;
use bytes::Bytes;
use futures::StreamExt;
use headers_accept::Accept;
use lazy_static::lazy_static;
use lh_bls::Signature;
pub use lh_types::ForkName;
use lh_types::{
    BeaconBlock,
    test_utils::{SeedableRng, TestRandom, XorShiftRng},
};
use mediatype::{MediaType, ReadParams};
use rand::{Rng, distr::Alphanumeric};
use reqwest::{
    Response,
    header::{ACCEPT, CONTENT_TYPE, HeaderMap},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use ssz::{BYTES_PER_LENGTH_OFFSET, Decode, Encode};
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
    pbs::{
        BuilderBidBellatrix, BuilderBidCapella, BuilderBidDeneb, BuilderBidElectra, BuilderBidFulu,
        ExecutionPayloadHeaderBellatrix, ExecutionPayloadHeaderCapella,
        ExecutionPayloadHeaderDeneb, ExecutionPayloadHeaderElectra, ExecutionPayloadHeaderFulu,
        ExecutionRequests, HEADER_VERSION_VALUE, KzgCommitments, SignedBlindedBeaconBlock,
        error::SszValueError,
    },
    types::{BlsPublicKey, Chain, Jwt, JwtAdminClaims, JwtClaims, ModuleId},
};

pub const APPLICATION_JSON: &str = "application/json";
pub const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
pub const WILDCARD: &str = "*/*";

const MILLIS_PER_SECOND: u64 = 1_000;
pub const CONSENSUS_VERSION_HEADER: &str = "Eth-Consensus-Version";

lazy_static! {
    static ref SSZ_VALUE_OFFSETS_BY_FORK: HashMap<ForkName, usize> = {
        let mut map: HashMap<ForkName, usize> = HashMap::new();
        let forks = [
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
        ];
        for fork in forks {
            let offset = get_ssz_value_offset_for_fork(fork).unwrap(); // If there isn't a supported fork, this needs to be updated prior to release so panicking is fine
            map.insert(fork, offset);
        }
        map
    };
}

#[derive(Debug, Error)]
pub enum ResponseReadError {
    #[error(
        "response size exceeds max size; max: {max}, content_length: {content_length}, raw: {raw}"
    )]
    PayloadTooLarge { max: usize, content_length: usize, raw: String },

    #[error("error reading response stream: {0}")]
    ReqwestError(#[from] reqwest::Error),
}

#[cfg(feature = "testing-flags")]
thread_local! {
    static IGNORE_CONTENT_LENGTH: Cell<bool> = const { Cell::new(false) };
}

#[cfg(feature = "testing-flags")]
pub fn set_ignore_content_length(val: bool) {
    IGNORE_CONTENT_LENGTH.with(|f| f.set(val));
}

#[cfg(feature = "testing-flags")]
#[allow(dead_code)]
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
    #[cfg(not(feature = "testing-flags"))]
    let content_length = res.content_length();

    #[cfg(feature = "testing-flags")]
    let mut content_length = res.content_length();

    #[cfg(feature = "testing-flags")]
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
pub fn create_jwt(
    module_id: &ModuleId,
    secret: &str,
    route: &str,
    payload: Option<&[u8]>,
) -> eyre::Result<Jwt> {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &JwtClaims {
            module: module_id.clone(),
            route: route.to_string(),
            exp: jsonwebtoken::get_current_timestamp() + SIGNER_JWT_EXPIRATION,
            payload_hash: payload.map(keccak256),
        },
        &jsonwebtoken::EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(Into::into)
    .map(Jwt::from)
}

// Creates a JWT for module administration
pub fn create_admin_jwt(
    admin_secret: String,
    route: &str,
    payload: Option<&[u8]>,
) -> eyre::Result<Jwt> {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &JwtAdminClaims {
            admin: true,
            route: route.to_string(),
            exp: jsonwebtoken::get_current_timestamp() + SIGNER_JWT_EXPIRATION,
            payload_hash: payload.map(keccak256),
        },
        &jsonwebtoken::EncodingKey::from_secret(admin_secret.as_ref()),
    )
    .map_err(Into::into)
    .map(Jwt::from)
}

/// Decode a JWT and return the JWT claims. IMPORTANT: This function does not
/// validate the JWT, it only obtains the claims.
pub fn decode_jwt(jwt: Jwt) -> eyre::Result<JwtClaims> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.insecure_disable_signature_validation();

    let claims = jsonwebtoken::decode::<JwtClaims>(
        jwt.as_str(),
        &jsonwebtoken::DecodingKey::from_secret(&[]),
        &validation,
    )?
    .claims;

    Ok(claims)
}

/// Decode an administrator JWT and return the JWT claims. IMPORTANT: This
/// function does not validate the JWT, it only obtains the claims.
pub fn decode_admin_jwt(jwt: Jwt) -> eyre::Result<JwtAdminClaims> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.insecure_disable_signature_validation();

    let claims = jsonwebtoken::decode::<JwtAdminClaims>(
        jwt.as_str(),
        &jsonwebtoken::DecodingKey::from_secret(&[]),
        &validation,
    )?
    .claims;

    Ok(claims)
}

pub fn validate_jwt(
    jwt: Jwt,
    secret: &str,
    route: &str,
    payload: Option<&[u8]>,
) -> eyre::Result<()> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.leeway = 10;

    let claims = jsonwebtoken::decode::<JwtClaims>(
        jwt.as_str(),
        &jsonwebtoken::DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )?
    .claims;

    // Validate the route
    if claims.route != route {
        eyre::bail!("Token route does not match");
    }

    // Validate the payload hash if provided
    if let Some(payload_bytes) = payload {
        if let Some(expected_hash) = claims.payload_hash {
            let actual_hash = keccak256(payload_bytes);
            if actual_hash != expected_hash {
                eyre::bail!("Payload hash does not match");
            }
        } else {
            eyre::bail!("JWT does not contain a payload hash");
        }
    } else if claims.payload_hash.is_some() {
        eyre::bail!("JWT contains a payload hash but no payload was provided");
    }
    Ok(())
}

pub fn validate_admin_jwt(
    jwt: Jwt,
    secret: &str,
    route: &str,
    payload: Option<&[u8]>,
) -> eyre::Result<()> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.leeway = 10;

    let claims = jsonwebtoken::decode::<JwtAdminClaims>(
        jwt.as_str(),
        &jsonwebtoken::DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )?
    .claims;

    if !claims.admin {
        eyre::bail!("Token is not admin")
    }

    // Validate the route
    if claims.route != route {
        eyre::bail!("Token route does not match");
    }

    // Validate the payload hash if provided
    if let Some(payload_bytes) = payload {
        if let Some(expected_hash) = claims.payload_hash {
            let actual_hash = keccak256(payload_bytes);
            if actual_hash != expected_hash {
                eyre::bail!("Payload hash does not match");
            }
        } else {
            eyre::bail!("JWT does not contain a payload hash");
        }
    } else if claims.payload_hash.is_some() {
        eyre::bail!("JWT contains a payload hash but no payload was provided");
    }
    Ok(())
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

/// Deterministic outbound `Accept` header used when PBS asks a relay for a
/// response it will itself decode (validation mode On/Extra). SSZ is preferred
/// for wire efficiency. Emitted verbatim so packet captures and support
/// tickets are reproducible.
pub const OUTBOUND_ACCEPT: &str = "application/octet-stream;q=1.0,application/json;q=0.9";

/// Encodings the original requester is willing to accept, in descending
/// preference order.
///
/// The builder spec defines exactly two media types (SSZ and JSON), so after
/// dedup the accepted set is at most one primary plus one optional fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedEncodings {
    /// Caller's highest-preference encoding.
    pub primary: EncodingType,
    /// Second-choice encoding, if the caller provided one.
    pub fallback: Option<EncodingType>,
}

impl AcceptedEncodings {
    pub const fn single(primary: EncodingType) -> Self {
        Self { primary, fallback: None }
    }

    pub fn contains(self, enc: EncodingType) -> bool {
        self.primary == enc || self.fallback == Some(enc)
    }

    /// Iterate in preference order: primary first, then fallback (if any).
    pub fn iter(self) -> impl Iterator<Item = EncodingType> {
        std::iter::once(self.primary).chain(self.fallback)
    }

    /// Pick the caller's highest-preference encoding that the server supports.
    /// Returns `None` if no overlap exists.
    pub fn preferred(self, supported: &[EncodingType]) -> Option<EncodingType> {
        self.iter().find(|a| supported.contains(a))
    }
}

impl IntoIterator for AcceptedEncodings {
    type Item = EncodingType;
    type IntoIter =
        std::iter::Chain<std::iter::Once<EncodingType>, std::option::IntoIter<EncodingType>>;
    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(self.primary).chain(self.fallback)
    }
}

/// Parse the ACCEPT header into a q-value ordered [`AcceptedEncodings`]
/// (highest preference first, deduplicated), defaulting to the request's
/// Content-Type when no Accept header is present. Returns an error only if
/// every media type in the header is malformed or unsupported. Supports
/// requests with multiple ACCEPT headers or headers with multiple media
/// types. `q=0` entries are treated as explicit rejections per RFC 7231
/// §5.3.1 and are skipped.
///
/// The returned order honors the RFC 9110 §12.5.1 precedence rules already
/// applied by `headers_accept::Accept::media_types()` (specificity, then
/// q-value, then original order).
pub fn get_accept_types(req_headers: &HeaderMap) -> eyre::Result<AcceptedEncodings> {
    // Only two supported media types, so the ordered set is at most two
    // entries: primary + optional fallback.
    let mut primary: Option<EncodingType> = None;
    let mut fallback: Option<EncodingType> = None;
    let mut saw_any = false;
    let mut had_supported = false;
    for header in req_headers.get_all(ACCEPT).iter() {
        let accept = Accept::from_str(header.to_str()?)
            .map_err(|e| eyre::eyre!("invalid accept header: {e}"))?;
        for mt in accept.media_types() {
            saw_any = true;

            // Skip q=0 entries — RFC 7231 §5.3.1: "A request without any Accept
            // header field implies that the user agent will accept any media
            // type in response.  When a header field is present ... a value of
            // 0 means 'not acceptable'."
            if let Some(q) = mt.get_param(mediatype::names::Q) &&
                q.as_str().parse::<f32>().is_ok_and(|v| v <= 0.0)
            {
                continue;
            }

            let parsed = match mt.essence().to_string().as_str() {
                APPLICATION_OCTET_STREAM => Some(EncodingType::Ssz),
                APPLICATION_JSON | WILDCARD => Some(EncodingType::Json),
                _ => None,
            };
            if let Some(enc) = parsed {
                had_supported = true;
                match primary {
                    None => primary = Some(enc),
                    Some(p) if p != enc && fallback.is_none() => fallback = Some(enc),
                    _ => {}
                }
            }
        }
    }

    if let Some(primary) = primary {
        return Ok(AcceptedEncodings { primary, fallback });
    }

    if saw_any && !had_supported {
        return Err(eyre::eyre!("unsupported accept type"));
    }

    // No accept header (or only q=0 rejections): fall back to the request
    // Content-Type, which mirrors the historical behavior.
    Ok(AcceptedEncodings::single(get_content_type(req_headers)))
}

/// Compute the q-value for the `index`-th preferred encoding when building an
/// outbound `Accept` header. The first entry gets q=1.0, each subsequent entry
/// decreases by 0.1, and the value is clamped to a minimum of 0.1 so we never
/// emit q=0 (which per RFC 7231 §5.3.1 means "not acceptable").
fn accept_q_value_for_index(index: usize) -> f32 {
    // `as i32` would silently wrap for large indices (e.g. usize::MAX → -1),
    // which would invert the clamp. Saturate the cast explicitly.
    let idx = i32::try_from(index).unwrap_or(i32::MAX);
    let step = 10_i32.saturating_sub(idx).max(1);
    step as f32 / 10.0
}

/// Format a single `Accept` header entry as `"<media-type>;q=<x.x>"`.
fn format_accept_entry(enc: EncodingType, q: f32) -> String {
    format!("{};q={:.1}", enc.content_type(), q)
}

/// Build an `Accept` header string that mirrors the caller's preference order
/// so the relay sees the same priority the beacon node asked us for. Each
/// subsequent entry receives a q-value 0.1 lower than the previous one,
/// starting at 1.0.
pub fn build_outbound_accept(preferred: AcceptedEncodings) -> String {
    preferred
        .iter()
        .enumerate()
        .map(|(i, enc)| format_accept_entry(enc, accept_q_value_for_index(i)))
        .collect::<Vec<_>>()
        .join(",")
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingType {
    Json,
    Ssz,
}

impl EncodingType {
    pub fn content_type(&self) -> &str {
        match self {
            EncodingType::Json => APPLICATION_JSON,
            EncodingType::Ssz => APPLICATION_OCTET_STREAM,
        }
    }
}

impl std::fmt::Display for EncodingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.content_type())
    }
}

impl FromStr for EncodingType {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // Preserve prior behavior: empty defaults to JSON (used by
        // `get_content_type` when Content-Type header is absent).
        if value.is_empty() {
            return Ok(EncodingType::Json);
        }
        // Parse as a media type so we tolerate RFC 7231 §3.1.1.1 parameters
        // (e.g. `application/json; charset=utf-8`). Compare essence only.
        let parsed =
            MediaType::parse(value).map_err(|e| format!("invalid content type {value}: {e}"))?;
        match parsed.essence().to_string().to_ascii_lowercase().as_str() {
            APPLICATION_JSON => Ok(EncodingType::Json),
            APPLICATION_OCTET_STREAM => Ok(EncodingType::Ssz),
            _ => Err(format!("unsupported encoding type: {value}")),
        }
    }
}

/// Parse the Content-Type and Eth-Consensus-Version headers from a relay
/// response, returning the encoding to use for body decoding and the
/// optional fork name. Tolerates MIME parameters per RFC 7231 §3.1.1.1 and
/// defaults to JSON when no Content-Type header is present (matching legacy
/// relay behavior). `code` is the HTTP status of the response and is echoed
/// back in any `PbsError::RelayResponse` this function produces, so callers
/// can surface the original status on decode failure.
pub fn parse_response_encoding_and_fork(
    headers: &HeaderMap,
    code: u16,
) -> Result<(EncodingType, Option<ForkName>), crate::pbs::error::PbsError> {
    use crate::pbs::error::PbsError;
    let content_type = match headers.get(CONTENT_TYPE) {
        // Assume missing Content-Type means JSON; shouldn't happen in
        // practice but just in case.
        None => EncodingType::Json,
        Some(hv) => {
            let header_str = hv.to_str().map_err(|e| PbsError::RelayResponse {
                error_msg: format!("cannot decode content-type header: {e}"),
                code,
            })?;
            EncodingType::from_str(header_str)
                .map_err(|msg| PbsError::RelayResponse { error_msg: msg, code })?
        }
    };
    Ok((content_type, get_consensus_version_header(headers)))
}

pub enum BodyDeserializeError {
    SerdeJsonError(serde_json::Error),
    SszDecodeError(ssz::DecodeError),
    UnsupportedMediaType,
    MissingVersionHeader,
}

impl Display for BodyDeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyDeserializeError::SerdeJsonError(e) => write!(f, "JSON deserialization error: {e}"),
            BodyDeserializeError::SszDecodeError(e) => {
                write!(f, "SSZ deserialization error: {e:?}")
            }
            BodyDeserializeError::UnsupportedMediaType => write!(f, "unsupported media type"),
            BodyDeserializeError::MissingVersionHeader => {
                write!(f, "missing consensus version header")
            }
        }
    }
}

pub async fn deserialize_body(
    headers: &HeaderMap,
    body: Bytes,
) -> Result<SignedBlindedBeaconBlock, BodyDeserializeError> {
    if headers.contains_key(CONTENT_TYPE) {
        return match get_content_type(headers) {
            EncodingType::Json => serde_json::from_slice::<SignedBlindedBeaconBlock>(&body)
                .map_err(BodyDeserializeError::SerdeJsonError),
            EncodingType::Ssz => {
                // Get the version header
                match get_consensus_version_header(headers) {
                    Some(version) => {
                        SignedBlindedBeaconBlock::from_ssz_bytes_with(&body, |bytes| {
                            BeaconBlock::from_ssz_bytes_for_fork(bytes, version)
                        })
                        .map_err(BodyDeserializeError::SszDecodeError)
                    }
                    None => Err(BodyDeserializeError::MissingVersionHeader),
                }
            }
        };
    }

    Err(BodyDeserializeError::UnsupportedMediaType)
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
        let mut rng = XorShiftRng::from_os_rng();
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

// Get the offset of the message in a SignedBuilderBid SSZ structure
fn get_ssz_value_offset_for_fork(fork: ForkName) -> Option<usize> {
    match fork {
        ForkName::Bellatrix => {
            // Message goes header -> value -> pubkey
            Some(
                get_message_offset::<BuilderBidBellatrix>() +
                    <ExecutionPayloadHeaderBellatrix as ssz::Decode>::ssz_fixed_len(),
            )
        }

        ForkName::Capella => {
            // Message goes header -> value -> pubkey
            Some(
                get_message_offset::<BuilderBidCapella>() +
                    <ExecutionPayloadHeaderCapella as ssz::Decode>::ssz_fixed_len(),
            )
        }

        ForkName::Deneb => {
            // Message goes header -> blob_kzg_commitments -> value -> pubkey
            Some(
                get_message_offset::<BuilderBidDeneb>() +
                    <ExecutionPayloadHeaderDeneb as ssz::Decode>::ssz_fixed_len() +
                    <KzgCommitments as ssz::Decode>::ssz_fixed_len(),
            )
        }

        ForkName::Electra => {
            // Message goes header -> blob_kzg_commitments -> execution_requests -> value ->
            // pubkey
            Some(
                get_message_offset::<BuilderBidElectra>() +
                    <ExecutionPayloadHeaderElectra as ssz::Decode>::ssz_fixed_len() +
                    <KzgCommitments as ssz::Decode>::ssz_fixed_len() +
                    <ExecutionRequests as ssz::Decode>::ssz_fixed_len(),
            )
        }

        ForkName::Fulu => {
            // Message goes header -> blob_kzg_commitments -> execution_requests -> value ->
            // pubkey
            Some(
                get_message_offset::<BuilderBidFulu>() +
                    <ExecutionPayloadHeaderFulu as ssz::Decode>::ssz_fixed_len() +
                    <KzgCommitments as ssz::Decode>::ssz_fixed_len() +
                    <ExecutionRequests as ssz::Decode>::ssz_fixed_len(),
            )
        }

        _ => None,
    }
}

/// Extracts the bid value from SSZ-encoded SignedBuilderBid response bytes.
pub fn get_bid_value_from_signed_builder_bid_ssz(
    response_bytes: &[u8],
    fork: ForkName,
) -> Result<U256, SszValueError> {
    let value_offset = SSZ_VALUE_OFFSETS_BY_FORK
        .get(&fork)
        .ok_or(SszValueError::UnsupportedFork { name: fork.to_string() })?;

    // Sanity check the response length so we don't panic trying to slice it
    let end_offset = value_offset + 32; // U256 is 32 bytes
    if response_bytes.len() < end_offset {
        return Err(SszValueError::InvalidPayloadLength {
            required: end_offset,
            actual: response_bytes.len(),
        });
    }

    // Extract the value bytes and convert to U256
    let value_bytes = &response_bytes[*value_offset..end_offset];
    let value = U256::from_le_slice(value_bytes);
    Ok(value)
}

// Get the offset where the `message` field starts in some SignedBuilderBid SSZ
// data. Requires that SignedBuilderBid always has the following structure:
// message -> signature
// where `message` is a BuilderBid type determined by the fork choice, and
// `signature` is a fixed-length Signature type.
fn get_message_offset<BuilderBidType>() -> usize
where
    BuilderBidType: ssz::Encode,
{
    // Since `message` is the first field, its offset is always 0
    let mut offset = 0;

    // If it's variable length, then it will be represented by a pointer to
    // the actual data, so we need to get the location of where that data starts
    if !BuilderBidType::is_ssz_fixed_len() {
        offset += BYTES_PER_LENGTH_OFFSET + <Signature as ssz::Decode>::ssz_fixed_len();
    }

    offset
}

#[cfg(test)]
mod test {
    use alloy::primitives::keccak256;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use bytes::Bytes;
    use reqwest::header::{ACCEPT, CONTENT_TYPE};

    use super::{
        AcceptedEncodings, BodyDeserializeError, CONSENSUS_VERSION_HEADER, OUTBOUND_ACCEPT,
        accept_q_value_for_index, build_outbound_accept, create_admin_jwt, create_jwt,
        decode_admin_jwt, decode_jwt, deserialize_body, format_accept_entry,
        get_consensus_version_header, get_content_type, parse_response_encoding_and_fork,
        random_jwt_secret, validate_admin_jwt, validate_jwt,
    };
    use crate::{
        constants::SIGNER_JWT_EXPIRATION,
        pbs::error::SszValueError,
        types::{Jwt, JwtAdminClaims, ModuleId},
        utils::{
            APPLICATION_JSON, APPLICATION_OCTET_STREAM, EncodingType, ForkName, WILDCARD,
            get_accept_types, get_bid_value_from_signed_builder_bid_ssz,
        },
    };

    const APPLICATION_TEXT: &str = "application/text";

    #[test]
    fn test_jwt_validation_no_payload_hash() {
        // Check valid JWT
        let jwt =
            create_jwt(&ModuleId("DA_COMMIT".to_string()), "secret", "/test/route", None).unwrap();
        let claims = decode_jwt(jwt.clone()).unwrap();
        let module_id = claims.module;
        let payload_hash = claims.payload_hash;
        assert_eq!(module_id, ModuleId("DA_COMMIT".to_string()));
        assert!(payload_hash.is_none());
        let response = validate_jwt(jwt, "secret", "/test/route", None);
        assert!(response.is_ok());

        // Check expired JWT
        let expired_jwt = Jwt::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NTgyOTkxNzIsIm1vZHVsZSI6IkRBX0NPTU1JVCIsInJvdXRlIjoiL3Rlc3Qvcm91dGUiLCJwYXlsb2FkX2hhc2giOm51bGx9._OBsNC67KLkk6f6ZQ2_CDbhYUJ2OtZ9egKAmi1L-ymA".to_string());
        let response = validate_jwt(expired_jwt, "secret", "/test/route", None);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().to_string(), "ExpiredSignature");

        // Check invalid signature JWT
        let invalid_jwt = Jwt::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NTgyOTkxMzQsIm1vZHVsZSI6IkRBX0NPTU1JVCIsInJvdXRlIjoiL3Rlc3Qvcm91dGUiLCJwYXlsb2FkX2hhc2giOm51bGx9.58QXayg2XeX5lXhIPw-a8kl04DWBEj5wBsqsedTeClo".to_string());
        let response = validate_jwt(invalid_jwt, "secret", "/test/route", None);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().to_string(), "InvalidSignature");
    }

    /// Make sure a missing Accept header is interpreted as JSON
    #[test]
    fn test_missing_accept_header() {
        let headers = HeaderMap::new();
        let result = get_accept_types(&headers).unwrap();
        assert_eq!(result, AcceptedEncodings::single(EncodingType::Json));
    }

    /// Test accepting JSON
    #[test]
    fn test_accept_header_json() {
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(APPLICATION_JSON).unwrap());
        let result = get_accept_types(&headers).unwrap();
        assert_eq!(result, AcceptedEncodings::single(EncodingType::Json));
    }

    /// Test accepting SSZ
    #[test]
    fn test_accept_header_ssz() {
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(APPLICATION_OCTET_STREAM).unwrap());
        let result = get_accept_types(&headers).unwrap();
        assert_eq!(result, AcceptedEncodings::single(EncodingType::Ssz));
    }

    /// Test accepting wildcards
    #[test]
    fn test_accept_header_wildcard() {
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(WILDCARD).unwrap());
        let result = get_accept_types(&headers).unwrap();
        assert_eq!(result, AcceptedEncodings::single(EncodingType::Json));
    }

    /// Test accepting one header with multiple values (order preserved,
    /// first listed wins at equal q)
    #[test]
    fn test_accept_header_multiple_values() {
        let header_string = format!("{APPLICATION_JSON}, {APPLICATION_OCTET_STREAM}");
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(&header_string).unwrap());
        let result = get_accept_types(&headers).unwrap();
        assert_eq!(result, AcceptedEncodings {
            primary: EncodingType::Json,
            fallback: Some(EncodingType::Ssz)
        });
    }

    /// Test accepting multiple headers
    #[test]
    fn test_multiple_accept_headers() {
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(APPLICATION_JSON).unwrap());
        headers.append(ACCEPT, HeaderValue::from_str(APPLICATION_OCTET_STREAM).unwrap());
        let result = get_accept_types(&headers).unwrap();
        assert!(result.contains(EncodingType::Json));
        assert!(result.contains(EncodingType::Ssz));
        assert!(result.fallback.is_some());
    }

    /// Test accepting one header with multiple values, including a type that
    /// can't be used
    #[test]
    fn test_accept_header_multiple_values_including_unknown() {
        let header_string =
            format!("{APPLICATION_JSON}, {APPLICATION_OCTET_STREAM}, {APPLICATION_TEXT}");
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(&header_string).unwrap());
        let result = get_accept_types(&headers).unwrap();
        assert_eq!(result, AcceptedEncodings {
            primary: EncodingType::Json,
            fallback: Some(EncodingType::Ssz)
        });
    }

    /// Test rejecting an unknown accept type
    #[test]
    fn test_invalid_accept_header_type() {
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(APPLICATION_TEXT).unwrap());
        let result = get_accept_types(&headers);
        assert!(result.is_err());
    }

    /// Test accepting one header with multiple values
    #[test]
    fn test_accept_header_invalid_parse() {
        let header_string = format!("{APPLICATION_JSON}, a?;ef)");
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(&header_string).unwrap());
        let result = get_accept_types(&headers);
        assert!(result.is_err());
    }

    /// q-values are honored: JSON@1.0 should outrank SSZ@0.1 regardless of
    /// byte order in the header.
    #[test]
    fn test_accept_header_q_value_ordering() {
        let mut headers = HeaderMap::new();
        headers.append(
            ACCEPT,
            HeaderValue::from_str("application/json;q=1.0, application/octet-stream;q=0.1")
                .unwrap(),
        );
        assert_eq!(get_accept_types(&headers).unwrap(), AcceptedEncodings {
            primary: EncodingType::Json,
            fallback: Some(EncodingType::Ssz)
        });

        let mut headers = HeaderMap::new();
        headers.append(
            ACCEPT,
            HeaderValue::from_str("application/octet-stream;q=0.1, application/json;q=1.0")
                .unwrap(),
        );
        assert_eq!(get_accept_types(&headers).unwrap(), AcceptedEncodings {
            primary: EncodingType::Json,
            fallback: Some(EncodingType::Ssz)
        });
    }

    /// q=0 is an explicit rejection per RFC 7231 §5.3.1 and must be dropped.
    #[test]
    fn test_accept_header_q_zero_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            ACCEPT,
            HeaderValue::from_str("application/json, application/octet-stream;q=0").unwrap(),
        );
        assert_eq!(
            get_accept_types(&headers).unwrap(),
            AcceptedEncodings::single(EncodingType::Json)
        );
    }

    /// An Accept header containing only q=0 for every supported type is a
    /// deliberate "I accept nothing" and must error (so the route can return
    /// 406 Not Acceptable per RFC 7231 §5.3.1 and §6.5.6).
    #[test]
    fn test_accept_header_only_q_zero_errors() {
        let mut headers = HeaderMap::new();
        headers.append(
            ACCEPT,
            HeaderValue::from_str("application/json;q=0, application/octet-stream;q=0").unwrap(),
        );
        assert!(get_accept_types(&headers).is_err());
    }

    /// `AcceptedEncodings::preferred` picks the caller's first choice that
    /// the server can actually produce.
    #[test]
    fn test_preferred_encoding_picks_highest_q_match() {
        let accepts =
            AcceptedEncodings { primary: EncodingType::Json, fallback: Some(EncodingType::Ssz) };
        let supported = [EncodingType::Ssz, EncodingType::Json];
        assert_eq!(accepts.preferred(&supported), Some(EncodingType::Json));

        let accepts = AcceptedEncodings::single(EncodingType::Ssz);
        let supported = [EncodingType::Json];
        assert_eq!(accepts.preferred(&supported), None);
    }

    /// Outbound Accept should be deterministic and q-ordered to match caller
    /// preference.
    #[test]
    fn test_build_outbound_accept_deterministic() {
        let ssz_then_json =
            AcceptedEncodings { primary: EncodingType::Ssz, fallback: Some(EncodingType::Json) };
        let json_then_ssz =
            AcceptedEncodings { primary: EncodingType::Json, fallback: Some(EncodingType::Ssz) };
        assert_eq!(
            build_outbound_accept(ssz_then_json),
            "application/octet-stream;q=1.0,application/json;q=0.9"
        );
        assert_eq!(
            build_outbound_accept(json_then_ssz),
            "application/json;q=1.0,application/octet-stream;q=0.9"
        );

        // Stable across repeats
        for _ in 0..100 {
            assert_eq!(
                build_outbound_accept(ssz_then_json),
                "application/octet-stream;q=1.0,application/json;q=0.9"
            );
        }
    }

    /// `AcceptedEncodings::single` produces a primary with no fallback.
    #[test]
    fn test_accepted_encodings_single() {
        let a = AcceptedEncodings::single(EncodingType::Ssz);
        assert_eq!(a.primary, EncodingType::Ssz);
        assert_eq!(a.fallback, None);
    }

    /// `contains` checks both primary and fallback.
    #[test]
    fn test_accepted_encodings_contains() {
        let only_ssz = AcceptedEncodings::single(EncodingType::Ssz);
        assert!(only_ssz.contains(EncodingType::Ssz));
        assert!(!only_ssz.contains(EncodingType::Json));

        let both =
            AcceptedEncodings { primary: EncodingType::Ssz, fallback: Some(EncodingType::Json) };
        assert!(both.contains(EncodingType::Ssz));
        assert!(both.contains(EncodingType::Json));
    }

    /// `iter` yields primary first, then fallback if present. Single-value
    /// instances yield exactly one element.
    #[test]
    fn test_accepted_encodings_iter_order() {
        let both =
            AcceptedEncodings { primary: EncodingType::Json, fallback: Some(EncodingType::Ssz) };
        assert_eq!(both.iter().collect::<Vec<_>>(), vec![EncodingType::Json, EncodingType::Ssz]);

        let only = AcceptedEncodings::single(EncodingType::Ssz);
        assert_eq!(only.iter().collect::<Vec<_>>(), vec![EncodingType::Ssz]);
    }

    /// `IntoIterator` matches `iter`: preference order preserved, fallback
    /// included only when present.
    #[test]
    fn test_accepted_encodings_into_iterator() {
        let both =
            AcceptedEncodings { primary: EncodingType::Ssz, fallback: Some(EncodingType::Json) };
        let collected: Vec<_> = both.into_iter().collect();
        assert_eq!(collected, vec![EncodingType::Ssz, EncodingType::Json]);

        let only = AcceptedEncodings::single(EncodingType::Json);
        let collected: Vec<_> = only.into_iter().collect();
        assert_eq!(collected, vec![EncodingType::Json]);
    }

    /// Duplicate media types in an Accept header are deduplicated — the
    /// second occurrence of `primary` must not populate `fallback`.
    #[test]
    fn test_accept_header_duplicate_dedups() {
        let header_string = format!("{APPLICATION_JSON}, {APPLICATION_JSON}");
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(&header_string).unwrap());
        assert_eq!(
            get_accept_types(&headers).unwrap(),
            AcceptedEncodings::single(EncodingType::Json)
        );
    }

    /// Once primary and fallback are filled, further supported entries must
    /// not overwrite fallback. (Belt-and-suspenders — only two supported
    /// variants exist today, so this is mostly a guard against future
    /// regressions if a third variant is added.)
    #[test]
    fn test_accept_header_third_supported_entry_ignored() {
        // Repeat SSZ to simulate a third supported-but-duplicate entry
        // landing after primary+fallback are already set.
        let header_string =
            format!("{APPLICATION_JSON}, {APPLICATION_OCTET_STREAM}, {APPLICATION_JSON}");
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(&header_string).unwrap());
        assert_eq!(get_accept_types(&headers).unwrap(), AcceptedEncodings {
            primary: EncodingType::Json,
            fallback: Some(EncodingType::Ssz),
        });
    }

    /// Unsupported media types interleaved with supported ones must not
    /// occupy the primary or fallback slots.
    #[test]
    fn test_accept_header_unsupported_does_not_fill_fallback() {
        let header_string = format!("{APPLICATION_TEXT}, {APPLICATION_JSON}");
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(&header_string).unwrap());
        // `saw_any = true` and `had_supported = true`, so we return the
        // supported type as primary with no fallback.
        assert_eq!(
            get_accept_types(&headers).unwrap(),
            AcceptedEncodings::single(EncodingType::Json)
        );
    }

    /// `build_outbound_accept` on a single-value `AcceptedEncodings` emits
    /// exactly one entry at q=1.0 (no trailing comma, no orphan fallback).
    #[test]
    fn test_build_outbound_accept_single_value() {
        let only_ssz = AcceptedEncodings::single(EncodingType::Ssz);
        assert_eq!(build_outbound_accept(only_ssz), "application/octet-stream;q=1.0");

        let only_json = AcceptedEncodings::single(EncodingType::Json);
        assert_eq!(build_outbound_accept(only_json), "application/json;q=1.0");
    }

    /// `preferred` walks the caller's preference order and returns the
    /// first supported match — not the server's first choice.
    #[test]
    fn test_preferred_respects_caller_order_over_server_order() {
        // Caller prefers JSON first. Server lists SSZ first. Caller wins.
        let accepts =
            AcceptedEncodings { primary: EncodingType::Json, fallback: Some(EncodingType::Ssz) };
        assert_eq!(
            accepts.preferred(&[EncodingType::Ssz, EncodingType::Json]),
            Some(EncodingType::Json)
        );
    }

    /// Snapshot test: constant emits exactly what we document in
    /// OUTBOUND_ACCEPT.
    #[test]
    fn test_outbound_accept_constant_snapshot() {
        assert_eq!(OUTBOUND_ACCEPT, "application/octet-stream;q=1.0,application/json;q=0.9");
    }

    /// q-value ladder: first entry is 1.0, each subsequent entry drops by 0.1.
    #[test]
    fn test_accept_q_value_for_index_ladder() {
        assert!((accept_q_value_for_index(0) - 1.0).abs() < f32::EPSILON);
        assert!((accept_q_value_for_index(1) - 0.9).abs() < f32::EPSILON);
        assert!((accept_q_value_for_index(5) - 0.5).abs() < f32::EPSILON);
        assert!((accept_q_value_for_index(9) - 0.1).abs() < f32::EPSILON);
    }

    /// Clamp at 0.1: we never emit q=0 (which per RFC 7231 §5.3.1 would mean
    /// "not acceptable").
    #[test]
    fn test_accept_q_value_for_index_clamps_to_minimum() {
        assert!((accept_q_value_for_index(10) - 0.1).abs() < f32::EPSILON);
        assert!((accept_q_value_for_index(100) - 0.1).abs() < f32::EPSILON);
        // Even an adversarial usize::MAX must not underflow or drop to zero.
        assert!((accept_q_value_for_index(usize::MAX) - 0.1).abs() < f32::EPSILON);
    }

    /// Entry formatter emits the spec-shaped string.
    #[test]
    fn test_format_accept_entry_shape() {
        assert_eq!(format_accept_entry(EncodingType::Ssz, 1.0), "application/octet-stream;q=1.0");
        assert_eq!(format_accept_entry(EncodingType::Json, 0.9), "application/json;q=0.9");
        // One decimal place, even when the value has more precision.
        assert_eq!(format_accept_entry(EncodingType::Json, 0.12345), "application/json;q=0.1");
    }

    #[test]
    fn test_jwt_validation_with_payload() {
        // Pretend payload
        let payload = serde_json::json!({
            "data": "test"
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        // Check valid JWT
        let jwt = create_jwt(
            &ModuleId("DA_COMMIT".to_string()),
            "secret",
            "/test/route",
            Some(&payload_bytes),
        )
        .unwrap();
        let claims = decode_jwt(jwt.clone()).unwrap();
        let module_id = claims.module;
        let payload_hash = claims.payload_hash;
        assert_eq!(module_id, ModuleId("DA_COMMIT".to_string()));
        assert_eq!(payload_hash, Some(keccak256(&payload_bytes)));
        let response = validate_jwt(jwt, "secret", "/test/route", Some(&payload_bytes));
        assert!(response.is_ok());

        // Check expired JWT
        let expired_jwt = Jwt::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NTgyOTgzNDQsIm1vZHVsZSI6IkRBX0NPTU1JVCIsInJvdXRlIjoiL3Rlc3Qvcm91dGUiLCJwYXlsb2FkX2hhc2giOiIweGFmODk2MjY0MzUzNTFmYzIwMDBkYmEwM2JiNTlhYjcyZWE0ODJiOWEwMDBmZWQzNmNkMjBlMDU0YjE2NjZmZjEifQ.PYrSxLXadKBgYZlmLam8RBSL32I1T_zAxlZpG6xnnII".to_string());
        let response = validate_jwt(expired_jwt, "secret", "/test/route", Some(&payload_bytes));
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().to_string(), "ExpiredSignature");

        // Check invalid signature JWT
        let invalid_jwt = Jwt::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NTgyOTkwMDAsIm1vZHVsZSI6IkRBX0NPTU1JVCIsInJvdXRlIjoiL3Rlc3Qvcm91dGUiLCJwYXlsb2FkX2hhc2giOiIweGFmODk2MjY0MzUzNTFmYzIwMDBkYmEwM2JiNTlhYjcyZWE0ODJiOWEwMDBmZWQzNmNkMjBlMDU0YjE2NjZmZjEifQ.mnC-AexkLlR9l98SJbln3DmV6r9XyHYdbjcUVcWdi_8".to_string());
        let response = validate_jwt(invalid_jwt, "secret", "/test/route", Some(&payload_bytes));
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().to_string(), "InvalidSignature");
    }

    // ── validate_jwt: route and secret errors ────────────────────────────────

    #[test]
    fn test_validate_jwt_wrong_route() {
        let jwt = create_jwt(&ModuleId("MOD".into()), "secret", "/correct/route", None).unwrap();
        let err = validate_jwt(jwt, "secret", "/wrong/route", None).unwrap_err();
        assert!(err.to_string().contains("Token route does not match"));
    }

    #[test]
    fn test_validate_jwt_wrong_secret() {
        let jwt = create_jwt(&ModuleId("MOD".into()), "correct_secret", "/route", None).unwrap();
        let err = validate_jwt(jwt, "wrong_secret", "/route", None).unwrap_err();
        assert_eq!(err.to_string(), "InvalidSignature");
    }

    // ── validate_jwt: payload hash mismatch branches ─────────────────────────

    #[test]
    fn test_validate_jwt_payload_hash_mismatch() {
        let payload_a = b"payload_a";
        let payload_b = b"payload_b";
        let jwt = create_jwt(&ModuleId("MOD".into()), "secret", "/route", Some(payload_a)).unwrap();
        let err = validate_jwt(jwt, "secret", "/route", Some(payload_b)).unwrap_err();
        assert!(err.to_string().contains("Payload hash does not match"));
    }

    #[test]
    fn test_validate_jwt_hash_present_but_no_payload_provided() {
        let payload = b"some payload";
        let jwt = create_jwt(&ModuleId("MOD".into()), "secret", "/route", Some(payload)).unwrap();
        let err = validate_jwt(jwt, "secret", "/route", None).unwrap_err();
        assert!(
            err.to_string().contains("JWT contains a payload hash but no payload was provided")
        );
    }

    #[test]
    fn test_validate_jwt_no_hash_but_payload_provided() {
        let jwt = create_jwt(&ModuleId("MOD".into()), "secret", "/route", None).unwrap();
        let err = validate_jwt(jwt, "secret", "/route", Some(b"unexpected")).unwrap_err();
        assert!(err.to_string().contains("JWT does not contain a payload hash"));
    }

    // ── admin JWT roundtrip ──────────────────────────────────────────────────

    #[test]
    fn test_admin_jwt_roundtrip_no_payload() {
        let jwt = create_admin_jwt("admin_secret".into(), "/admin/route", None).unwrap();
        let claims = decode_admin_jwt(jwt.clone()).unwrap();
        assert!(claims.admin);
        assert_eq!(claims.route, "/admin/route");
        assert!(claims.payload_hash.is_none());
        validate_admin_jwt(jwt, "admin_secret", "/admin/route", None).unwrap();
    }

    #[test]
    fn test_admin_jwt_roundtrip_with_payload() {
        let payload = b"admin payload";
        let jwt = create_admin_jwt("admin_secret".into(), "/admin/route", Some(payload)).unwrap();
        let claims = decode_admin_jwt(jwt.clone()).unwrap();
        assert!(claims.admin);
        assert_eq!(claims.payload_hash, Some(keccak256(payload)));
        validate_admin_jwt(jwt, "admin_secret", "/admin/route", Some(payload)).unwrap();
    }

    // ── validate_admin_jwt: route, secret, admin flag errors ─────────────────

    #[test]
    fn test_validate_admin_jwt_wrong_route() {
        let jwt = create_admin_jwt("admin_secret".into(), "/correct/route", None).unwrap();
        let err = validate_admin_jwt(jwt, "admin_secret", "/wrong/route", None).unwrap_err();
        assert!(err.to_string().contains("Token route does not match"));
    }

    #[test]
    fn test_validate_admin_jwt_wrong_secret() {
        let jwt = create_admin_jwt("correct_secret".into(), "/route", None).unwrap();
        let err = validate_admin_jwt(jwt, "wrong_secret", "/route", None).unwrap_err();
        assert_eq!(err.to_string(), "InvalidSignature");
    }

    #[test]
    fn test_validate_admin_jwt_admin_false() {
        // Craft a JWT whose claims have admin: false — something create_admin_jwt
        // never produces — to exercise the explicit admin flag guard.
        let claims = JwtAdminClaims {
            admin: false,
            route: "/route".into(),
            exp: jsonwebtoken::get_current_timestamp() + SIGNER_JWT_EXPIRATION,
            payload_hash: None,
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        let jwt = Jwt::from(token);
        let err = validate_admin_jwt(jwt, "secret", "/route", None).unwrap_err();
        assert!(err.to_string().contains("Token is not admin"));
    }

    // ── validate_admin_jwt: payload hash mismatch branches ───────────────────

    #[test]
    fn test_validate_admin_jwt_payload_hash_mismatch() {
        let payload_a = b"admin_payload_a";
        let payload_b = b"admin_payload_b";
        let jwt = create_admin_jwt("secret".into(), "/route", Some(payload_a)).unwrap();
        let err = validate_admin_jwt(jwt, "secret", "/route", Some(payload_b)).unwrap_err();
        assert!(err.to_string().contains("Payload hash does not match"));
    }

    #[test]
    fn test_validate_admin_jwt_hash_present_but_no_payload_provided() {
        let payload = b"admin payload";
        let jwt = create_admin_jwt("secret".into(), "/route", Some(payload)).unwrap();
        let err = validate_admin_jwt(jwt, "secret", "/route", None).unwrap_err();
        assert!(
            err.to_string().contains("JWT contains a payload hash but no payload was provided")
        );
    }

    #[test]
    fn test_validate_admin_jwt_no_hash_but_payload_provided() {
        let jwt = create_admin_jwt("secret".into(), "/route", None).unwrap();
        let err = validate_admin_jwt(jwt, "secret", "/route", Some(b"unexpected")).unwrap_err();
        assert!(err.to_string().contains("JWT does not contain a payload hash"));
    }

    // ── random_jwt_secret ────────────────────────────────────────────────────

    #[test]
    fn test_random_jwt_secret() {
        let secret = random_jwt_secret();
        assert_eq!(secret.len(), 32);
        assert!(secret.chars().all(|c| c.is_ascii_alphanumeric()));
        // Two calls should produce distinct values with overwhelming probability.
        assert_ne!(secret, random_jwt_secret());
    }

    // ── get_content_type ─────────────────────────────────────────────────────

    #[test]
    fn test_content_type_missing_defaults_to_json() {
        let headers = HeaderMap::new();
        assert_eq!(get_content_type(&headers), EncodingType::Json);
    }

    #[test]
    fn test_content_type_json() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(APPLICATION_JSON).unwrap());
        assert_eq!(get_content_type(&headers), EncodingType::Json);
    }

    #[test]
    fn test_content_type_ssz() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(APPLICATION_OCTET_STREAM).unwrap());
        assert_eq!(get_content_type(&headers), EncodingType::Ssz);
    }

    #[test]
    fn test_content_type_unknown_defaults_to_json() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/xml").unwrap());
        assert_eq!(get_content_type(&headers), EncodingType::Json);
    }

    // ── get_consensus_version_header ─────────────────────────────────────────

    #[test]
    fn test_consensus_version_header_electra() {
        let mut headers = HeaderMap::new();
        let name = HeaderName::try_from(CONSENSUS_VERSION_HEADER).unwrap();
        headers.insert(name, HeaderValue::from_str("electra").unwrap());
        assert_eq!(get_consensus_version_header(&headers), Some(ForkName::Electra));
    }

    #[test]
    fn test_consensus_version_header_missing() {
        let headers = HeaderMap::new();
        assert_eq!(get_consensus_version_header(&headers), None);
    }

    #[test]
    fn test_consensus_version_header_invalid() {
        let mut headers = HeaderMap::new();
        let name = HeaderName::try_from(CONSENSUS_VERSION_HEADER).unwrap();
        headers.insert(name, HeaderValue::from_str("not_a_fork").unwrap());
        assert_eq!(get_consensus_version_header(&headers), None);
    }

    // ── EncodingType ─────────────────────────────────────────────────────────

    #[test]
    fn test_encoding_type_from_str_variants() {
        use std::str::FromStr;
        assert_eq!(EncodingType::from_str(APPLICATION_JSON).unwrap(), EncodingType::Json);
        assert_eq!(EncodingType::from_str(APPLICATION_OCTET_STREAM).unwrap(), EncodingType::Ssz);
        // empty string defaults to JSON per the impl
        assert_eq!(EncodingType::from_str("").unwrap(), EncodingType::Json);
        assert!(EncodingType::from_str("application/xml").is_err());
    }

    #[test]
    fn test_encoding_type_from_str_with_mime_params() {
        // RFC 7231 §3.1.1.1: media-type parameters must be tolerated.
        // Relays behind proxies routinely add charset= and similar.
        use std::str::FromStr;
        assert_eq!(
            EncodingType::from_str("application/json; charset=utf-8").unwrap(),
            EncodingType::Json
        );
        assert_eq!(
            EncodingType::from_str("application/octet-stream; boundary=x").unwrap(),
            EncodingType::Ssz
        );
        // Case-insensitivity per RFC 7231: type/subtype are lowercased before
        // comparison.
        assert_eq!(EncodingType::from_str("APPLICATION/OCTET-STREAM").unwrap(), EncodingType::Ssz);
        // Extra whitespace around parameters is tolerated by the MIME parser.
        assert_eq!(
            EncodingType::from_str("application/json;charset=utf-8").unwrap(),
            EncodingType::Json
        );
        // Garbage that can't parse as a media type is an error.
        assert!(EncodingType::from_str("garbage").is_err());
        // A parseable media type that isn't one we support is an error.
        assert!(EncodingType::from_str("text/plain").is_err());
    }

    #[test]
    fn test_parse_response_encoding_and_fork_tolerates_mime_params() {
        // Full integration of the helper: missing header defaults to JSON,
        // present header with params still decodes correctly.
        let mut headers = HeaderMap::new();
        let (enc, fork) = parse_response_encoding_and_fork(&headers, 200).unwrap();
        assert_eq!(enc, EncodingType::Json);
        assert!(fork.is_none());

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str("application/octet-stream; charset=binary").unwrap(),
        );
        let (enc, _) = parse_response_encoding_and_fork(&headers, 200).unwrap();
        assert_eq!(enc, EncodingType::Ssz);

        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/xml").unwrap());
        let err = parse_response_encoding_and_fork(&headers, 415).unwrap_err();
        match err {
            crate::pbs::error::PbsError::RelayResponse { code, .. } => assert_eq!(code, 415),
            other => panic!("expected RelayResponse, got {other:?}"),
        }
    }

    #[test]
    fn test_encoding_type_display() {
        assert_eq!(EncodingType::Json.to_string(), APPLICATION_JSON);
        assert_eq!(EncodingType::Ssz.to_string(), APPLICATION_OCTET_STREAM);
    }

    // ── get_bid_value_from_signed_builder_bid_ssz ────────────────────────────

    #[test]
    fn test_ssz_value_extraction_unsupported_fork() {
        let dummy_bytes = vec![0u8; 1000];
        let err =
            get_bid_value_from_signed_builder_bid_ssz(&dummy_bytes, ForkName::Altair).unwrap_err();
        assert!(matches!(err, SszValueError::UnsupportedFork { .. }));
    }

    #[test]
    fn test_ssz_value_extraction_truncated_payload() {
        // A payload that is far too short for any supported fork's value offset
        let tiny_bytes = vec![0u8; 4];
        let err =
            get_bid_value_from_signed_builder_bid_ssz(&tiny_bytes, ForkName::Electra).unwrap_err();
        assert!(matches!(err, SszValueError::InvalidPayloadLength { .. }));
    }

    /// Per-fork positive tests: construct a `SignedBuilderBid` with a known
    /// value for each supported fork, SSZ-encode it, and verify
    /// `get_bid_value_from_signed_builder_bid_ssz` round-trips correctly.
    #[test]
    fn test_ssz_value_extraction_with_known_bid() {
        use alloy::primitives::U256;
        use ssz::Encode;

        use crate::{
            pbs::{
                BuilderBid, BuilderBidBellatrix, BuilderBidCapella, BuilderBidDeneb,
                BuilderBidElectra, BuilderBidFulu, ExecutionPayloadHeaderBellatrix,
                ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb,
                ExecutionPayloadHeaderElectra, ExecutionPayloadHeaderFulu, ExecutionRequests,
                SignedBuilderBid,
            },
            types::{BlsPublicKeyBytes, BlsSignature},
            utils::TestRandomSeed,
        };

        // Distinctive value — large enough that endianness bugs produce a
        // different number and zero-matches are impossible.
        let known_value = U256::from(0x0102_0304_0506_0708_u64);
        let pubkey = BlsPublicKeyBytes::test_random();
        let sig = BlsSignature::test_random();

        // ── Bellatrix ────────────────────────────────────────────────────────
        {
            let message = BuilderBid::Bellatrix(BuilderBidBellatrix {
                header: ExecutionPayloadHeaderBellatrix::test_random(),
                value: known_value,
                pubkey,
            });
            let bid = SignedBuilderBid { message, signature: sig.clone() };
            let got =
                get_bid_value_from_signed_builder_bid_ssz(&bid.as_ssz_bytes(), ForkName::Bellatrix)
                    .expect("Bellatrix extraction failed");
            assert_eq!(got, known_value, "Bellatrix: value mismatch");
        }

        // ── Capella ──────────────────────────────────────────────────────────
        {
            let message = BuilderBid::Capella(BuilderBidCapella {
                header: ExecutionPayloadHeaderCapella::test_random(),
                value: known_value,
                pubkey,
            });
            let bid = SignedBuilderBid { message, signature: sig.clone() };
            let got =
                get_bid_value_from_signed_builder_bid_ssz(&bid.as_ssz_bytes(), ForkName::Capella)
                    .expect("Capella extraction failed");
            assert_eq!(got, known_value, "Capella: value mismatch");
        }

        // ── Deneb ────────────────────────────────────────────────────────────
        {
            let message = BuilderBid::Deneb(BuilderBidDeneb {
                header: ExecutionPayloadHeaderDeneb::test_random(),
                blob_kzg_commitments: Default::default(),
                value: known_value,
                pubkey,
            });
            let bid = SignedBuilderBid { message, signature: sig.clone() };
            let got =
                get_bid_value_from_signed_builder_bid_ssz(&bid.as_ssz_bytes(), ForkName::Deneb)
                    .expect("Deneb extraction failed");
            assert_eq!(got, known_value, "Deneb: value mismatch");
        }

        // ── Electra ──────────────────────────────────────────────────────────
        {
            let message = BuilderBid::Electra(BuilderBidElectra {
                header: ExecutionPayloadHeaderElectra::test_random(),
                blob_kzg_commitments: Default::default(),
                execution_requests: ExecutionRequests::default(),
                value: known_value,
                pubkey,
            });
            let bid = SignedBuilderBid { message, signature: sig.clone() };
            let got =
                get_bid_value_from_signed_builder_bid_ssz(&bid.as_ssz_bytes(), ForkName::Electra)
                    .expect("Electra extraction failed");
            assert_eq!(got, known_value, "Electra: value mismatch");
        }

        // ── Fulu ─────────────────────────────────────────────────────────────
        {
            let message = BuilderBid::Fulu(BuilderBidFulu {
                header: ExecutionPayloadHeaderFulu::test_random(),
                blob_kzg_commitments: Default::default(),
                execution_requests: ExecutionRequests::default(),
                value: known_value,
                pubkey,
            });
            let bid = SignedBuilderBid { message, signature: sig };
            let got =
                get_bid_value_from_signed_builder_bid_ssz(&bid.as_ssz_bytes(), ForkName::Fulu)
                    .expect("Fulu extraction failed");
            assert_eq!(got, known_value, "Fulu: value mismatch");
        }
    }

    // ── deserialize_body error paths ─────────────────────────────────────────

    #[tokio::test]
    async fn test_deserialize_body_missing_content_type() {
        let headers = HeaderMap::new();
        let body = Bytes::from_static(b"{}");
        let err = deserialize_body(&headers, body).await.unwrap_err();
        assert!(matches!(err, BodyDeserializeError::UnsupportedMediaType));
    }

    #[tokio::test]
    async fn test_deserialize_body_ssz_missing_version_header() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(APPLICATION_OCTET_STREAM).unwrap());
        let body = Bytes::from_static(b"\x00\x01\x02\x03");
        let err = deserialize_body(&headers, body).await.unwrap_err();
        assert!(matches!(err, BodyDeserializeError::MissingVersionHeader));
    }
}
