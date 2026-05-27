#[cfg(feature = "testing-flags")]
use std::cell::Cell;
use std::str::FromStr;

use axum::http::HeaderValue;
use bytes::Bytes;
use futures::StreamExt;
use headers_accept::Accept;
use lh_types::{BeaconBlock, ForkName};
use mediatype::{MediaType, ReadParams};
use reqwest::{
    Response,
    header::{ACCEPT, CONTENT_TYPE, HeaderMap},
};
use thiserror::Error;

use crate::pbs::{HEADER_VERSION_VALUE, SignedBlindedBeaconBlock};

pub const APPLICATION_JSON: &str = "application/json";
pub const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
pub const WILDCARD: &str = "*/*";
pub const CONSENSUS_VERSION_HEADER: &str = "Eth-Consensus-Version";

#[derive(Debug, Error)]
pub enum ResponseReadError {
    #[error(
        "response size exceeds max size; max: {max}, content_length: {content_length}, request_url: {request_url}"
    )]
    PayloadTooLarge { max: usize, content_length: usize, request_url: String },

    #[error("error reading response stream: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error(
        "request failed with status: {status_code}, request_url: {request_url}, body: {error_msg}"
    )]
    NonSuccess { status_code: u16, error_msg: String, request_url: String },
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
    request_url: &str,
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
            request_url: request_url.to_string(),
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
                request_url: request_url.to_string(),
            });
        }

        response_bytes.extend_from_slice(&chunk);
    }

    Ok(response_bytes)
}

/// Reads an HTTP response body with a size limit, erroring on non-success
/// status or read failure.
pub async fn safe_read_http_response(
    response: reqwest::Response,
    max_size: usize,
) -> Result<Vec<u8>, ResponseReadError> {
    let status_code = response.status();
    let request_url = response.url().to_string();
    let body = read_chunked_body_with_max(response, max_size, &request_url).await?;
    if status_code.is_success() {
        Ok(body)
    } else {
        Err(ResponseReadError::NonSuccess {
            status_code: status_code.as_u16(),
            error_msg: String::from_utf8_lossy(&body).into_owned(),
            request_url: request_url.to_string(),
        })
    }
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

/// Default encoding used when the caller does not express a format
/// preference. This covers both `Accept: */*` (see `get_accept_types`) and
/// a missing Content-Type header on inbound or relay responses (see
/// `parse_response_encoding_and_fork` and `deserialize_body`). Keeping the
/// policy in one place prevents drift between those sites.
pub const NO_PREFERENCE_DEFAULT: EncodingType = EncodingType::Json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedEncodings {
    pub primary: EncodingType,
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
                APPLICATION_JSON => Some(EncodingType::Json),
                WILDCARD => Some(NO_PREFERENCE_DEFAULT),
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
        eyre::bail!("unsupported accept type");
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
#[inline]
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

pub fn get_content_type(req_headers: &HeaderMap) -> EncodingType {
    EncodingType::from_str(
        req_headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or(APPLICATION_JSON),
    )
    .unwrap_or(EncodingType::Json)
}

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

    /// Pre-built `Content-Type` header for this encoding.
    pub fn content_type_header(&self) -> &'static HeaderValue {
        static JSON_HEADER: HeaderValue = HeaderValue::from_static(APPLICATION_JSON);
        static SSZ_HEADER: HeaderValue = HeaderValue::from_static(APPLICATION_OCTET_STREAM);
        match self {
            EncodingType::Json => &JSON_HEADER,
            EncodingType::Ssz => &SSZ_HEADER,
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
        // No Content-Type: apply the shared no-preference default
        None => NO_PREFERENCE_DEFAULT,
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

#[derive(Debug, Error)]
pub enum BodyDeserializeError {
    #[error("JSON deserialization error: {0}")]
    SerdeJsonError(serde_json::Error),
    #[error("SSZ deserialization error: {0:?}")]
    SszDecodeError(ssz::DecodeError),
    #[error("unsupported media type")]
    UnsupportedMediaType,
    #[error("missing consensus version header")]
    MissingVersionHeader,
}

pub fn deserialize_body(
    headers: &HeaderMap,
    body: Bytes,
) -> Result<SignedBlindedBeaconBlock, BodyDeserializeError> {
    // Determine the encoding to decode with. Precedence:
    //   - Content-Type absent     → NO_PREFERENCE_DEFAULT
    //   - Content-Type recognized → use it.
    //   - Content-Type present but unrecognized → UnsupportedMediaType.
    let encoding = match headers.get(CONTENT_TYPE) {
        None => NO_PREFERENCE_DEFAULT,
        Some(hv) => {
            let value = hv.to_str().map_err(|_| BodyDeserializeError::UnsupportedMediaType)?;
            EncodingType::from_str(value).map_err(|_| BodyDeserializeError::UnsupportedMediaType)?
        }
    };

    match encoding {
        EncodingType::Json => serde_json::from_slice::<SignedBlindedBeaconBlock>(&body)
            .map_err(BodyDeserializeError::SerdeJsonError),
        EncodingType::Ssz => match get_consensus_version_header(headers) {
            Some(version) => SignedBlindedBeaconBlock::from_ssz_bytes_with(&body, |bytes| {
                BeaconBlock::from_ssz_bytes_for_fork(bytes, version)
            })
            .map_err(BodyDeserializeError::SszDecodeError),
            None => Err(BodyDeserializeError::MissingVersionHeader),
        },
    }
}

#[cfg(test)]
mod test {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use bytes::Bytes;
    use lh_types::ForkName;
    use reqwest::header::{ACCEPT, CONTENT_TYPE};

    use super::{
        APPLICATION_JSON, APPLICATION_OCTET_STREAM, AcceptedEncodings, BodyDeserializeError,
        CONSENSUS_VERSION_HEADER, EncodingType, NO_PREFERENCE_DEFAULT, OUTBOUND_ACCEPT, WILDCARD,
        accept_q_value_for_index, build_outbound_accept, deserialize_body, format_accept_entry,
        get_accept_types, get_consensus_version_header, get_content_type,
        parse_response_encoding_and_fork,
    };

    const APPLICATION_TEXT: &str = "application/text";

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

    /// Wildcard `Accept: */*` resolves to the `NO_PREFERENCE_DEFAULT`
    /// policy. Separate from the explicit
    /// `Accept: application/json` path to keep the two intents distinct.
    #[test]
    fn test_accept_header_wildcard() {
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_str(WILDCARD).unwrap());
        let result = get_accept_types(&headers).unwrap();
        assert_eq!(result, AcceptedEncodings::single(NO_PREFERENCE_DEFAULT));
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
            fallback: Some(EncodingType::Ssz)
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

    // ── deserialize_body error paths ─────────────────────────────────────────

    /// Missing Content-Type falls back to the `NO_PREFERENCE_DEFAULT` (JSON)
    /// path, matching pre-PR behavior. Garbage body reaches the JSON
    /// decoder and errors as `SerdeJsonError`, proving the default kicked
    /// in (vs. bailing early with `UnsupportedMediaType`).
    #[tokio::test]
    async fn test_deserialize_body_missing_content_type_falls_back_to_json() {
        let headers = HeaderMap::new();
        let body = Bytes::from_static(b"not json");
        let err = deserialize_body(&headers, body).unwrap_err();
        assert!(
            matches!(err, BodyDeserializeError::SerdeJsonError(_)),
            "expected SerdeJsonError (JSON decode attempted), got: {err}"
        );
    }

    /// Present-but-unrecognized Content-Type still bails as
    /// `UnsupportedMediaType`; the fallback only covers *missing* headers.
    #[tokio::test]
    async fn test_deserialize_body_unrecognized_content_type() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        let body = Bytes::from_static(b"hi");
        let err = deserialize_body(&headers, body).unwrap_err();
        assert!(matches!(err, BodyDeserializeError::UnsupportedMediaType));
    }

    #[tokio::test]
    async fn test_deserialize_body_ssz_missing_version_header() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(APPLICATION_OCTET_STREAM).unwrap());
        let body = Bytes::from_static(b"\x00\x01\x02\x03");
        let err = deserialize_body(&headers, body).unwrap_err();
        assert!(matches!(err, BodyDeserializeError::MissingVersionHeader));
    }
}
