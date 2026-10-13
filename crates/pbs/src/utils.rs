use std::{
    future::Future,
    time::{Duration, Instant},
};

use alloy::primitives::utils::{ParseUnits, Unit};
use axum::body::Bytes;
use cb_common::{
    pbs::{HEADER_VERSION_KEY, RelayClient, decode_auth_data_url, error::PbsError},
    types::BlsPublicKey,
    wire::{
        CONSENSUS_VERSION_HEADER, EncodingType, GLOAS_CONSENSUS_VERSION,
        get_user_agent_with_version, read_chunked_body_with_max,
    },
};
use futures::future::join_all;
use reqwest::{
    Response, StatusCode,
    header::{CONTENT_TYPE, HOST, HeaderMap, USER_AGENT},
};
use tracing::{Instrument, debug, error, warn};
use url::Url;

use crate::{
    constants::{MAX_SIZE_DEFAULT, TIMEOUT_ERROR_CODE_STR},
    dial::{auth_data_address, dial_relay, host_url},
    error::PbsClientError,
    metrics::{BEACON_NODE_STATUS, RELAY_LATENCY, RELAY_STATUS_CODE},
};

/// Sends one already-built relay request, recording the per-relay metrics
/// shared by all three ePBS endpoints, and returns the response and its latency
/// so the caller can read/decode the body itself. `tag` is the per-endpoint
/// metric label. Callers build their own `RequestBuilder` because the requests
/// legitimately differ (bid sets a per-call timeout and timing headers).
pub(crate) async fn send_to_relay(
    req: reqwest::RequestBuilder,
    relay: &RelayClient,
    tag: &str,
) -> Result<(reqwest::Response, Duration), PbsError> {
    let start_request = Instant::now();
    let res = match req.send().await {
        Ok(res) => res,
        Err(err) => {
            RELAY_STATUS_CODE.with_label_values(&[TIMEOUT_ERROR_CODE_STR, tag, &relay.id]).inc();
            return Err(err.into());
        }
    };

    let request_latency = start_request.elapsed();
    RELAY_LATENCY.with_label_values(&[tag, &relay.id]).observe(request_latency.as_secs_f64());

    let code = res.status();
    RELAY_STATUS_CODE.with_label_values(&[code.as_str(), tag, &relay.id]).inc();

    Ok((res, request_latency))
}

pub(crate) fn record_beacon_status(code: &str, endpoint: &str) {
    BEACON_NODE_STATUS.with_label_values(&[code, endpoint]).inc();
}

/// Logs and counts a failed ePBS request before it is returned to the beacon
/// node. A 4xx is the caller's fault, not CB's: only a 5xx is an error.
pub(crate) fn record_request_failure(
    err: impl Into<PbsClientError>,
    endpoint: &str,
) -> PbsClientError {
    let err = err.into();
    if err.status_code().is_server_error() {
        error!(%err, "{endpoint} failed");
    } else {
        warn!(%err, "{endpoint} failed");
    }
    record_beacon_status(err.status_code().as_str(), endpoint);
    err
}

/// Fans `sends` out on detached tasks and waits for all of them
pub(crate) async fn join_detached_sends<F>(
    sends: impl IntoIterator<Item = F>,
) -> impl Iterator<Item = Result<(), PbsError>>
where
    F: Future<Output = Result<(), PbsError>> + Send + 'static,
{
    let handles: Vec<_> =
        sends.into_iter().map(|send| tokio::spawn(send.in_current_span())).collect();
    join_all(handles)
        .await
        .into_iter()
        .map(|joined| joined.unwrap_or_else(|err| Err(PbsError::TokioJoinError(err))))
}

pub(crate) fn log_mux_selection(
    maybe_mux_id: Option<&str>,
    relay_count: usize,
    pubkey: &BlsPublicKey,
) {
    match maybe_mux_id {
        Some(mux_id) => {
            debug!(mux_id, relays = relay_count, pubkey = %pubkey, "using mux config")
        }
        None => debug!(relays = relay_count, pubkey = %pubkey, "using default config"),
    }
}

/// POSTs `body` in `encoding` to a builder and returns the latency; 202 is the
/// only success
pub(crate) async fn post_expect_accepted(
    relay: &RelayClient,
    url: Url,
    body: Bytes,
    encoding: EncodingType,
    headers: HeaderMap,
    timeout_ms: u64,
    tag: &str,
) -> Result<Duration, PbsError> {
    let req = relay
        .client
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers)
        .header(CONTENT_TYPE, encoding.content_type_header().clone())
        .body(body);
    let (res, latency) = send_to_relay(req, relay, tag).await?;
    if res.status() == StatusCode::ACCEPTED {
        return Ok(latency);
    }
    Err(relay_response_error(res, "expected 202").await)
}

/// A failed builder response as an error; a body over the cap still reports the
/// status
pub(crate) async fn relay_response_error(res: Response, if_empty: &str) -> PbsError {
    let code = res.status().as_u16();
    let url = res.url().to_string();
    let error_msg = match read_chunked_body_with_max(res, MAX_SIZE_DEFAULT, &url).await {
        Ok(body) if !body.is_empty() => String::from_utf8_lossy(&body).into_owned(),
        Ok(_) => if_empty.to_string(),
        Err(err) => err.to_string(),
    };
    PbsError::RelayResponse { error_msg, code }
}

/// A gwei amount in ETH, for logs
pub(crate) fn format_gwei_as_eth(gwei: u64) -> String {
    ParseUnits::from(gwei).format_units(Unit::GWEI)
}

/// The builder's own 400 or 401, handed back to the proposer; any other relay
/// failure is the caller's to map.
pub(crate) fn builder_rejection(err: &PbsError) -> Option<PbsClientError> {
    match err.relay_status_code() {
        Some(400) => Some(PbsClientError::BuilderRejected(StatusCode::BAD_REQUEST)),
        Some(401) => Some(PbsClientError::BuilderRejected(StatusCode::UNAUTHORIZED)),
        _ => None,
    }
}

/// Headers every ePBS relay request carries: the versioned `User-Agent`, and
/// `Eth-Consensus-Version`, which the route has validated as Gloas
pub(crate) fn epbs_base_send_headers(req_headers: &HeaderMap) -> Result<HeaderMap, PbsClientError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        get_user_agent_with_version(req_headers).map_err(|_| PbsClientError::Internal)?,
    );
    headers.insert(CONSENSUS_VERSION_HEADER, GLOAS_CONSENSUS_VERSION.clone());
    Ok(headers)
}

const GAS_LIMIT_ADJUSTMENT_FACTOR: u64 = 1024;
const GAS_LIMIT_MINIMUM: u64 = 5_000;

/// Validates the gas limit against the parent gas limit, according to the
/// execution spec https://github.com/ethereum/execution-specs/blob/98d6ddaaa709a2b7d0cd642f4cfcdadc8c0808e1/src/ethereum/cancun/fork.py#L1118-L1154
pub fn check_gas_limit(gas_limit: u64, parent_gas_limit: u64) -> bool {
    let max_adjustment_delta = parent_gas_limit / GAS_LIMIT_ADJUSTMENT_FACTOR;
    if gas_limit >= parent_gas_limit + max_adjustment_delta {
        return false;
    }

    if gas_limit <= parent_gas_limit - max_adjustment_delta {
        return false;
    }

    if gas_limit < GAS_LIMIT_MINIMUM {
        return false;
    }

    true
}

/// The relay `auth_data` names among `relays`, then `default_relays`, else a
/// dial to it if `dial_unconfigured_builders`, with what the dial's setup left
/// of `timeout_ms`
pub(crate) async fn resolve_addressed_relay(
    relays: &[RelayClient],
    default_relays: &[RelayClient],
    dial_unconfigured_builders: bool,
    auth_data: &[u8],
    req_headers: &HeaderMap,
    timeout_ms: u64,
) -> Result<(RelayClient, u64), PbsClientError> {
    let address = auth_data_address(auth_data);
    let data_url = decode_auth_data_url(address);
    // A relay configured for other keys is reached with its own settings rather
    // than dialed without them
    if let Some(relay) = relays
        .iter()
        .chain(default_relays)
        .find(|relay| names_relay(relay, address, data_url.as_ref()))
    {
        return Ok((relay.clone(), timeout_ms));
    }
    if !dial_unconfigured_builders {
        warn!(
            auth_data = ?String::from_utf8_lossy(auth_data),
            "auth data matches no configured relay and dial_unconfigured_builders is off, not dialing"
        );
        return Err(PbsClientError::AuthDataMismatch);
    }
    // Every Commit-Boost dial carries this header, so a request dialed back into
    // a Commit-Boost, this one included, goes no further
    if req_headers.contains_key(HEADER_VERSION_KEY) {
        warn!(
            auth_data = ?String::from_utf8_lossy(auth_data),
            "auth data matches no configured relay and the request came from a Commit-Boost, not dialing on"
        );
        return Err(PbsClientError::AuthDataMismatch);
    }
    // A key without builder config sends this Commit-Boost's host, which a dial
    // would reach on port 443, not here
    if is_request_host(req_headers, address) {
        warn!(
            auth_data = ?String::from_utf8_lossy(auth_data),
            "auth data names the host this request was sent to, not dialing"
        );
        return Err(PbsClientError::AuthDataMismatch);
    }
    let started = Instant::now();
    let relay = dial_relay(data_url, address, Duration::from_millis(timeout_ms)).await?;
    let left_ms = timeout_ms.saturating_sub(started.elapsed().as_millis() as u64);
    // A request with no time left would still reach the builder
    if left_ms == 0 {
        return Err(PbsClientError::NoBuilderResponse);
    }
    Ok((relay, left_ms))
}

/// Whether `address` is the relay's hostname or, as a URL, its scheme, host and
/// port
fn names_relay(relay: &RelayClient, address: &[u8], data_url: Option<&Url>) -> bool {
    let url = &relay.config.entry.url;
    match data_url {
        None => url.host_str().is_some_and(|host| host.as_bytes() == address),
        Some(data_url) => {
            url.scheme() == data_url.scheme() &&
                url.host() == data_url.host() &&
                url.port_or_known_default() == data_url.port_or_known_default()
        }
    }
}

/// Whether `address` is the host in the request's `Host` header, in the form of
/// default auth data
fn is_request_host(req_headers: &HeaderMap, address: &[u8]) -> bool {
    req_headers
        .get(HOST)
        .and_then(|host| host_url(host.to_str().ok()?))
        .is_some_and(|url| url.host_str().is_some_and(|host| host.as_bytes() == address))
}

#[cfg(test)]
mod tests {
    use cb_common::{
        config::{GetHeaderTransport, RelayConfig},
        pbs::RelayEntry,
        types::BlsSecretKey,
    };

    use super::*;

    fn test_relay(url: &str) -> RelayClient {
        let entry = RelayEntry {
            id: url.to_string(),
            pubkey: BlsSecretKey::random().public_key(),
            url: Url::parse(url).unwrap(),
        };
        let config = RelayConfig {
            entry,
            id: None,
            headers: None,
            get_params: None,
            get_header: GetHeaderTransport::Http,
            enable_timing_games: false,
            target_first_request_ms: None,
            frequency_get_header_ms: None,
            validator_registration_batch_size: None,
        };
        RelayClient::new(config).unwrap()
    }

    /// Headers of a request from a Commit-Boost, so a miss is an error, not a
    /// dial
    fn from_cb() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_VERSION_KEY, reqwest::header::HeaderValue::from_static("test"));
        headers
    }

    #[tokio::test]
    async fn resolve_relay_by_auth_data() {
        let relays = vec![
            test_relay("https://0xdeadbeef@builder-a.example.com"),
            test_relay("https://builder-b.example.com:8443/eth"),
            test_relay("http://[::1]:18550"),
        ];
        let from_cb = from_cb();
        let host = async |data: &[u8]| -> Option<String> {
            resolve_addressed_relay(&relays, &[], true, data, &from_cb, 0)
                .await
                .ok()
                .map(|(relay, _)| relay.config.entry.url.host_str().unwrap().to_string())
        };
        assert_eq!(host(b"builder-a.example.com").await.as_deref(), Some("builder-a.example.com"));
        assert_eq!(host(b"builder-b.example.com").await.as_deref(), Some("builder-b.example.com"));
        assert_eq!(host(b"[::1]").await.as_deref(), Some("[::1]"));
        assert!(host(b"Builder-A.example.com").await.is_none());
        assert!(host(b"builder-a.example.com:443").await.is_none());
        // A URL matches on scheme, host and port
        assert_eq!(
            host(b"https://builder-a.example.com:443/eth").await.as_deref(),
            Some("builder-a.example.com")
        );
        assert!(host(b"http://builder-a.example.com:443").await.is_none());
        assert!(host(b"https://builder-b.example.com").await.is_none());
        // Parameters after `?` are for the builder and do not affect routing
        assert_eq!(
            host(b"builder-a.example.com?ofac=1").await.as_deref(),
            Some("builder-a.example.com")
        );
    }

    #[tokio::test]
    async fn resolve_falls_back_to_default_relays_in_config_order() {
        let own = vec![test_relay("https://builder-a.example.com/mux")];
        let default_relays = vec![
            test_relay("https://builder-a.example.com:8443"),
            test_relay("https://builder-b.example.com:8443/eth"),
            test_relay("https://builder-b.example.com:9000"),
            test_relay("https://builder-b.example.com:9000/second"),
        ];
        let from_cb = from_cb();
        let url = async |data: &[u8]| {
            resolve_addressed_relay(&own, &default_relays, true, data, &from_cb, 0)
                .await
                .ok()
                .map(|(relay, _)| relay.config.entry.url.to_string())
        };
        assert_eq!(
            url(b"builder-a.example.com").await.as_deref(),
            Some("https://builder-a.example.com/mux")
        );
        assert_eq!(
            url(b"builder-b.example.com").await.as_deref(),
            Some("https://builder-b.example.com:8443/eth")
        );
        assert_eq!(
            url(b"https://builder-b.example.com:9000").await.as_deref(),
            Some("https://builder-b.example.com:9000/")
        );
    }

    #[tokio::test]
    async fn resolve_refuses_the_host_the_request_was_sent_to() {
        let resolve = async |host: &'static str, data: &[u8]| {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, reqwest::header::HeaderValue::from_static(host));
            resolve_addressed_relay(&[], &[], true, data, &headers, 1000)
                .await
                .map(|(relay, _)| relay.config.entry.url.to_string())
        };
        for (host, data) in [
            ("1.1.1.1:18550", &b"1.1.1.1"[..]),
            ("1.1.1.1", b"1.1.1.1"),
            ("[2606:4700:4700:0:0:0:0:1111]:18550", b"[2606:4700:4700::1111]"),
        ] {
            let res = resolve(host, data).await;
            assert!(matches!(res, Err(PbsClientError::AuthDataMismatch)), "{host}");
        }
        assert_eq!(resolve("2.2.2.2:18550", b"1.1.1.1").await.unwrap(), "https://1.1.1.1/");
    }

    // Not from a Commit-Boost, so a miss is dialed at the address before `?`,
    // and refused once the dial's setup leaves no time
    #[tokio::test]
    async fn resolve_dials_the_address_before_the_parameters() {
        let headers = HeaderMap::new();
        let dial = |timeout_ms| {
            resolve_addressed_relay(&[], &[], true, b"1.1.1.1?ofac=1", &headers, timeout_ms)
        };
        let (relay, _) = dial(1000).await.unwrap();
        assert_eq!(relay.config.entry.url.as_str(), "https://1.1.1.1/");
        assert!(matches!(dial(0).await, Err(PbsClientError::NoBuilderResponse)));
    }

    // With dialing off, configured relays still serve and a miss is refused
    #[tokio::test]
    async fn resolve_without_dialing_refuses_a_miss() {
        let own = vec![test_relay("https://builder-a.example.com")];
        let default_relays = vec![test_relay("https://builder-b.example.com")];
        let headers = HeaderMap::new();
        let resolve = async |data: &[u8]| {
            resolve_addressed_relay(&own, &default_relays, false, data, &headers, 1000)
                .await
                .map(|(relay, _)| relay.config.entry.url.to_string())
        };
        assert_eq!(
            resolve(b"builder-a.example.com").await.unwrap(),
            "https://builder-a.example.com/"
        );
        assert_eq!(
            resolve(b"builder-b.example.com").await.unwrap(),
            "https://builder-b.example.com/"
        );
        assert!(matches!(resolve(b"1.1.1.1").await, Err(PbsClientError::AuthDataMismatch)));
    }
}
