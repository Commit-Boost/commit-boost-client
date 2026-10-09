use std::{
    future::Future,
    time::{Duration, Instant},
};

use alloy::primitives::utils::{ParseUnits, Unit};
use axum::{body::Bytes, http::uri::Authority};
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
    StatusCode,
    header::{CONTENT_TYPE, HOST, HeaderMap, USER_AGENT},
};
use tracing::{Instrument, debug, error, warn};
use url::Url;

use crate::{
    config_miss::{self, Miss},
    constants::{
        GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG, MAX_SIZE_DEFAULT,
        SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG, TIMEOUT_ERROR_CODE_STR,
    },
    dial::{auth_data_address, dial_relay},
    error::PbsClientError,
    metrics::{AUTH_DATA_ROUTE, BEACON_NODE_STATUS, RELAY_LATENCY, RELAY_STATUS_CODE},
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
    } else if matches!(err, PbsClientError::NoBuilderConfig) {
        // config_miss warned about the key, a few times an epoch
        debug!(%err, "{endpoint} failed");
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

/// POSTs an SSZ body to a builder; 202 Accepted is the only success. A failed
/// response's body, capped at `MAX_SIZE_DEFAULT`, becomes the error message.
/// Returns the request latency.
pub(crate) async fn post_ssz_expect_accepted(
    relay: &RelayClient,
    url: Url,
    body: Bytes,
    headers: HeaderMap,
    timeout_ms: u64,
    tag: &str,
) -> Result<Duration, PbsError> {
    let req = relay
        .client
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers)
        .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
        .body(body);
    let (res, latency) = send_to_relay(req, relay, tag).await?;
    let code = res.status();
    if code == StatusCode::ACCEPTED {
        return Ok(latency);
    }
    // Read after the status check, so a body over the cap still reports the
    // builder's status
    let url = res.url().to_string();
    let error_msg = match read_chunked_body_with_max(res, MAX_SIZE_DEFAULT, &url).await {
        Ok(body) if !body.is_empty() => String::from_utf8_lossy(&body).into_owned(),
        Ok(_) => "expected 202".to_string(),
        Err(err) => err.to_string(),
    };
    Err(PbsError::RelayResponse { error_msg, code: code.as_u16() })
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

/// The key a bid or preferences request is for, and every relay Commit-Boost
/// has, to tell a missing or stale builder config from a dial
pub(crate) struct Addressed<'a> {
    pub endpoint: &'static str,
    pub pubkey: &'a BlsPublicKey,
    pub mux_id: Option<&'a str>,
    pub all_relays: &'a [RelayClient],
}

/// The relay `address` names, by hostname or, for a URL, by origin
fn relay_named<'a>(
    relays: &'a [RelayClient],
    address: &[u8],
    data_url: Option<&Url>,
) -> Option<&'a RelayClient> {
    relays.iter().find(|relay| {
        let url = &relay.config.entry.url;
        match data_url {
            Some(data_url) => {
                url.scheme() == data_url.scheme() &&
                    url.host() == data_url.host() &&
                    url.port_or_known_default() == data_url.port_or_known_default()
            }
            None => url.host_str().is_some_and(|host| host.as_bytes() == address),
        }
    })
}

/// Whether auth data naming none of the key's relays names another of
/// Commit-Boost's relays, or Commit-Boost itself by the request's `Host`
fn classify_miss(
    address: &[u8],
    data_url: Option<&Url>,
    req_headers: &HeaderMap,
    all_relays: &[RelayClient],
) -> Option<Miss> {
    if relay_named(all_relays, address, data_url).is_some() {
        return Some(Miss::Stale);
    }
    let own: Authority = req_headers.get(HOST)?.to_str().ok()?.parse().ok()?;
    let is_own = match data_url {
        // A URL also names a port, so a builder on Commit-Boost's host at another
        // port is still dialed
        Some(data_url) => {
            let default = if data_url.scheme() == "https" { 443 } else { 80 };
            data_url.host_str()?.eq_ignore_ascii_case(own.host()) &&
                data_url.port_or_known_default() == Some(own.port_u16().unwrap_or(default))
        }
        None => address.eq_ignore_ascii_case(own.host().as_bytes()),
    };
    is_own.then_some(Miss::NoConfig)
}

/// The outcomes `resolve_addressed_relay` counts
const AUTH_DATA_OUTCOMES: [&str; 4] = ["relay", "no_config", "stale", "dial"];

/// Creates every auth data route series at 0, so an alert sees the first miss
/// as an increase
pub(crate) fn init_auth_data_route_metric() {
    for endpoint in
        [GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG, SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG]
    {
        for outcome in AUTH_DATA_OUTCOMES {
            AUTH_DATA_ROUTE.with_label_values(&[endpoint, outcome]);
        }
    }
}

/// The first configured relay that the address in `auth_data` names, by
/// hostname or, for a URL, by origin; otherwise a relay that dials it, unless
/// it names Commit-Boost itself. Also returns what `timeout_ms` leaves after
/// setting up that dial.
pub(crate) async fn resolve_addressed_relay(
    relays: &[RelayClient],
    auth_data: &[u8],
    req_headers: &HeaderMap,
    timeout_ms: u64,
    addressed: &Addressed<'_>,
) -> Result<(RelayClient, u64), PbsClientError> {
    let count = |outcome| AUTH_DATA_ROUTE.with_label_values(&[addressed.endpoint, outcome]).inc();
    let address = auth_data_address(auth_data);
    let data_url = decode_auth_data_url(address);
    if let Some(relay) = relay_named(relays, address, data_url.as_ref()) {
        count("relay");
        return Ok((relay.clone(), timeout_ms));
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
    match classify_miss(address, data_url.as_ref(), req_headers, addressed.all_relays) {
        Some(Miss::NoConfig) => {
            config_miss::record(addressed.pubkey, addressed.mux_id, auth_data, Miss::NoConfig);
            count("no_config");
            return Err(PbsClientError::NoBuilderConfig);
        }
        Some(Miss::Stale) => {
            config_miss::record(addressed.pubkey, addressed.mux_id, auth_data, Miss::Stale);
            count("stale");
        }
        None => count("dial"),
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
            max_execution_payment_gwei: None,
        };
        RelayClient::new(config).unwrap()
    }

    // A miss naming Commit-Boost's own host, as a hostname or Prysm's whole URL,
    // is a key with no builder config; one naming another of its relays is
    // stale, even on Commit-Boost's host; anything else is a dial
    #[test]
    fn classify_auth_data_misses() {
        let all =
            vec![test_relay("https://other.example.com"), test_relay("http://127.0.0.1:9000")];
        let with_host = |host: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, host.parse().unwrap());
            headers
        };
        for (data, host, expected) in [
            ("cb.example.com", "cb.example.com:18550", Some(Miss::NoConfig)),
            ("CB.example.com", "cb.example.com", Some(Miss::NoConfig)),
            ("http://cb.example.com:18550", "cb.example.com:18550", Some(Miss::NoConfig)),
            ("http://cb.example.com", "cb.example.com", Some(Miss::NoConfig)),
            ("http://cb.example.com:9000", "cb.example.com:18550", None),
            ("http://cb.example.com:18550", "CB.example.com:18550", Some(Miss::NoConfig)),
            ("https://cb.example.com", "cb.example.com", Some(Miss::NoConfig)),
            ("[::1]", "[::1]:18550", Some(Miss::NoConfig)),
            // A Host that is not an authority names nothing
            ("cb.example.com", "cb example.com", None),
            ("other.example.com", "cb.example.com:18550", Some(Miss::Stale)),
            ("https://other.example.com", "cb.example.com:18550", Some(Miss::Stale)),
            ("127.0.0.1", "127.0.0.1:18550", Some(Miss::Stale)),
            ("builder.example.com", "cb.example.com:18550", None),
            ("http://builder.example.com", "cb.example.com:18550", None),
        ] {
            let data_url = decode_auth_data_url(data.as_bytes());
            let miss = classify_miss(data.as_bytes(), data_url.as_ref(), &with_host(host), &all);
            assert_eq!(miss, expected, "{data} at {host}");
        }
        // Without a Host header Commit-Boost cannot tell its own name
        let none = classify_miss(b"cb.example.com", None, &HeaderMap::new(), &all);
        assert_eq!(none, None);
    }

    #[tokio::test]
    async fn resolve_relay_by_auth_data() {
        let relays = vec![
            test_relay("https://0xdeadbeef@builder-a.example.com"),
            test_relay("https://builder-b.example.com:8443/eth"),
            test_relay("http://[::1]:18550"),
        ];
        // From a Commit-Boost, so a miss is an error, not a dial
        let mut from_cb = HeaderMap::new();
        from_cb.insert(HEADER_VERSION_KEY, reqwest::header::HeaderValue::from_static("test"));
        let host = async |data: &[u8]| -> Option<String> {
            let pubkey = BlsSecretKey::random().public_key();
            let addressed =
                Addressed { endpoint: "test", pubkey: &pubkey, mux_id: None, all_relays: &relays };
            resolve_addressed_relay(&relays, data, &from_cb, 0, &addressed)
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
        assert!(host(b"http://builder-a.example.com").await.is_none());
        assert!(host(b"http://builder-a.example.com:443").await.is_none());
        assert!(host(b"https://builder-b.example.com").await.is_none());
        // Parameters after `?` are for the builder and do not affect routing
        assert_eq!(
            host(b"builder-a.example.com?ofac=1").await.as_deref(),
            Some("builder-a.example.com")
        );
    }

    // Each endpoint has every outcome's series before any request
    #[test]
    fn auth_data_route_series_start_at_zero() {
        use prometheus::core::Collector;

        init_auth_data_route_metric();
        let family = &AUTH_DATA_ROUTE.collect()[0];
        let present = |endpoint: &str, outcome: &str| {
            family.get_metric().iter().any(|metric| {
                let labels: Vec<_> =
                    metric.get_label().iter().map(|label| label.get_value()).collect();
                labels.contains(&endpoint) && labels.contains(&outcome)
            })
        };
        for endpoint in
            [GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG, SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG]
        {
            for outcome in AUTH_DATA_OUTCOMES {
                assert!(present(endpoint, outcome), "{endpoint} {outcome}");
            }
        }
    }

    // Each route counts its outcome: one of the key's relays, Commit-Boost
    // itself (refused), another of its relays (stale, still dialed) and any
    // other builder (dialed). A request from a Commit-Boost goes no further and
    // is not counted. The dials here are to addresses the dial check refuses
    #[tokio::test]
    async fn resolve_counts_each_outcome() {
        let relays = vec![test_relay("https://builder-a.example.com")];
        let all = vec![relays[0].clone(), test_relay("http://127.0.0.1:9000")];
        let endpoint = "resolve_counts_each_outcome";
        let pubkey = BlsSecretKey::random().public_key();
        let addressed = Addressed { endpoint, pubkey: &pubkey, mux_id: None, all_relays: &all };
        let mut to_cb = HeaderMap::new();
        to_cb.insert(HOST, reqwest::header::HeaderValue::from_static("cb.example.com:18550"));
        let mut from_cb = to_cb.clone();
        from_cb.insert(HEADER_VERSION_KEY, reqwest::header::HeaderValue::from_static("test"));
        let outcomes = AUTH_DATA_OUTCOMES;
        let counts = || {
            outcomes.map(|outcome| AUTH_DATA_ROUTE.with_label_values(&[endpoint, outcome]).get())
        };
        for (data, headers, outcome, expected) in [
            ("builder-a.example.com", &to_cb, Some("relay"), "routed"),
            ("cb.example.com", &to_cb, Some("no_config"), "no builder config"),
            ("127.0.0.1", &to_cb, Some("stale"), "dialed"),
            ("10.0.0.1", &to_cb, Some("dial"), "dialed"),
            ("cb.example.com", &from_cb, None, "not dialed on"),
        ] {
            let before = counts();
            let result =
                resolve_addressed_relay(&relays, data.as_bytes(), headers, 1000, &addressed);
            let result = match result.await {
                Ok(_) => "routed",
                Err(PbsClientError::NoBuilderConfig) => "no builder config",
                Err(PbsClientError::DialTargetBlocked) => "dialed",
                Err(PbsClientError::AuthDataMismatch) => "not dialed on",
                Err(err) => panic!("{data}: {err}"),
            };
            assert_eq!(result, expected, "{data}");
            let after = counts();
            for (i, name) in outcomes.iter().enumerate() {
                let counted = u64::from(Some(*name) == outcome);
                assert_eq!(after[i] - before[i], counted, "{data}: {name}");
            }
        }
    }
}
