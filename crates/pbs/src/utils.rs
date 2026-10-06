use std::{
    future::Future,
    time::{Duration, Instant},
};

use alloy::primitives::utils::{ParseUnits, Unit};
use axum::body::Bytes;
use cb_common::{
    pbs::{RelayClient, error::PbsError},
    types::BlsPublicKey,
    wire::{
        CONSENSUS_VERSION_HEADER, EncodingType, get_user_agent_with_version,
        read_chunked_body_with_max,
    },
};
use futures::future::join_all;
use reqwest::{
    StatusCode,
    header::{CONTENT_TYPE, HeaderMap, USER_AGENT},
};
use tracing::{Instrument, debug, error, warn};
use url::Url;

use crate::{
    constants::{MAX_SIZE_DEFAULT, TIMEOUT_ERROR_CODE_STR},
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
/// the beacon node's `Eth-Consensus-Version`, which the route has validated
pub(crate) fn epbs_base_send_headers(req_headers: &HeaderMap) -> Result<HeaderMap, PbsClientError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        get_user_agent_with_version(req_headers).map_err(|_| PbsClientError::Internal)?,
    );
    if let Some(version) = req_headers.get(CONSENSUS_VERSION_HEADER) {
        headers.insert(CONSENSUS_VERSION_HEADER, version.clone());
    }
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

/// The relay an ePBS request addresses: the first whose URL hostname equals
/// `auth_data`. No match is a 400.
pub(crate) fn resolve_addressed_relay(
    relays: &[RelayClient],
    auth_data: &[u8],
) -> Result<RelayClient, PbsClientError> {
    let addressed = relays.iter().find(|relay| {
        relay.config.entry.url.host_str().is_some_and(|host| host.as_bytes() == auth_data)
    });
    match addressed {
        Some(relay) => Ok(relay.clone()),
        None => {
            warn!(
                auth_data = %String::from_utf8_lossy(auth_data),
                "auth data matches no configured relay"
            );
            Err(PbsClientError::AuthDataMismatch)
        }
    }
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

    #[test]
    fn resolve_relay_by_hostname() {
        let relays = vec![
            test_relay("https://0xdeadbeef@builder-a.example.com"),
            test_relay("https://builder-b.example.com:8443/eth"),
            test_relay("http://[::1]:18550"),
        ];
        let host = |data: &[u8]| -> Option<String> {
            resolve_addressed_relay(&relays, data)
                .ok()
                .map(|relay| relay.config.entry.url.host_str().unwrap().to_string())
        };
        assert_eq!(host(b"builder-a.example.com").as_deref(), Some("builder-a.example.com"));
        assert_eq!(host(b"builder-b.example.com").as_deref(), Some("builder-b.example.com"));
        assert_eq!(host(b"[::1]").as_deref(), Some("[::1]"));
        assert!(host(b"Builder-A.example.com").is_none());
        assert!(host(b"builder-a.example.com:443").is_none());
        // a URL is not a hostname
        assert!(host(b"https://builder-a.example.com").is_none());
    }
}
