use std::time::{Duration, Instant};

use cb_common::{
    pbs::{ForkName, RelayClient, SignedRequestAuth, error::PbsError},
    signature::verify_request_auth_signature,
    types::{BlsPublicKey, Chain},
    wire::{CONSENSUS_VERSION_HEADER, get_user_agent_with_version},
};
use reqwest::{
    StatusCode,
    header::{HeaderMap, HeaderValue, USER_AGENT},
};
use tracing::warn;
use url::Url;

use crate::{
    constants::TIMEOUT_ERROR_CODE_STR,
    error::PbsClientError,
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
};

/// Sends one already-built relay request and records the per-relay metrics
/// shared by all three ePBS endpoints: a send failure bumps `RELAY_STATUS_CODE`
/// at `TIMEOUT_ERROR_CODE_STR` and returns the error; otherwise the latency is
/// observed and the response status recorded. Returns the response and its
/// latency so the caller can read/decode the body itself. `tag` is the
/// per-endpoint metric label. Callers build their own `RequestBuilder` because
/// the requests legitimately differ (bid sets a per-call timeout and timing
/// headers).
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

/// Count a request-rejection in `BEACON_NODE_STATUS` before it short-circuits
/// the handler. Without this a client broken by e.g. the strict
/// `Eth-Consensus-Version` rule or a bad `Accept` header VANISHES from the
/// endpoint counter instead of showing up as a 4xx spike - the exact signal an
/// operator needs during a rollout.
pub(crate) fn record_client_error(
    err: impl Into<PbsClientError>,
    endpoint: &str,
) -> PbsClientError {
    let err = err.into();
    crate::metrics::BEACON_NODE_STATUS
        .with_label_values(&[err.status_code().as_str(), endpoint])
        .inc();
    err
}

/// Count a relay response that CB rejected during validation. The relay's HTTP
/// status was already recorded when the response arrived, so without this a
/// relay serving invalid bids every slot is indistinguishable in metrics from
/// an honest empty auction.
pub(crate) fn record_invalid_relay_response(reason: &str, endpoint: &str, relay_id: &str) {
    crate::metrics::RELAY_INVALID_RESPONSE.with_label_values(&[reason, endpoint, relay_id]).inc();
}

/// The ePBS write endpoints (`submitBuilderPreferences`,
/// `submitSignedBeaconBlock`) make 202 Accepted the only success: any other
/// status means the builder did not commit. One home for that rule.
pub(crate) fn expect_status(code: StatusCode, expected: StatusCode) -> Result<(), PbsError> {
    if code != expected {
        return Err(PbsError::RelayResponse {
            error_msg: format!("expected {}", expected.as_u16()),
            code: code.as_u16(),
        });
    }
    Ok(())
}

/// Base outbound headers shared by the ePBS endpoints: the versioned
/// `User-Agent` and `Eth-Consensus-Version`. All three relay hops send SSZ
/// bodies of fork-versioned wire types, so the builder needs the fork header;
/// it is re-derived as Gloas (these are Gloas-only endpoints), never echoed
/// from the inbound request. Callers add their endpoint-specific headers (bid
/// adds `Accept` and the timing headers).
pub(crate) fn epbs_base_send_headers(req_headers: &HeaderMap) -> Result<HeaderMap, PbsClientError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        get_user_agent_with_version(req_headers).map_err(|_| PbsClientError::Internal)?,
    );
    headers.insert(
        CONSENSUS_VERSION_HEADER,
        HeaderValue::from_str(&ForkName::Gloas.to_string())
            .expect("fork name is always a valid header value"),
    );
    Ok(headers)
}

const GAS_LIMIT_ADJUSTMENT_FACTOR: u64 = 1024;
const GAS_LIMIT_MINIMUM: u64 = 5_000;

/// Validates the gas limit against the parent gas limit, according to the
/// execution spec https://github.com/ethereum/execution-specs/blob/98d6ddaaa709a2b7d0cd642f4cfcdadc8c0808e1/src/ethereum/cancun/fork.py#L1118-L1154
pub(crate) fn check_gas_limit(gas_limit: u64, parent_gas_limit: u64) -> bool {
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

/// Verifies the request auth signature when `verify_signature` is on. The
/// downstream builder verifies it regardless, which is why the crypto is
/// opt-in. Shared by the request-auth validators of both ePBS endpoints; the
/// slot rule differs between them and stays with each caller.
pub(crate) fn verify_auth_signature(
    pubkey: &BlsPublicKey,
    auth: &SignedRequestAuth,
    chain: Chain,
    verify_signature: bool,
) -> Result<(), PbsClientError> {
    if verify_signature &&
        !verify_request_auth_signature(pubkey, &auth.message, &auth.signature, chain)
    {
        warn!(pubkey = %pubkey, "auth signature verification failed");
        return Err(PbsClientError::AuthSigVerify);
    }

    Ok(())
}

/// Selects the relays an ePBS request is addressed to.
///
/// Each `getExecutionPayloadBid` or `submitBuilderPreferences` call is for one
/// builder, designated by the caller's `auth.message.data`. Two layers, most
/// specific first:
///
/// 1. A relay with `expected_auth_data` configured matches only that exact byte
///    string. This is the authoritative form for bilateral agreements where the
///    data is a shared secret rather than a URL.
/// 2. Otherwise, data carrying a builder URL (see [`decode_auth_data_url`])
///    matches the relays whose configured URL it names. Comparison ignores
///    userinfo, so a bare URL matches a relay entry that embeds its pubkey.
///
/// Data matching nothing selects no relay: CB then has no builder to proxy to
/// and the caller must get the same DataMismatch 400 a builder would return.
/// The result is usually one relay, several when multiple builders are
/// configured behind the same agreement. Comparing bids across different
/// builders is the beacon node's job across its per-entry calls; within the
/// matched set the winner is the highest total payment.
pub(crate) fn match_relays_by_auth_data<'a>(
    relays: &'a [RelayClient],
    received_data: &[u8],
) -> Vec<&'a RelayClient> {
    let data_url = decode_auth_data_url(received_data);
    relays
        .iter()
        .filter(|relay| {
            if let Some(expected) = &relay.config.expected_auth_data {
                return received_data == expected.as_ref();
            }
            match &data_url {
                Some(url) => url_matches(&relay.config.entry.url, url),
                None => false,
            }
        })
        .collect()
}

/// Extracts a builder URL from `auth.message.data` using Commit-Boost's
/// purely additive convention: the UTF-8 bytes of the builder's URL, optionally
/// followed by a NUL byte and opaque extra bytes. Data without extra bytes is
/// byte-identical to the spec's nothing-agreed default, so parties using the
/// default need no change; NUL cannot appear in a URL, so the split is
/// unambiguous. Returns None for opaque data carrying no URL.
pub(crate) fn decode_auth_data_url(data: &[u8]) -> Option<Url> {
    let url_bytes = match data.iter().position(|&b| b == 0) {
        Some(i) => &data[..i],
        None => data,
    };
    std::str::from_utf8(url_bytes).ok().and_then(|s| Url::parse(s).ok())
}

/// Compares two URLs without checking userinfo/path/queries/frags. A relay
/// entry URL embeds the relay pubkey as userinfo, so full equality would never
/// match a bare builder URL.
pub(crate) fn url_matches(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() &&
        a.host_str() == b.host_str() &&
        a.port_or_known_default() == b.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use cb_common::{
        config::{GetHeaderTransport, RelayConfig},
        pbs::RelayEntry,
        types::BlsSecretKey,
    };

    use super::*;

    fn test_relay(url: &str, expected_auth_data: Option<&[u8]>) -> RelayClient {
        let entry = RelayEntry {
            id: url.to_string(),
            pubkey: BlsSecretKey::random().public_key().into(),
            url: Url::parse(url).unwrap(),
        };
        let mut config = RelayConfig {
            entry,
            id: None,
            headers: None,
            get_params: None,
            get_header: GetHeaderTransport::Http,
            enable_timing_games: false,
            target_first_request_ms: None,
            frequency_get_header_ms: None,
            bid_poll_timeout_ms: None,
            validator_registration_batch_size: None,
            max_execution_payment_gwei: None,
            expected_auth_data: None,
        };
        config.expected_auth_data = expected_auth_data.map(|d| d.to_vec().into());
        RelayClient::new(config).unwrap()
    }

    #[test]
    fn match_relays_configured_data_never_matches_empty() {
        let relays = vec![test_relay("http://a.example.com", Some(&[0xaa]))];
        // An empty `data` field must not satisfy a relay that declared its data
        assert!(match_relays_by_auth_data(&relays, &[]).is_empty());
    }

    #[test]
    fn match_relays_prefers_configured_auth_data() {
        let relays = vec![
            test_relay("http://a.example.com", Some(&[0xaa])),
            test_relay("http://b.example.com", Some(&[0xbb])),
        ];
        // Exact-bytes match selects exactly one relay
        let matched = match_relays_by_auth_data(&relays, &[0xbb]);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].config.entry.url.host_str(), Some("b.example.com"));
        // Data matching no configured value selects none, even though the data
        // is a URL naming a configured relay: configured bytes take precedence
        assert!(match_relays_by_auth_data(&relays, b"http://a.example.com").is_empty());
    }

    #[test]
    fn match_relays_url_fallback_and_unmatched_selects_none() {
        let relays = vec![
            test_relay("http://a.example.com", None),
            test_relay("http://b.example.com", None),
        ];
        // URL-carrying data selects the named relay only
        let matched = match_relays_by_auth_data(&relays, b"http://a.example.com");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].config.entry.url.host_str(), Some("a.example.com"));
        // NUL-suffixed extra bytes route identically
        let mut with_extra = b"http://a.example.com".to_vec();
        with_extra.push(0);
        with_extra.extend_from_slice(&[0xde, 0xad]);
        assert_eq!(match_relays_by_auth_data(&relays, &with_extra).len(), 1);
        // A URL naming nothing configured selects none
        assert!(match_relays_by_auth_data(&relays, b"http://z.example.com").is_empty());
        // Opaque non-URL data names nothing: no catch-all, no relay
        assert!(match_relays_by_auth_data(&relays, &[0xde, 0xad]).is_empty());
        // Empty data carries no URL either
        assert!(match_relays_by_auth_data(&relays, &[]).is_empty());
    }

    #[test]
    fn url_matches_ignores_userinfo_and_default_port() {
        let u = |s: &str| Url::parse(s).unwrap();
        // A bare builder URL matches a configured relay whose URL embeds the
        // relay pubkey as userinfo and omits the default port.
        assert!(url_matches(
            &u("https://0xdeadbeef@builder.example.com"),
            &u("https://builder.example.com")
        ));
        assert!(url_matches(
            &u("https://builder.example.com:443"),
            &u("https://builder.example.com")
        ));
        assert!(!url_matches(&u("http://a.com"), &u("https://a.com")));
        assert!(!url_matches(&u("https://a.com"), &u("https://b.com")));
        assert!(!url_matches(&u("http://a.com:8001"), &u("http://a.com:8002")));
    }

    #[test]
    fn decode_auth_data_url_variants() {
        // raw UTF-8 URL bytes (the spec's nothing-agreed default)
        let url = decode_auth_data_url(b"https://builder.example.com").unwrap();
        assert_eq!(url.host_str(), Some("builder.example.com"));
        // NUL-suffixed extra bytes decode to the same URL: purely additive
        let mut with_extra = b"https://builder.example.com".to_vec();
        with_extra.push(0);
        with_extra.extend_from_slice(&[0xde, 0xad]);
        let url = decode_auth_data_url(&with_extra).unwrap();
        assert_eq!(url.host_str(), Some("builder.example.com"));
        // empty extra after the NUL is also valid and identical
        let url = decode_auth_data_url(b"https://builder.example.com\x00").unwrap();
        assert_eq!(url.host_str(), Some("builder.example.com"));
        // opaque non-URL bytes carry no routing, with or without a NUL
        assert!(decode_auth_data_url(&[0xde, 0xad, 0xbe, 0xef]).is_none());
        assert!(decode_auth_data_url(&[0xde, 0x00, 0xad]).is_none());
        assert!(decode_auth_data_url(b"not a url").is_none());
    }

    /// Pins that the helper lands in `BEACON_NODE_STATUS` with the declared
    /// label ORDER (status, endpoint). Both labels are &str, so a swapped
    /// order compiles and silently writes a different series - this read-back
    /// with the correct order is the only thing that catches it. The endpoint
    /// tag is unique to this test, so parallel tests cannot race it.
    /// Same label-order pin as the beacon-node counter: all three labels are
    /// &str, so a permuted order compiles and silently writes another series.
    #[test]
    fn record_invalid_relay_response_lands_in_relay_invalid_response() {
        const TAG: &str = "invalid-relay-response-unit-test";

        let before = crate::metrics::RELAY_INVALID_RESPONSE
            .with_label_values(&["wrong_fork", TAG, "relay-x"])
            .get();
        record_invalid_relay_response("wrong_fork", TAG, "relay-x");
        let after = crate::metrics::RELAY_INVALID_RESPONSE
            .with_label_values(&["wrong_fork", TAG, "relay-x"])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn record_client_error_lands_in_beacon_node_status() {
        const TAG: &str = "record-client-error-unit-test";

        let before = crate::metrics::BEACON_NODE_STATUS.with_label_values(&["400", TAG]).get();
        let err =
            record_client_error(cb_common::wire::BodyDeserializeError::MissingVersionHeader, TAG);
        assert_eq!(err.status_code(), reqwest::StatusCode::BAD_REQUEST);
        let after = crate::metrics::BEACON_NODE_STATUS.with_label_values(&["400", TAG]).get();
        assert_eq!(after, before + 1, "the 400 must count under (status, endpoint)");
    }
}
