use cb_common::{
    pbs::{RelayClient, SignedRequestAuthV1},
    signature::verify_request_auth_signature,
    types::{BlsPublicKey, Chain},
};
use tracing::warn;
use url::Url;

use crate::error::PbsClientError;

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

/// Verifies the request auth signature when `verify_signature` is on. The
/// downstream builder verifies it regardless, which is why the crypto is
/// opt-in. Shared by the request-auth validators of both ePBS endpoints; the
/// slot rule differs between them and stays with each caller.
pub fn verify_auth_signature(
    pubkey: &BlsPublicKey,
    auth: &SignedRequestAuthV1,
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
/// builder: the caller's `auth.message.data` designates which downstream
/// builder it is for, since the Builder API carries no routing header. Relays
/// are matched in three layers, most specific first:
///
/// 1. A relay with `expected_auth_data` configured matches only that exact byte
///    string. This is the authoritative form for bilateral agreements where the
///    data is a shared secret rather than a URL.
/// 2. Otherwise, data carrying a builder URL (see [`decode_auth_data_url`])
///    matches the relays whose configured URL it names. Comparison ignores
///    userinfo, so a bare URL matches a relay entry that embeds its pubkey.
/// 3. Data carrying no URL matches every relay with no `expected_auth_data`
///    configured. `strict_auth_data` disables this catch-all, requiring every
///    relay to declare the data it serves.
///
/// The result is usually one relay, several when multiple builders are
/// configured behind the same agreement, and empty when the data names nothing
/// this instance serves (a 400 to the caller). Comparing bids across different
/// builders is the beacon node's job across its per-entry calls; within the
/// matched set the winner is the highest total payment.
///
/// NOTE for callers that WRITE rather than read: layer 3 sends the request to
/// every relay, so an endpoint carrying proposer-private data reaches builders
/// the proposer did not address unless `strict_auth_data` is set.
pub(crate) fn match_relays_by_auth_data<'a>(
    relays: &'a [RelayClient],
    received_data: &[u8],
    strict_auth_data: bool,
) -> Vec<&'a RelayClient> {
    let data_url = decode_auth_data_url(received_data);
    relays
        .iter()
        .filter(|relay| {
            if let Some(expected) = &relay.config.expected_auth_data {
                return received_data == expected.as_ref();
            }
            if strict_auth_data {
                return false;
            }
            match &data_url {
                Some(url) => url_matches(&relay.config.entry.url, url),
                None => true,
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
    use cb_common::{config::RelayConfig, pbs::RelayEntry, types::BlsSecretKey};

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
        assert!(match_relays_by_auth_data(&relays, &[], false).is_empty());
    }

    #[test]
    fn match_relays_prefers_configured_auth_data() {
        let relays = vec![
            test_relay("http://a.example.com", Some(&[0xaa])),
            test_relay("http://b.example.com", Some(&[0xbb])),
        ];
        // Exact-bytes match selects exactly one relay
        let matched = match_relays_by_auth_data(&relays, &[0xbb], false);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].config.entry.url.host_str(), Some("b.example.com"));
        // Data matching no configured value selects none, even though the data
        // is a URL naming a configured relay: configured bytes take precedence
        assert!(match_relays_by_auth_data(&relays, b"http://a.example.com", false).is_empty());
    }

    #[test]
    fn match_relays_falls_back_to_url_then_catch_all() {
        let relays = vec![
            test_relay("http://a.example.com", None),
            test_relay("http://b.example.com", None),
        ];
        // URL-carrying data selects the named relay only
        let matched = match_relays_by_auth_data(&relays, b"http://a.example.com", false);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].config.entry.url.host_str(), Some("a.example.com"));
        // NUL-suffixed extra bytes route identically
        let mut with_extra = b"http://a.example.com".to_vec();
        with_extra.push(0);
        with_extra.extend_from_slice(&[0xde, 0xad]);
        assert_eq!(match_relays_by_auth_data(&relays, &with_extra, false).len(), 1);
        // A URL naming nothing configured selects none
        assert!(match_relays_by_auth_data(&relays, b"http://z.example.com", false).is_empty());
        // Opaque non-URL data hits the catch-all
        assert_eq!(match_relays_by_auth_data(&relays, &[0xde, 0xad], false).len(), 2);
        // Empty data carries no URL, so it hits the catch-all too
        assert_eq!(match_relays_by_auth_data(&relays, &[], false).len(), 2);
        // strict_auth_data disables the catch-all entirely
        assert!(match_relays_by_auth_data(&relays, &[0xde, 0xad], true).is_empty());
        // URL matching still works under strict mode? No: strict requires
        // expected_auth_data on every relay
        assert!(match_relays_by_auth_data(&relays, b"http://a.example.com", true).is_empty());
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
}
