use alloy::primitives::{B256, U256};
use cb_common::{
    pbs::{
        GetExecutionPayloadBidResponse, HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS, RelayClient,
        SignedBuilderRequestAuth, SignedExecutionPayloadBid,
    },
    signer::random_secret,
    types::{BlsPublicKey, Chain},
    utils::utcnow_ms,
    wire::{CONSENSUS_VERSION_HEADER, EncodingType},
};
use cb_pbs::GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG;
use cb_tests::{
    mock_relay::MockRelayState,
    mock_validator::MockValidator,
    utils::{
        RELAY_API_KEY, TEST_AUTH_DATA, TEST_PROPOSER_PUBKEY, generate_mock_relay, opaque_auth,
        setup_mux_relays, setup_relay, setup_relays, setup_relays_on_hosts, spawn_mock_relay,
    },
};
use eyre::Result;
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::{Decode, Encode};
use tracing::info;

const TEST_SLOT: u64 = 100;

/// The request most tests send: a JSON-accept bid request for `TEST_SLOT` on
/// a zero parent hash/root, carrying `auth`.
async fn get_json_bid(
    mock_validator: &MockValidator,
    auth: &SignedBuilderRequestAuth,
) -> Result<reqwest::Response> {
    mock_validator
        .do_get_execution_payload_bid(TEST_SLOT, B256::ZERO, B256::ZERO, None, Some(auth), vec![
            EncodingType::Json,
        ])
        .await
}

/// The literal spec URL of the bid endpoint for `TEST_SLOT`, for the tests that
/// build their request by hand (bare-URL shape, missing headers, raw bodies).
fn bid_url(mock_validator: &MockValidator) -> String {
    format!(
        "{}eth/v1/builder/execution_payload_bid/{}/{}/{}/{}",
        mock_validator.comm_boost.config.entry.url,
        TEST_SLOT,
        B256::ZERO,
        B256::ZERO,
        TEST_PROPOSER_PUBKEY,
    )
}

/// The relay is asked and its bid is returned as JSON with the 200's required
/// Eth-Consensus-Version
#[tokio::test]
async fn test_get_execution_payload_bid() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;

    info!("Sending get execution payload bid");
    let res = get_json_bid(&mock_validator, &opaque_auth(TEST_AUTH_DATA, TEST_SLOT)).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);

    let version_header =
        res.headers().get("eth-consensus-version").and_then(|v| v.to_str().ok()).map(str::to_owned);
    assert_eq!(
        version_header.as_deref(),
        Some("gloas"),
        "200 response must set Eth-Consensus-Version: gloas"
    );

    let res = serde_json::from_slice::<GetExecutionPayloadBidResponse>(&res.bytes().await?)?;
    assert_eq!(res.version.to_string(), "gloas");
    assert_ne!(res.data.message.block_hash.0, B256::ZERO);
    assert_eq!(res.data.message.value, 10);
    Ok(())
}

/// `min_bid_eth` does NOT floor ePBS bids: the BN enforces the per-key
/// min_bid on this path (beacon-APIs #630), so a bid below the global CB
/// minimum still passes through
#[tokio::test]
async fn test_get_execution_payload_bid_below_min_bid_passes() -> Result<()> {
    // Default mock bid: trustless 10 gwei, no execution payment; CB floor 20 gwei
    let (mock_validator, mock_state) = setup_relay(
        Chain::Hoodi,
        |cfg| cfg.min_bid_wei = U256::from(20_000_000_000u64),
        generate_mock_relay,
    )
    .await?;

    let auth = opaque_auth(TEST_AUTH_DATA, TEST_SLOT);
    let res = get_json_bid(&mock_validator, &auth).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    Ok(())
}

/// Relays on one host share its default auth data: only the first configured
/// one is asked
#[tokio::test]
async fn test_get_execution_payload_bid_shared_auth_data_asks_the_first() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;

    let res = get_json_bid(&mock_validator, &opaque_auth(TEST_AUTH_DATA, TEST_SLOT)).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(states[0].received_execution_payload_bid(), 1);
    assert_eq!(states[1].received_execution_payload_bid(), 0);
    Ok(())
}

/// The spec default auth data, the builder's hostname, routes to the relay on
/// that host, and the auth reaches the relay unchanged. An unconfigured
/// `localhost` resolves to loopback, so it is refused with 400 and not dialed.
#[tokio::test]
async fn test_get_execution_payload_bid_demux_by_hostname() -> Result<()> {
    let chain = Chain::Hoodi;
    // 0.0.0.0 and 127.0.0.1 both reach the local mocks under distinct hostnames
    let (mock_validator, states) = setup_relays_on_hosts(chain, vec![
        (MockRelayState::new(chain, random_secret()), "0.0.0.0"),
        (MockRelayState::new(chain, random_secret()), "127.0.0.1"),
    ])
    .await?;

    let res = get_json_bid(&mock_validator, &opaque_auth(b"127.0.0.1", TEST_SLOT)).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(states[0].received_execution_payload_bid(), 0);
    assert_eq!(states[1].received_execution_payload_bid(), 1);
    assert_eq!(states[1].received_auth_data(), Some(b"127.0.0.1".to_vec()));

    let res = get_json_bid(&mock_validator, &opaque_auth(b"localhost", TEST_SLOT)).await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(states[0].received_execution_payload_bid(), 0);
    assert_eq!(states[1].received_execution_payload_bid(), 1);
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert_eq!(
        body["message"],
        "Invalid SignedBuilderRequestAuth: the addressed builder's host does not resolve or resolves to a disallowed address"
    );
    Ok(())
}

/// Auth data that matches no relay entry is dialed, and the builder gets the
/// auth, `?` parameters included, unchanged. A request from a Commit-Boost is
/// not dialed, though a configured relay still serves it.
#[tokio::test]
async fn test_get_execution_payload_bid_dial() -> Result<()> {
    // The mock builder listens on an address the dial check refuses
    cb_pbs::set_skip_dial_target_check(true);
    let chain = Chain::Hoodi;
    let (mut mock_validator, cfg_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    let (dial_state, dial_port) =
        spawn_mock_relay(MockRelayState::new(chain, random_secret())).await?;
    let dial_auth_data = format!("http://0.0.0.0:{dial_port}/?ofac=1").into_bytes();

    let res = get_json_bid(&mock_validator, &opaque_auth(&dial_auth_data, TEST_SLOT)).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(dial_state.received_auth_data(), Some(dial_auth_data.clone()));
    // A dial carries none of the relays' configured headers, the API key included
    assert_eq!(dial_state.api_key_seen(GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG), None);

    // RelayClient::new's client sends the Commit-Boost version header
    mock_validator.comm_boost =
        RelayClient::new(mock_validator.comm_boost.config.as_ref().clone())?;
    let res = get_json_bid(&mock_validator, &opaque_auth(&dial_auth_data, TEST_SLOT)).await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(
        body["message"],
        "Invalid SignedBuilderRequestAuth: auth.message.data does not match any configured builder"
    );
    let res = get_json_bid(&mock_validator, &opaque_auth(TEST_AUTH_DATA, TEST_SLOT)).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(dial_state.received_execution_payload_bid(), 1);
    assert_eq!(cfg_state.received_execution_payload_bid(), 1);
    assert_eq!(
        cfg_state.api_key_seen(GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG).as_deref(),
        Some(RELAY_API_KEY)
    );
    Ok(())
}

/// A key in a `[[mux]]` is served by that mux's relays, and reaches a relay
/// configured only in `[[relays]]` through its entry, its API key included. A
/// relay only in a mux is not reached so by other keys: it is dialed instead
#[tokio::test]
async fn test_get_execution_payload_bid_mux_routes_to_mux_relays() -> Result<()> {
    let relays = setup_mux_relays(Chain::Hoodi).await?;
    let bid = async |key: Option<BlsPublicKey>, auth_data: &[u8]| {
        relays
            .validator
            .do_get_execution_payload_bid(
                TEST_SLOT,
                B256::ZERO,
                B256::ZERO,
                key,
                Some(&opaque_auth(auth_data, TEST_SLOT)),
                vec![EncodingType::Json],
            )
            .await
    };
    let muxed = Some(relays.muxed_key.clone());

    assert_eq!(bid(muxed.clone(), TEST_AUTH_DATA).await?.status(), StatusCode::OK);
    assert_eq!(relays.mux_state.received_execution_payload_bid(), 1);
    assert_eq!(relays.default_state.received_execution_payload_bid(), 0);

    let to_default = format!("http://0.0.0.0:{}", relays.default_port);
    assert_eq!(bid(muxed, to_default.as_bytes()).await?.status(), StatusCode::OK);
    assert_eq!(relays.default_state.received_execution_payload_bid(), 1);
    assert_eq!(
        relays.default_state.api_key_seen(GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG).as_deref(),
        Some(RELAY_API_KEY)
    );

    // Dialed, and the dial check refuses 0.0.0.0
    let to_mux = format!("http://0.0.0.0:{}", relays.mux_port);
    assert_eq!(bid(None, to_mux.as_bytes()).await?.status(), StatusCode::BAD_REQUEST);
    assert_eq!(relays.mux_state.received_execution_payload_bid(), 1);
    Ok(())
}

/// `auth.message.slot` must match the proposal slot in the request path.
#[tokio::test]
async fn test_get_execution_payload_bid_auth_slot_mismatch_400() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;

    let auth = opaque_auth(TEST_AUTH_DATA, TEST_SLOT + 1);
    let res = get_json_bid(&mock_validator, &auth).await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        mock_state.received_execution_payload_bid(),
        0,
        "slot mismatch precedes relay calls"
    );
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert_eq!(
        body["message"],
        "Invalid SignedBuilderRequestAuth: auth.message.slot does not match the proposal slot in the request path"
    );
    Ok(())
}

/// Requests refused before any relay is contacted, one row per status: a
/// missing required header, an unsupported media type and an unacceptable
/// Accept.
#[tokio::test]
async fn test_get_execution_payload_bid_rejected_before_relays() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;
    // Unlabeled, so JSON (builder-specs)
    let body = serde_json::to_vec(&opaque_auth(TEST_AUTH_DATA, TEST_SLOT))?;

    // (headers dropped, header added, expected status, message excerpt)
    let cases = [
        (
            vec![CONSENSUS_VERSION_HEADER],
            None,
            StatusCode::BAD_REQUEST,
            "missing consensus version",
        ),
        (
            vec![HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS],
            None,
            StatusCode::BAD_REQUEST,
            "Invalid request: Date-Milliseconds and X-Timeout-Ms headers are required",
        ),
        (vec![], Some(("content-type", "text/plain")), StatusCode::UNSUPPORTED_MEDIA_TYPE, ""),
        (vec![], Some(("accept", "application/xml")), StatusCode::NOT_ACCEPTABLE, ""),
    ];
    for (dropped, added, status, message) in cases {
        let mut headers = vec![
            (CONSENSUS_VERSION_HEADER, "gloas".to_string()),
            (HEADER_START_TIME_UNIX_MS, utcnow_ms().to_string()),
            (HEADER_TIMEOUT_MS, "60000".to_string()),
        ];
        headers.retain(|(name, _)| !dropped.contains(name));
        if let Some((name, value)) = added {
            headers.push((name, value.to_string()));
        }

        let mut req =
            mock_validator.comm_boost.client.post(bid_url(&mock_validator)).body(body.clone());
        for (name, value) in &headers {
            req = req.header(*name, value);
        }
        let res = req.send().await?;
        assert_eq!(res.status(), status, "headers: {headers:?}");
        let json: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
        assert_eq!(json["code"], status.as_u16(), "{json}");
        assert!(json["message"].as_str().unwrap_or_default().contains(message), "{json}");
    }
    assert_eq!(mock_state.received_execution_payload_bid(), 0, "rejected before any relay");
    Ok(())
}

/// A deadline that has already passed means there is no time to serve the
/// request: CB returns 204 rather than calling a relay it cannot beat, or
/// looking up a dial target (`localhost` would be refused with 400).
#[tokio::test]
async fn test_get_execution_payload_bid_expired_deadline_204() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;
    let url = mock_validator.comm_boost.get_execution_payload_bid_url(
        TEST_SLOT,
        &B256::ZERO,
        &B256::ZERO,
        &random_secret().public_key(),
    )?;
    for auth_data in [TEST_AUTH_DATA, b"localhost"] {
        let res = mock_validator
            .comm_boost
            .client
            .post(url.clone())
            .header(HEADER_START_TIME_UNIX_MS, utcnow_ms() - 5_000)
            .header(HEADER_TIMEOUT_MS, 1_000u64)
            .header("Eth-Consensus-Version", "gloas")
            .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
            .body(opaque_auth(auth_data, TEST_SLOT).as_ssz_bytes())
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }
    assert_eq!(mock_state.received_execution_payload_bid(), 0, "no relay call past the deadline");
    Ok(())
}

#[tokio::test]
async fn test_get_execution_payload_bid_spec_url() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;

    let url = bid_url(&mock_validator);
    // The auth body, timing headers and version header are required, so even
    // the bare-URL shape test must carry them
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
        .header(HEADER_TIMEOUT_MS, 60_000u64)
        .header("Eth-Consensus-Version", "gloas")
        .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
        .body(opaque_auth(TEST_AUTH_DATA, TEST_SLOT).as_ssz_bytes())
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock_state.received_execution_payload_bid(), 1);
    Ok(())
}

/// The beacon node's `Eth-Consensus-Version` parses in any case, and CB sends
/// the spec's lowercase name on to the relay and back in the 200
#[tokio::test]
async fn test_get_execution_payload_bid_sends_the_spec_consensus_version() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;
    let res = mock_validator
        .comm_boost
        .client
        .post(bid_url(&mock_validator))
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
        .header(HEADER_TIMEOUT_MS, 60_000u64)
        .header(CONSENSUS_VERSION_HEADER, "GLOAS")
        .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
        .body(opaque_auth(TEST_AUTH_DATA, TEST_SLOT).as_ssz_bytes())
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    let echoed = res.headers().get(CONSENSUS_VERSION_HEADER).and_then(|v| v.to_str().ok());
    assert_eq!(echoed, Some("gloas"));
    assert_eq!(mock_state.received_bid_consensus_version().as_deref(), Some("gloas"));
    Ok(())
}

/// The response encoding follows the caller's Accept and defaults to JSON when
/// none is sent (builder-specs), and the 200 carries Eth-Consensus-Version
/// either way. Default relays answer in SSZ; the JSON-only relays cover the
/// relay's JSON passed through and converted to SSZ.
#[tokio::test]
async fn test_get_execution_payload_bid_response_encoding() -> Result<()> {
    let chain = Chain::Hoodi;
    let cases = [
        (vec![], MockRelayState::new(chain, random_secret()), EncodingType::Json),
        (vec![EncodingType::Ssz], MockRelayState::new(chain, random_secret()), EncodingType::Ssz),
        (
            vec![EncodingType::Json],
            MockRelayState::new(chain, random_secret()).with_json_only_response(),
            EncodingType::Json,
        ),
        (
            vec![EncodingType::Ssz],
            MockRelayState::new(chain, random_secret()).with_json_only_response(),
            EncodingType::Ssz,
        ),
    ];
    for (accept, relay, expected) in cases {
        let (mock_validator, _) = setup_relays(chain, vec![relay]).await?;
        let auth = opaque_auth(TEST_AUTH_DATA, TEST_SLOT);
        let res = mock_validator
            .do_get_execution_payload_bid(
                TEST_SLOT,
                B256::ZERO,
                B256::ZERO,
                None,
                Some(&auth),
                accept,
            )
            .await?;
        assert_eq!(res.status(), StatusCode::OK, "{expected}");

        let header =
            |name| res.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
        assert_eq!(header(CONTENT_TYPE.as_str()), Some(expected.to_string()));
        assert_eq!(header(CONSENSUS_VERSION_HEADER).as_deref(), Some("gloas"), "{expected}");

        let body = res.bytes().await?;
        let (slot, block_hash) = match expected {
            EncodingType::Ssz => {
                let bid = SignedExecutionPayloadBid::from_ssz_bytes(&body)
                    .expect("body must SSZ-decode to a SignedExecutionPayloadBid");
                (bid.message.slot.as_u64(), bid.message.block_hash.0)
            }
            EncodingType::Json => {
                let bid = serde_json::from_slice::<GetExecutionPayloadBidResponse>(&body)?;
                (bid.data.message.slot.as_u64(), bid.data.message.block_hash.0)
            }
        };
        assert_eq!(slot, TEST_SLOT, "{expected}");
        assert_ne!(block_hash, B256::ZERO, "{expected}");
    }
    Ok(())
}

/// A beacon node that asks for the relay's encoding gets the relay's body byte
/// for byte; a re-encode would drop the pretty-printing
#[tokio::test]
async fn test_get_execution_payload_bid_json_passthrough() -> Result<()> {
    let chain = Chain::Hoodi;
    let relay = MockRelayState::new(chain, random_secret())
        .with_json_only_response()
        .with_pretty_json_bid();
    let (mock_validator, states) = setup_relays(chain, vec![relay]).await?;

    let res = get_json_bid(&mock_validator, &opaque_auth(TEST_AUTH_DATA, TEST_SLOT)).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(Some(res.bytes().await?), states[0].served_bid());
    Ok(())
}

/// An SSZ bid without `Eth-Consensus-Version` cannot be forwarded, since CB's
/// 200 must name the fork: that relay contributes no bid, so the request is a
/// 204. The relay is still contacted, so the 204 proves the drop.
#[tokio::test]
async fn test_get_execution_payload_bid_unversioned_ssz_bid_dropped() -> Result<()> {
    let relay = MockRelayState::new(Chain::Hoodi, random_secret())
        .with_ssz_only_response()
        .with_epbs_omit_consensus_version();
    let (mock_validator, states) = setup_relays(Chain::Hoodi, vec![relay]).await?;
    let res = get_json_bid(&mock_validator, &opaque_auth(TEST_AUTH_DATA, TEST_SLOT)).await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(states[0].received_execution_payload_bid(), 1);
    Ok(())
}

/// A relay error is a no-bid 204, not a 502, except the builder's own 400 and
/// 401, which reach the proposer.
#[tokio::test]
async fn test_get_execution_payload_bid_relay_status() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;

    // (builder's answer, CB's answer)
    let cases = [
        (StatusCode::INTERNAL_SERVER_ERROR, StatusCode::NO_CONTENT),
        (StatusCode::BAD_REQUEST, StatusCode::BAD_REQUEST),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED),
    ];
    for (builder, expected) in cases {
        mock_state.set_response_override(builder);
        let res = get_json_bid(&mock_validator, &opaque_auth(TEST_AUTH_DATA, TEST_SLOT)).await?;
        assert_eq!(res.status(), expected, "builder answered {builder}");
    }
    assert_eq!(mock_state.received_execution_payload_bid(), 3);
    Ok(())
}

/// An error body over PBS's 1 KiB read cap still reports the builder's status.
#[tokio::test]
async fn test_get_execution_payload_bid_large_error_body() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) =
        setup_relays(chain, vec![MockRelayState::new(chain, random_secret()).with_large_body()])
            .await?;
    for status in [StatusCode::BAD_REQUEST, StatusCode::UNAUTHORIZED] {
        states[0].set_response_override(status);
        let res = get_json_bid(&mock_validator, &opaque_auth(TEST_AUTH_DATA, TEST_SLOT)).await?;
        assert_eq!(res.status(), status);
    }
    Ok(())
}

/// A relay slower than the proposer's `X-Timeout-Ms` is dropped, so the request
/// degrades to 204 rather than waiting the relay out.
#[tokio::test]
async fn test_get_execution_payload_bid_slow_relay_times_out_204() -> Result<()> {
    const DELAY_MS: u64 = 600;
    const BUDGET_MS: u64 = 200;

    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()).with_bid_delay_ms(DELAY_MS),
    ])
    .await?;

    let auth = opaque_auth(TEST_AUTH_DATA, TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid_with_timeout(
            TEST_SLOT,
            B256::ZERO,
            B256::ZERO,
            None,
            Some(&auth),
            vec![EncodingType::Json],
            BUDGET_MS,
        )
        .await?;
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "a relay slower than the deadline is dropped, not awaited"
    );
    assert_eq!(states[0].received_execution_payload_bid(), 1, "the relay was still contacted");
    Ok(())
}

/// The relay gets CB's own timing headers, not the beacon node's: an
/// `X-Timeout-Ms` of five slots is clamped to one 12 s slot, less the 100 ms
/// buffer. The mock relay 400s a request missing either header, so the 200
/// also proves `Date-Milliseconds` arrived.
#[tokio::test]
async fn test_get_execution_payload_bid_relay_timing_headers() -> Result<()> {
    let (mock_validator, mock_state) =
        setup_relay(Chain::Hoodi, |cfg| cfg.proposer_deadline_buffer_ms = 100, generate_mock_relay)
            .await?;

    let auth = opaque_auth(TEST_AUTH_DATA, TEST_SLOT);
    let res = mock_validator
        .do_get_execution_payload_bid_with_timeout(
            TEST_SLOT,
            B256::ZERO,
            B256::ZERO,
            None,
            Some(&auth),
            vec![EncodingType::Json],
            60_000,
        )
        .await?;
    assert_eq!(res.status(), StatusCode::OK);
    let timeout_ms = mock_state.received_bid_timeout_ms().expect("relay saw X-Timeout-Ms");
    assert!(0 < timeout_ms && timeout_ms <= 11_900, "relay saw X-Timeout-Ms {timeout_ms}");
    Ok(())
}

/// Auth data naming Commit-Boost's own URL is dialed once: the second hop, from
/// a Commit-Boost, answers 400 and the beacon node gets it
#[tokio::test]
async fn test_get_execution_payload_bid_dial_self_400() -> Result<()> {
    // As if Commit-Boost's own address were public
    cb_pbs::set_skip_dial_target_check(true);
    let (mock_validator, cfg_state) =
        setup_relay(Chain::Hoodi, |_| {}, generate_mock_relay).await?;
    let own = &mock_validator.comm_boost.config.entry.url;
    let own = format!("http://{}:{}/", own.host_str().unwrap(), own.port().unwrap());

    let res = get_json_bid(&mock_validator, &opaque_auth(own.as_bytes(), TEST_SLOT)).await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["message"], "The addressed builder rejected the request with status 400");
    assert_eq!(cfg_state.received_execution_payload_bid(), 0);
    Ok(())
}
