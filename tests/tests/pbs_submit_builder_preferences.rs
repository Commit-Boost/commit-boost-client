use cb_common::{
    pbs::{BuilderPreferences, BuilderPreferencesRequest, SignedBuilderRequestAuth},
    signer::random_secret,
    types::Chain,
    utils::utcnow_ms,
    wire::{CONSENSUS_VERSION_HEADER, EncodingType},
};
use cb_tests::{
    mock_relay::MockRelayState,
    utils::{
        TEST_AUTH_DATA, generate_mock_relay, opaque_auth, setup_relay, setup_relays,
        setup_relays_on_hosts, spawn_mock_relay,
    },
};
use eyre::Result;
use reqwest::{StatusCode, header::CONTENT_TYPE};

const TEST_MAX_EXECUTION_PAYMENT: u64 = 1_000_000_000;

/// CB does not gate preferences on slot age, so a fixed slot serves.
const TEST_SLOT: u64 = 100;

/// A slot that has already ended. Saturating: a chain whose genesis is under 10
/// slots old would otherwise underflow rather than yield slot 0.
fn past_slot(chain: Chain) -> u64 {
    let now_sec = utcnow_ms() / 1_000;
    ((now_sec.saturating_sub(chain.genesis_time_sec())) / chain.slot_time_sec()).saturating_sub(10)
}

fn preferences(
    auth: SignedBuilderRequestAuth,
    max_execution_payment: u64,
) -> BuilderPreferencesRequest {
    BuilderPreferencesRequest { auth, preferences: BuilderPreferences { max_execution_payment } }
}

/// The happy path: an SSZ submission reaches the builder as a 202, with the
/// preferences and the auth forwarded unchanged.
#[tokio::test]
async fn test_submit_builder_preferences() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let auth = opaque_auth(TEST_AUTH_DATA, TEST_SLOT);
    let request = preferences(auth.clone(), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(mock_state.received_builder_preferences(), 1);
    assert_eq!(mock_state.received_max_execution_payment(), Some(TEST_MAX_EXECUTION_PAYMENT));

    // The builder verifies what the proposer signed, so the auth must survive
    // the hop byte for byte
    let forwarded = mock_state.received_preferences_auth().expect("auth forwarded");
    assert_eq!(forwarded.message.data.to_vec(), TEST_AUTH_DATA.to_vec());
    assert_eq!(forwarded.message.slot, auth.message.slot);
    assert_eq!(forwarded.signature, auth.signature);

    // A builder files preferences per proposer, so the wrong path segment would
    // store them against the wrong validator
    assert_eq!(
        mock_state.received_preferences_pubkey(),
        Some(mock_validator.comm_boost.pubkey().clone()),
        "preferences must be filed under the proposer from the request path"
    );
    Ok(())
}

/// The JSON wire form is the spec's, not merely whatever our own Serialize
/// produces: Gwei and slot are quoted strings and `data` is hex. Built from a
/// literal so that dropping the serde attributes fails here instead of
/// round-tripping through the same impl the assertion uses. Quotes on the Gwei
/// are optional on decode by ecosystem convention, so the unquoted number is
/// accepted too.
#[tokio::test]
async fn test_submit_builder_preferences_json_wire_form() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    let slot = TEST_SLOT;
    let url = mock_validator
        .comm_boost
        .submit_builder_preferences_url(&mock_validator.comm_boost.pubkey().clone())?;

    for max_execution_payment in [
        serde_json::json!(TEST_MAX_EXECUTION_PAYMENT.to_string()),
        serde_json::json!(TEST_MAX_EXECUTION_PAYMENT),
    ] {
        let body = serde_json::json!({
            "preferences": { "max_execution_payment": max_execution_payment },
            "auth": {
                // "0.0.0.0", the mock relay's hostname
                "message": { "data": "0x302e302e302e30", "slot": slot.to_string() },
                "signature": format!("0x{}", "0".repeat(192)),
            }
        });
        let res = mock_validator
            .comm_boost
            .client
            .post(url.clone())
            .header(CONTENT_TYPE, EncodingType::Json.content_type_header().clone())
            .header(CONSENSUS_VERSION_HEADER, "gloas")
            .body(serde_json::to_vec(&body)?)
            .send()
            .await?;

        assert_eq!(res.status(), StatusCode::ACCEPTED, "{body}");
        assert_eq!(mock_state.received_max_execution_payment(), Some(TEST_MAX_EXECUTION_PAYMENT));
        let forwarded = mock_state.received_preferences_auth().expect("auth forwarded");
        assert_eq!(forwarded.message.data.to_vec(), TEST_AUTH_DATA.to_vec());
        assert_eq!(forwarded.message.slot.as_u64(), slot);
    }
    Ok(())
}

/// Requests refused before any builder is asked, with an ErrorMessage body:
/// `Eth-Consensus-Version` is required for JSON and SSZ alike (builder-specs
/// #165), and an unsupported media type is a 415, distinct from the 400 of a
/// malformed body. The per-rule detail (both encodings, the JSON default, an
/// empty body) is pinned once in the wire.rs decoder test.
#[tokio::test]
async fn test_submit_builder_preferences_rejected_before_builders() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    let request = preferences(opaque_auth(TEST_AUTH_DATA, TEST_SLOT), TEST_MAX_EXECUTION_PAYMENT);
    let url = mock_validator
        .comm_boost
        .submit_builder_preferences_url(&mock_validator.comm_boost.pubkey().clone())?;

    // (Content-Type, Eth-Consensus-Version, body, expected status, message excerpt)
    let cases = [
        (
            "application/json",
            None,
            serde_json::to_vec(&request)?,
            StatusCode::BAD_REQUEST,
            "missing consensus version",
        ),
        ("text/plain", Some("gloas"), b"nonsense".to_vec(), StatusCode::UNSUPPORTED_MEDIA_TYPE, ""),
    ];
    for (content_type, version, body, status, message) in cases {
        let mut req =
            mock_validator.comm_boost.client.post(url.clone()).header(CONTENT_TYPE, content_type);
        if let Some(version) = version {
            req = req.header(CONSENSUS_VERSION_HEADER, version);
        }
        let res = req.body(body).send().await?;
        assert_eq!(res.status(), status, "{content_type}");
        let json: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
        assert_eq!(json["code"], status.as_u16(), "{json}");
        assert!(json["message"].as_str().unwrap_or_default().contains(message), "{json}");
    }
    assert_eq!(mock_state.received_builder_preferences(), 0, "rejected before any builder");
    Ok(())
}

/// CB does not gate preferences on slot age: freshness (rejecting a stale or
/// replayed submission) is the builder's call, not the relay's, so CB forwards
/// regardless. A preference naming a slot that has already ended still reaches
/// the builder and is accepted.
#[tokio::test]
async fn test_submit_builder_preferences_past_slot_forwarded() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, past_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(mock_state.received_builder_preferences(), 1, "past-slot preference is forwarded");
    Ok(())
}

/// Auth data that is neither a hostname nor a URL is a 400 with the builder's
/// data-mismatch message: CB has no builder to proxy to, and proposer-private
/// preferences must never broadcast to builders the proposer did not address.
#[tokio::test]
async fn test_submit_builder_preferences_unmatched_auth_data_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let request = preferences(opaque_auth(&[0xbe, 0xef], TEST_SLOT), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mock_state.received_builder_preferences(), 0, "no relay receives anything");
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert_eq!(
        body["message"],
        "Invalid SignedBuilderRequestAuth: auth.message.data does not match any configured builder"
    );
    Ok(())
}

/// The addressed builder's answer: only 202 is an acceptance. Its 400 and
/// 401 propagate, so the proposer can see the spec's rejection and
/// authentication failure, with a CB-written message rather than the
/// builder's untrusted body. Any other status, another 2xx included, is the
/// blanket 500; the 503 row is not itself a 500, so passthrough would show.
#[tokio::test]
async fn test_submit_builder_preferences_builder_status() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    let request = preferences(opaque_auth(TEST_AUTH_DATA, TEST_SLOT), TEST_MAX_EXECUTION_PAYMENT);

    // (builder's answer, CB's answer)
    let cases = [
        (StatusCode::OK, StatusCode::INTERNAL_SERVER_ERROR),
        (StatusCode::BAD_REQUEST, StatusCode::BAD_REQUEST),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED),
        (StatusCode::SERVICE_UNAVAILABLE, StatusCode::INTERNAL_SERVER_ERROR),
    ];
    for (builder, expected) in cases {
        mock_state.set_response_override(builder);
        let res =
            mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;
        assert_eq!(res.status(), expected, "builder answered {builder}");
        let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
        assert_eq!(body["code"], expected.as_u16(), "{body}");
        if builder == StatusCode::BAD_REQUEST {
            assert_eq!(
                body["message"],
                "The addressed builder rejected the request with status 400"
            );
        }
    }
    assert_eq!(mock_state.received_builder_preferences(), 4, "the builder is asked every time");
    Ok(())
}

/// An error body over PBS's 1 KiB read cap still reports the builder's status.
#[tokio::test]
async fn test_submit_builder_preferences_large_error_body() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) =
        setup_relays(chain, vec![MockRelayState::new(chain, random_secret()).with_large_body()])
            .await?;
    states[0].set_response_override(StatusCode::UNAUTHORIZED);
    let request = preferences(opaque_auth(TEST_AUTH_DATA, TEST_SLOT), TEST_MAX_EXECUTION_PAYMENT);

    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

/// Two relays on distinct hostnames: preferences addressing one must reach
/// only that builder, the other's received counter stays 0.
#[tokio::test]
async fn test_submit_builder_preferences_two_relays_addressed_one_only() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays_on_hosts(chain, vec![
        (MockRelayState::new(chain, random_secret()), "0.0.0.0"),
        (MockRelayState::new(chain, random_secret()), "127.0.0.1"),
    ])
    .await?;

    // The second relay, so that asking the first configured one would fail
    let request = preferences(opaque_auth(b"127.0.0.1", TEST_SLOT), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(states[0].received_builder_preferences(), 0, "the unaddressed builder is not");
    assert_eq!(states[1].received_builder_preferences(), 1, "the addressed builder is asked");
    Ok(())
}

/// Preferences whose auth data names a builder outside the config are sent
/// to it by a dial and accepted with its 202
#[tokio::test]
async fn test_submit_builder_preferences_dial() -> Result<()> {
    // The mock builder listens on an address the dial check refuses
    cb_pbs::set_skip_dial_target_check(true);
    let chain = Chain::Hoodi;
    let (mock_validator, _) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    let (dial_state, dial_port) =
        spawn_mock_relay(MockRelayState::new(chain, random_secret())).await?;

    let auth = opaque_auth(format!("http://0.0.0.0:{dial_port}/").as_bytes(), TEST_SLOT);
    let request = preferences(auth, TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(dial_state.received_builder_preferences(), 1);
    Ok(())
}
