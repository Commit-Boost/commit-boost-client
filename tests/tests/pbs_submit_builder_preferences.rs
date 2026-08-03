use cb_common::{
    pbs::{BuilderPreferencesRequestV1, BuilderPreferencesV1, SignedRequestAuthV1},
    signer::random_secret,
    types::Chain,
    utils::utcnow_ms,
    wire::EncodingType,
};
use cb_tests::{
    mock_relay::MockRelayState,
    utils::{
        generate_mock_relay, generate_mock_relay_with_auth_data, opaque_auth, setup_relay,
        setup_relays, signed_auth,
    },
};
use eyre::Result;
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::Encode;

const TEST_AUTH_DATA: &[u8] = &[0xde, 0xad];
const TEST_MAX_EXECUTION_PAYMENT: u64 = 1_000_000_000;

/// A slot comfortably ahead of now. Preferences name the proposal slot they
/// apply to, and one that has already ended is rejected, so tests cannot use a
/// fixed constant the way the bid tests do.
fn future_slot(chain: Chain) -> u64 {
    let now_sec = utcnow_ms() / 1_000;
    (now_sec.saturating_sub(chain.genesis_time_sec())) / chain.slot_time_sec() + 10
}

/// A slot that has already ended. Saturating: a chain whose genesis is under 10
/// slots old would otherwise underflow rather than yield slot 0.
fn past_slot(chain: Chain) -> u64 {
    let now_sec = utcnow_ms() / 1_000;
    ((now_sec.saturating_sub(chain.genesis_time_sec())) / chain.slot_time_sec()).saturating_sub(10)
}

fn preferences(
    auth: SignedRequestAuthV1,
    max_execution_payment: u64,
) -> BuilderPreferencesRequestV1 {
    BuilderPreferencesRequestV1 {
        auth,
        preferences: BuilderPreferencesV1 { max_execution_payment },
    }
}

/// The happy path: an SSZ submission reaches the builder as a 202, with the
/// preferences and the auth forwarded unchanged.
#[tokio::test]
async fn test_submit_builder_preferences() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let auth = opaque_auth(TEST_AUTH_DATA, future_slot(chain));
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
/// round-tripping through the same impl the assertion uses.
#[tokio::test]
async fn test_submit_builder_preferences_json_wire_form() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    let slot = future_slot(chain);

    let body = serde_json::json!({
        "preferences": { "max_execution_payment": TEST_MAX_EXECUTION_PAYMENT.to_string() },
        "auth": {
            "message": { "data": "0xdead", "slot": slot.to_string() },
            "signature": format!("0x{}", "0".repeat(192)),
        }
    });
    let url = mock_validator
        .comm_boost
        .submit_builder_preferences_url(&mock_validator.comm_boost.pubkey().clone())?;
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, EncodingType::Json.content_type_header().clone())
        .body(serde_json::to_vec(&body)?)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED, "the spec's JSON wire form must be accepted");
    assert_eq!(mock_state.received_max_execution_payment(), Some(TEST_MAX_EXECUTION_PAYMENT));
    let forwarded = mock_state.received_preferences_auth().expect("auth forwarded");
    assert_eq!(forwarded.message.data.to_vec(), TEST_AUTH_DATA.to_vec());
    assert_eq!(forwarded.message.slot.as_u64(), slot);
    Ok(())
}

/// Quotes are optional on decode by ecosystem convention, so a client sending
/// an unquoted Gwei number is still accepted even though the spec's wire form
/// is the quoted string.
#[tokio::test]
async fn test_submit_builder_preferences_unquoted_gwei_accepted() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let body = serde_json::json!({
        "preferences": { "max_execution_payment": TEST_MAX_EXECUTION_PAYMENT },
        "auth": {
            "message": { "data": "0xdead", "slot": future_slot(chain).to_string() },
            "signature": format!("0x{}", "0".repeat(192)),
        }
    });
    let url = mock_validator
        .comm_boost
        .submit_builder_preferences_url(&mock_validator.comm_boost.pubkey().clone())?;
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, EncodingType::Json.content_type_header().clone())
        .body(serde_json::to_vec(&body)?)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(mock_state.received_max_execution_payment(), Some(TEST_MAX_EXECUTION_PAYMENT));
    Ok(())
}

/// Only 202 means the builder committed to storing the preferences. Another 2xx
/// must not be reported to the proposer as acceptance.
#[tokio::test]
async fn test_submit_builder_preferences_non_202_success_is_failure() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    mock_state.set_response_override(StatusCode::OK);

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_ne!(res.status(), StatusCode::ACCEPTED, "a 200 from the builder is not an acceptance");
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

/// A signature valid under one key submitted at another proposer's path must be
/// rejected: the auth is only meaningful bound to the pubkey it is filed under.
#[tokio::test]
async fn test_submit_builder_preferences_signature_bound_to_path_pubkey() -> Result<()> {
    let chain = Chain::Hoodi;
    let signer = random_secret();
    let other_pubkey = random_secret().public_key().into();
    let (mock_validator, mock_state) =
        setup_relay(chain, |config| config.verify_request_auth = true, generate_mock_relay).await?;

    // Genuinely signed, just not by the proposer named in the path
    let auth = signed_auth(&signer, TEST_AUTH_DATA, future_slot(chain), chain);
    let request = preferences(auth, TEST_MAX_EXECUTION_PAYMENT);
    let res = mock_validator
        .do_submit_builder_preferences(Some(other_pubkey), &request, EncodingType::Ssz)
        .await?;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(mock_state.received_builder_preferences(), 0);
    Ok(())
}

/// With no `Content-Type` the body is SSZ, which is this endpoint's documented
/// no-preference default and differs from the shared JSON default.
#[tokio::test]
async fn test_submit_builder_preferences_no_content_type_is_ssz() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let url = mock_validator
        .comm_boost
        .submit_builder_preferences_url(&mock_validator.comm_boost.pubkey().clone())?;
    let res =
        mock_validator.comm_boost.client.post(url).body(request.as_ssz_bytes()).send().await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(mock_state.received_max_execution_payment(), Some(TEST_MAX_EXECUTION_PAYMENT));
    Ok(())
}

/// An unsupported media type is a 415, distinct from the 400 a malformed body
/// of a supported type produces.
#[tokio::test]
async fn test_submit_builder_preferences_unsupported_media_type_415() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let url = mock_validator
        .comm_boost
        .submit_builder_preferences_url(&mock_validator.comm_boost.pubkey().clone())?;
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, "text/plain")
        .body("nonsense")
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(mock_state.received_builder_preferences(), 0);
    Ok(())
}

/// A JSON submission is accepted too and decodes to the same values, including
/// the quoted-string Gwei on the JSON wire.
#[tokio::test]
async fn test_submit_builder_preferences_json() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Json).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(mock_state.received_max_execution_payment(), Some(TEST_MAX_EXECUTION_PAYMENT));
    Ok(())
}

/// Preferences naming a slot that has already ended are rejected before any
/// builder is contacted: a replay must not roll preferences back to a stale
/// value.
#[tokio::test]
async fn test_submit_builder_preferences_slot_passed_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, past_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert_eq!(
        body["message"],
        "Invalid SignedRequestAuthV1: auth.message.slot has already passed"
    );
    assert_eq!(mock_state.received_builder_preferences(), 0, "no builder should be contacted");
    Ok(())
}

/// The body is required, exactly as on the bid endpoint.
#[tokio::test]
async fn test_submit_builder_preferences_missing_body_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let url = mock_validator
        .comm_boost
        .submit_builder_preferences_url(&mock_validator.comm_boost.pubkey().clone())?;
    let res = mock_validator.comm_boost.client.post(url).send().await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mock_state.received_builder_preferences(), 0);

    // Distinguish the missing-body guard from the decode failure an empty SSZ
    // body would otherwise produce, which is also a 400
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert!(
        body["message"].as_str().unwrap_or_default().contains("missing request body"),
        "expected the missing-body error, got {}",
        body["message"]
    );
    Ok(())
}

/// Preferences addressed to a builder this PBS does not serve are rejected by
/// the demux, not blindly fanned out.
#[tokio::test]
async fn test_submit_builder_preferences_auth_data_mismatch_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(
        chain,
        |config| config.strict_auth_data = true,
        |port, pubkey| generate_mock_relay_with_auth_data(port, pubkey, TEST_AUTH_DATA),
    )
    .await?;

    let request =
        preferences(opaque_auth(&[0xbe, 0xef], future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mock_state.received_builder_preferences(), 0, "the demux must not fan out");
    Ok(())
}

/// Preferences addressed by matching auth data reach that builder.
#[tokio::test]
async fn test_submit_builder_preferences_auth_data_match() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(
        chain,
        |config| config.strict_auth_data = true,
        |port, pubkey| generate_mock_relay_with_auth_data(port, pubkey, TEST_AUTH_DATA),
    )
    .await?;

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(mock_state.received_builder_preferences(), 1);
    Ok(())
}

/// With verification on, an unsigned submission is a 401 and never reaches a
/// builder.
#[tokio::test]
async fn test_submit_builder_preferences_bad_signature_401() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) =
        setup_relay(chain, |config| config.verify_request_auth = true, generate_mock_relay).await?;

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["message"], "Invalid SignedRequestAuthV1: signature verification failed");
    assert_eq!(mock_state.received_builder_preferences(), 0);
    Ok(())
}

/// With verification on, a properly signed submission is accepted.
#[tokio::test]
async fn test_submit_builder_preferences_valid_signature() -> Result<()> {
    let chain = Chain::Hoodi;
    let secret = random_secret();
    let pubkey = secret.public_key().into();
    let (mock_validator, mock_state) =
        setup_relay(chain, |config| config.verify_request_auth = true, generate_mock_relay).await?;

    let auth = signed_auth(&secret, TEST_AUTH_DATA, future_slot(chain), chain);
    let request = preferences(auth, TEST_MAX_EXECUTION_PAYMENT);
    let res = mock_validator
        .do_submit_builder_preferences(Some(pubkey), &request, EncodingType::Ssz)
        .await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(mock_state.received_builder_preferences(), 1);
    Ok(())
}

/// A builder that refuses the submission is surfaced as a failure rather than
/// reported as accepted.
#[tokio::test]
async fn test_submit_builder_preferences_lone_builder_400_propagates() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    mock_state.set_response_override(StatusCode::BAD_REQUEST);

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mock_state.received_builder_preferences(), 1, "the builder was still asked");

    // The builder's own body is untrusted and must not be relayed onward
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert_eq!(body["message"], "The addressed builder rejected the submission with status 400");
    Ok(())
}

/// A lone builder's 401 propagates too, so the spec's authentication failure is
/// reachable at all rather than always collapsing into a 502.
#[tokio::test]
async fn test_submit_builder_preferences_lone_builder_401_propagates() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    mock_state.set_response_override(StatusCode::UNAUTHORIZED);

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

/// A status the spec does not sanction for this endpoint is not passed through:
/// only the builder's 400 and 401 are meaningful to the proposer.
#[tokio::test]
async fn test_submit_builder_preferences_builder_500_is_502() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    mock_state.set_response_override(StatusCode::INTERNAL_SERVER_ERROR);

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

/// Two addressed builders both reject: with more than one addressed builder no
/// single verdict is unambiguous, so even a 400 (which passes through for a
/// lone builder) must NOT be handed back — the result is a 502 NoResponse. The
/// inverse of `lone_builder_400_propagates`, guarding the `relays.len() == 1`
/// condition in the route.
#[tokio::test]
async fn test_submit_builder_preferences_two_relays_all_reject_502() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;

    // Both reject with a 400: a lone builder's 400 propagates, so two of them
    // must prove the multi-builder path collapses to 502 instead.
    for state in &states {
        state.set_response_override(StatusCode::BAD_REQUEST);
    }

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(
        res.status(),
        StatusCode::BAD_GATEWAY,
        "two rejecting builders collapse to 502, not a 400 passthrough"
    );
    assert_eq!(states[0].received_builder_preferences(), 1, "each addressed builder is asked");
    assert_eq!(states[1].received_builder_preferences(), 1, "each addressed builder is asked");
    Ok(())
}

/// Two addressed builders, one accepts and one rejects: they are separate
/// destinations, not replicas, so a single acceptance is a successful 202.
#[tokio::test]
async fn test_submit_builder_preferences_two_relays_one_accepts_202() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;

    // The first rejects; the second accepts by default
    states[0].set_response_override(StatusCode::INTERNAL_SERVER_ERROR);

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(
        res.status(),
        StatusCode::ACCEPTED,
        "one accepting builder makes the submission a success"
    );
    assert_eq!(states[0].received_builder_preferences(), 1, "each addressed builder is asked");
    assert_eq!(states[1].received_builder_preferences(), 1, "each addressed builder is asked");
    Ok(())
}
