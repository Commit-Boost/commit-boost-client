use cb_common::{
    pbs::{BuilderPreferences, BuilderPreferencesRequest, SignedRequestAuth},
    signer::random_secret,
    types::Chain,
    utils::utcnow_ms,
    wire::{CONSENSUS_VERSION_HEADER, EncodingType},
};
use std::{path::PathBuf, sync::Arc};

use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::MockValidator,
    utils::{
        TEST_AUTH_DATA, generate_mock_relay, generate_mock_relay_url_only,
        generate_mock_relay_with_auth_data, get_free_listener, get_pbs_config, opaque_auth,
        setup_relay, setup_relays, setup_relays_with_auth_data, setup_test_env, signed_auth,
        to_pbs_config, wait_for_ready,
    },
};
use eyre::Result;
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::Encode;
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

fn preferences(auth: SignedRequestAuth, max_execution_payment: u64) -> BuilderPreferencesRequest {
    BuilderPreferencesRequest { auth, preferences: BuilderPreferences { max_execution_payment } }
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
        .header(CONSENSUS_VERSION_HEADER, "gloas")
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
        .header(CONSENSUS_VERSION_HEADER, "gloas")
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
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

/// A signature valid under one key submitted at another proposer's path must be
/// rejected: the auth is only meaningful bound to the pubkey it is filed under.
#[tokio::test]
async fn test_submit_builder_preferences_signature_bound_to_path_pubkey() -> Result<()> {
    let chain = Chain::Hoodi;
    let signer = random_secret();
    let other_pubkey = random_secret().public_key();
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
/// no-preference default and differs from the shared JSON default. The version
/// header still travels: an SSZ-default body requires it like explicit SSZ.
#[tokio::test]
async fn test_submit_builder_preferences_no_content_type_is_ssz() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let url = mock_validator
        .comm_boost
        .submit_builder_preferences_url(&mock_validator.comm_boost.pubkey().clone())?;
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header("Eth-Consensus-Version", "gloas")
        .body(request.as_ssz_bytes())
        .send()
        .await?;

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

/// An SSZ submission missing `Eth-Consensus-Version` is a 400: builder-specs
/// fork-versions the request wire type, so the header is required to accept the
/// SSZ form (and the same submission with the header is a 202).
#[tokio::test]
async fn test_submit_builder_preferences_ssz_missing_version_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let url = mock_validator
        .comm_boost
        .submit_builder_preferences_url(&mock_validator.comm_boost.pubkey().clone())?;
    // Note: SSZ Content-Type but no Eth-Consensus-Version
    let res = mock_validator
        .comm_boost
        .client
        .post(url.clone())
        .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
        .body(request.as_ssz_bytes())
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        mock_state.received_builder_preferences(),
        0,
        "an undecodable request must not forward"
    );
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);

    // The identical submission carrying the literal spec header is accepted
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
        .header("Eth-Consensus-Version", "gloas")
        .body(request.as_ssz_bytes())
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(mock_state.received_builder_preferences(), 1);
    Ok(())
}

/// builder-specs marks `Eth-Consensus-Version` required for JSON and SSZ alike
/// (builder-specs #165): a JSON submission without it is a 400.
#[tokio::test]
async fn test_submit_builder_preferences_json_no_version_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let url = mock_validator
        .comm_boost
        .submit_builder_preferences_url(&mock_validator.comm_boost.pubkey().clone())?;
    // No Eth-Consensus-Version: required regardless of encoding
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .header(CONTENT_TYPE, EncodingType::Json.content_type_header().clone())
        .body(serde_json::to_vec(&request)?)
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await?;
    assert!(
        body["message"].as_str().unwrap_or_default().contains("missing consensus version"),
        "the 400 must name the missing header: {body}"
    );
    assert_eq!(mock_state.received_builder_preferences(), 0, "rejected before any builder");
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
    assert_eq!(body["message"], "Invalid SignedRequestAuth: auth.message.slot has already passed");
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

/// PIPE: preferences whose auth data names a builder URL outside CB's config
/// are forwarded to it via the same transient-client pipe as the bid endpoint
/// and accepted with the builder's 202.
#[tokio::test]
async fn test_submit_builder_preferences_pipe_dials_unconfigured_builder() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;
    let pbs_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr()?.port();

    // A configured relay, addressed by opaque bytes only
    let cfg_listener = get_free_listener().await;
    let cfg_port = cfg_listener.local_addr()?.port();
    let cfg_state = Arc::new(MockRelayState::new(chain, random_secret()));
    let cfg_relay =
        generate_mock_relay_with_auth_data(cfg_port, cfg_state.signer.public_key(), &[0xaa])?;
    tokio::spawn(start_mock_relay_service_with_listener(cfg_state.clone(), cfg_listener));

    // The pipe builder runs but is NOT in CB's config
    let pipe_listener = get_free_listener().await;
    let pipe_port = pipe_listener.local_addr()?.port();
    let pipe_state = Arc::new(MockRelayState::new(chain, random_secret()));
    tokio::spawn(start_mock_relay_service_with_listener(pipe_state.clone(), pipe_listener));

    let mut pbs_config = get_pbs_config(pbs_port);
    pbs_config.advertised_urls = vec!["http://cb.self.example:18550".parse()?];
    let config = to_pbs_config(chain, pbs_config, vec![cfg_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    let mock_validator = MockValidator::new(pbs_port)?;
    wait_for_ready(&mock_validator).await?;

    let pipe_url = format!("http://0.0.0.0:{pipe_port}/");
    let auth = opaque_auth(pipe_url.as_bytes(), future_slot(chain));
    let request = preferences(auth, TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(pipe_state.received_builder_preferences(), 1);
    assert_eq!(cfg_state.received_builder_preferences(), 0, "only the piped builder is dialed");
    assert_eq!(pipe_state.received_max_execution_payment(), Some(TEST_MAX_EXECUTION_PAYMENT));
    let forwarded = pipe_state.received_preferences_auth().expect("auth forwarded");
    assert_eq!(forwarded.message.data.to_vec(), pipe_url.as_bytes().to_vec());
    Ok(())
}

/// PIPE self-URL guard, preferences side: auth data decoding to one of CB's
/// `advertised_urls` is a clean 400 and nothing is dialed; with
/// `advertised_urls` unset the guard fails closed the same way.
#[tokio::test]
async fn test_submit_builder_preferences_pipe_self_url_not_dialed() -> Result<()> {
    setup_test_env();
    let chain = Chain::Hoodi;

    for advertise_self in [true, false] {
        let pbs_listener = get_free_listener().await;
        let pbs_port = pbs_listener.local_addr()?.port();
        let relay_listener = get_free_listener().await;
        let relay_port = relay_listener.local_addr()?.port();

        // The mock stands in for whatever answers at the named URL: anything
        // it receives means a dial went out
        let mock_state = Arc::new(MockRelayState::new(chain, random_secret()));
        let mock_relay = generate_mock_relay_with_auth_data(
            relay_port,
            mock_state.signer.public_key(),
            &[0xaa],
        )?;
        tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

        let self_url = format!("http://0.0.0.0:{relay_port}/");
        let mut pbs_config = get_pbs_config(pbs_port);
        if advertise_self {
            pbs_config.advertised_urls = vec![self_url.parse()?];
        }
        let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
        let state = PbsState::new(config, PathBuf::new());
        tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

        let mock_validator = MockValidator::new(pbs_port)?;
        wait_for_ready(&mock_validator).await?;

        let auth = opaque_auth(self_url.as_bytes(), future_slot(chain));
        let request = preferences(auth, TEST_MAX_EXECUTION_PAYMENT);
        let res =
            mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "advertise_self={advertise_self}");
        assert_eq!(
            mock_state.received_builder_preferences(),
            0,
            "no dial (advertise_self={advertise_self})"
        );
    }
    Ok(())
}

/// Preferences addressed to a builder this PBS does not serve are rejected by
/// the demux, not blindly fanned out.
#[tokio::test]
async fn test_submit_builder_preferences_auth_data_mismatch_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(
        chain,
        |_| {},
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

/// Opaque data matching no relay is a 400 with the builder's data-mismatch
/// message even when a relay declares no `expected_auth_data`: unmatched means
/// CB has no builder to proxy to, and proposer-private preferences must never
/// broadcast to builders the proposer did not address.
#[tokio::test]
async fn test_submit_builder_preferences_unmatched_opaque_auth_400() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) =
        setup_relay(chain, |_| {}, generate_mock_relay_url_only).await?;

    let request =
        preferences(opaque_auth(&[0xbe, 0xef], future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mock_state.received_builder_preferences(), 0, "no relay receives anything");
    let body: serde_json::Value = serde_json::from_slice(&res.bytes().await?)?;
    assert_eq!(body["code"], 400);
    assert_eq!(
        body["message"],
        "Invalid SignedRequestAuth: auth.message.data does not match the value agreed with this builder"
    );
    Ok(())
}

/// Preferences addressed by matching auth data reach that builder.
#[tokio::test]
async fn test_submit_builder_preferences_auth_data_match() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(
        chain,
        |_| {},
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
    assert_eq!(body["message"], "Invalid SignedRequestAuth: signature verification failed");
    assert_eq!(mock_state.received_builder_preferences(), 0);
    Ok(())
}

/// With verification on, a properly signed submission is accepted.
#[tokio::test]
async fn test_submit_builder_preferences_valid_signature() -> Result<()> {
    let chain = Chain::Hoodi;
    let secret = random_secret();
    let pubkey = secret.public_key();
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
/// reachable at all rather than always collapsing into the blanket failure.
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
/// only the builder's 400 and 401 are meaningful to the proposer. The override
/// is 503, NOT 500, so passthrough and the NoBuilderResponse fallback produce
/// different codes and the assertion discriminates (a 500 override could not).
#[tokio::test]
async fn test_submit_builder_preferences_builder_503_is_500() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, mock_state) = setup_relay(chain, |_| {}, generate_mock_relay).await?;
    mock_state.set_response_override(StatusCode::SERVICE_UNAVAILABLE);

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

/// Two addressed builders both reject: with more than one addressed builder no
/// single verdict is unambiguous, so even a 400 (which passes through for a
/// lone builder) must NOT be handed back — the result is a blanket 500
/// (`NoBuilderResponse`; 502 is not in the spec's declared response set). The
/// inverse of `lone_builder_400_propagates`, guarding the `relays.len() == 1`
/// condition in the route.
#[tokio::test]
async fn test_submit_builder_preferences_two_relays_all_reject_500() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays(chain, vec![
        MockRelayState::new(chain, random_secret()),
        MockRelayState::new(chain, random_secret()),
    ])
    .await?;

    // Both reject with a 400: a lone builder's 400 propagates, so two of them
    // must prove the multi-builder path collapses to the blanket 500 instead.
    for state in &states {
        state.set_response_override(StatusCode::BAD_REQUEST);
    }

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(
        res.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "two rejecting builders collapse to 500, not a 400 passthrough"
    );
    assert_eq!(states[0].received_builder_preferences(), 1, "each addressed builder is asked");
    assert_eq!(states[1].received_builder_preferences(), 1, "each addressed builder is asked");
    Ok(())
}

/// Two relays with distinct auth data: preferences addressing one must reach
/// only that builder, the other's received counter stays 0.
#[tokio::test]
async fn test_submit_builder_preferences_two_relays_addressed_one_only() -> Result<()> {
    let chain = Chain::Hoodi;
    let other_auth_data: &[u8] = &[0xbe, 0xef];
    let (mock_validator, states) = setup_relays_with_auth_data(chain, vec![
        (MockRelayState::new(chain, random_secret()), TEST_AUTH_DATA),
        (MockRelayState::new(chain, random_secret()), other_auth_data),
    ])
    .await?;

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(states[0].received_builder_preferences(), 1, "the addressed builder is asked");
    assert_eq!(states[1].received_builder_preferences(), 0, "the unaddressed builder is not");
    Ok(())
}

/// Two builders behind the same auth data, one 202 and one 400: the documented
/// any-success policy makes the submission a 202.
#[tokio::test]
async fn test_submit_builder_preferences_two_relays_one_202_one_400_is_202() -> Result<()> {
    let chain = Chain::Hoodi;
    let (mock_validator, states) = setup_relays_with_auth_data(chain, vec![
        (MockRelayState::new(chain, random_secret()), TEST_AUTH_DATA),
        (MockRelayState::new(chain, random_secret()), TEST_AUTH_DATA),
    ])
    .await?;

    // The first rejects with a 400; the second accepts by default
    states[0].set_response_override(StatusCode::BAD_REQUEST);

    let request =
        preferences(opaque_auth(TEST_AUTH_DATA, future_slot(chain)), TEST_MAX_EXECUTION_PAYMENT);
    let res =
        mock_validator.do_submit_builder_preferences(None, &request, EncodingType::Ssz).await?;

    assert_eq!(res.status(), StatusCode::ACCEPTED, "any-success: one acceptance is a 202");
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
