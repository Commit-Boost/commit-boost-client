use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use cb_common::{
    pbs::{
        BuilderApiVersion, ForkName, GetPayloadInfo, PayloadAndBlobs, SubmitBlindedBlockResponse,
    },
    signer::random_secret,
    types::Chain,
    wire::{CONSENSUS_VERSION_HEADER, EncodingType},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_tests::{
    mock_relay::{MockRelayState, start_mock_relay_service_with_listener},
    mock_validator::{MockValidator, load_test_signed_blinded_block},
    utils::{
        generate_mock_relay, get_free_listener, get_pbs_config, setup_test_env, to_pbs_config,
    },
};
use eyre::Result;
use lh_types::ForkVersionDecode;
use reqwest::{
    Response, StatusCode,
    header::{ACCEPT, CONTENT_TYPE},
};
use tracing::info;

#[tokio::test]
async fn test_submit_block_v1() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        vec![EncodingType::Json],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body = serde_json::from_slice::<SubmitBlindedBlockResponse>(&res.bytes().await?)?;
    assert_eq!(
        response_body.data.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v2() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V2,
        vec![EncodingType::Json],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
        StatusCode::ACCEPTED,
        false,
        false,
    )
    .await?;
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

// A v2 submission to a relay that does not support v2 must fail loud, not fake
// success. v2's contract is an empty 202 after which the relay publishes the
// block; a v1 payload is useless because the beacon node expects 202 and will
// not read a 200 body. So PBS returns an error (no relay could serve v2) rather
// than forwarding a v1 body the caller silently drops.
#[tokio::test]
async fn test_submit_block_v2_without_relay_support() -> Result<()> {
    let _res = submit_block_impl(
        BuilderApiVersion::V2,
        vec![EncodingType::Json],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        0, // relay 404s v2 and there is no v1 fallback, so it never receives a submit
        StatusCode::BAD_GATEWAY,
        true,
        false,
    )
    .await?;
    Ok(())
}

// Test that when submitting a block using v2 to a relay that returns 404s
// for both v1 and v2, PBS doesn't loop forever.
#[tokio::test]
async fn test_submit_block_on_broken_relay() -> Result<()> {
    let _res = submit_block_impl(
        BuilderApiVersion::V2,
        vec![EncodingType::Json],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Json,
        1,
        StatusCode::BAD_GATEWAY,
        true,
        true,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v1_ssz() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        vec![EncodingType::Ssz],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Ssz,
        1,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body =
        PayloadAndBlobs::from_ssz_bytes_by_fork(&res.bytes().await?, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

#[tokio::test]
async fn test_submit_block_v2_ssz() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V2,
        vec![EncodingType::Ssz],
        HashSet::from([EncodingType::Ssz, EncodingType::Json]),
        EncodingType::Ssz,
        1,
        StatusCode::ACCEPTED,
        false,
        false,
    )
    .await?;
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

/// Test that a v1 submit block request in SSZ is converted to JSON if the relay
/// only supports JSON
#[tokio::test]
async fn test_submit_block_v1_ssz_into_json() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        vec![EncodingType::Ssz],
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body =
        PayloadAndBlobs::from_ssz_bytes_by_fork(&res.bytes().await?, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

/// Test that a v2 submit block request in SSZ is converted to JSON if the relay
/// only supports JSON
#[tokio::test]
async fn test_submit_block_v2_ssz_into_json() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V2,
        vec![EncodingType::Ssz],
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
        StatusCode::ACCEPTED,
        false,
        false,
    )
    .await?;
    assert_eq!(res.bytes().await?.len(), 0);
    Ok(())
}

/// Test v1 requesting multiple types when the relay supports SSZ, which should
/// return SSZ
#[tokio::test]
async fn test_submit_block_v1_multitype_ssz() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        vec![EncodingType::Ssz, EncodingType::Json],
        HashSet::from([EncodingType::Ssz]),
        EncodingType::Ssz,
        1,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body =
        PayloadAndBlobs::from_ssz_bytes_by_fork(&res.bytes().await?, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

/// Test v1 requesting multiple types when the relay supports JSON, which should
/// still return SSZ
#[tokio::test]
async fn test_submit_block_v1_multitype_json() -> Result<()> {
    let res = submit_block_impl(
        BuilderApiVersion::V1,
        vec![EncodingType::Ssz, EncodingType::Json],
        HashSet::from([EncodingType::Json]),
        EncodingType::Ssz,
        2,
        StatusCode::OK,
        false,
        false,
    )
    .await?;
    let signed_blinded_block = load_test_signed_blinded_block();

    let response_body =
        PayloadAndBlobs::from_ssz_bytes_by_fork(&res.bytes().await?, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}

#[tokio::test]
async fn test_submit_block_too_large() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();

    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let relays = vec![generate_mock_relay(relay_port, pubkey)?];
    let mock_state = Arc::new(MockRelayState::new(chain, signer).with_large_body());
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), relays);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = mock_validator
        .do_submit_block_v1(None, vec![EncodingType::Json], EncodingType::Json, ForkName::Electra)
        .await;

    // response size exceeds max size: max: 20971520
    assert_eq!(res.unwrap().status(), StatusCode::BAD_GATEWAY);
    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(())
}

// A relay must not be able to have its response validated, or its version
// header forwarded to the beacon node, under a fork other than the one the
// request was for. Here the relay answers an Electra request but labels the
// JSON response Fulu; PBS must reject it rather than trust the relay-controlled
// version.
#[tokio::test]
async fn test_submit_block_rejects_fork_mismatch() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    let mut mock_relay_state =
        MockRelayState::new(chain, signer).with_submit_block_version(ForkName::Fulu);
    // JSON-only so the response parses cleanly and the rejection is on the fork
    // mismatch, not an SSZ decode error.
    mock_relay_state.supported_content_types = Arc::new(HashSet::from([EncodingType::Json]));
    let mock_state = Arc::new(mock_relay_state);
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    let res = mock_validator
        .do_submit_block_v1(
            Some(load_test_signed_blinded_block()),
            vec![EncodingType::Json],
            EncodingType::Json,
            ForkName::Electra,
        )
        .await?;

    // The relay was reached (SSZ attempt 415s on this JSON-only relay, then a
    // JSON retry carries the mismatched version), but the fork-mismatched
    // response is rejected rather than trusted.
    assert_eq!(mock_state.received_submit_block(), 2);
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

// A v2 submission does no content negotiation (its success is an empty 202), so
// an unsupported Accept header must NOT 406 the request before it reaches a
// relay. Only v1, which returns a body, negotiates on Accept.
#[tokio::test]
async fn test_submit_block_v2_ignores_unsupported_accept() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    // Default mock supports v2.
    let mock_state = Arc::new(MockRelayState::new(chain, signer));
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;
    let url = mock_validator.comm_boost.submit_block_url(BuilderApiVersion::V2).unwrap();
    let body = serde_json::to_vec(&load_test_signed_blinded_block()).unwrap();
    let res = mock_validator
        .comm_boost
        .client
        .post(url)
        .body(body)
        .header(CONTENT_TYPE, EncodingType::Json.to_string())
        .header(CONSENSUS_VERSION_HEADER, ForkName::Electra.to_string())
        .header(ACCEPT, "application/garbage")
        .send()
        .await?;

    // Reaches the relay and returns the v2 empty-202 rather than a 406.
    assert_ne!(res.status(), StatusCode::NOT_ACCEPTABLE);
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(mock_state.received_submit_block(), 1);
    Ok(())
}

/// Error responses on submit_block follow the Builder API `ErrorMessage`
/// schema: JSON `{code, message}` with `application/json`, not plain text.
#[tokio::test]
async fn test_submit_block_error_response_is_json() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let mut mock_relay_state = MockRelayState::new(chain, signer);
    mock_relay_state.supported_content_types =
        Arc::new(HashSet::from([EncodingType::Ssz, EncodingType::Json]));
    let mock_state = Arc::new(mock_relay_state);
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let config = to_pbs_config(chain, get_pbs_config(pbs_port), vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    drop(pbs_listener);
    tokio::spawn(PbsService::run::<(), DefaultBuilderApi>(state));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mock_validator = MockValidator::new(pbs_port)?;

    // Happy path: a valid v1 submit returns 200 with the payload (parses as the
    // payload, which an error envelope would not).
    let ok = mock_validator
        .do_submit_block_v1(
            Some(load_test_signed_blinded_block()),
            vec![EncodingType::Json],
            EncodingType::Json,
            ForkName::Electra,
        )
        .await?;
    assert_eq!(ok.status(), StatusCode::OK);
    serde_json::from_slice::<SubmitBlindedBlockResponse>(&ok.bytes().await?)
        .expect("happy response is the payload, not an error object");

    // Unhappy path: an unrecognized request Content-Type must yield a spec JSON
    // error (415).
    let url = mock_validator.comm_boost.submit_block_url(BuilderApiVersion::V1).unwrap();
    let body = serde_json::to_vec(&load_test_signed_blinded_block()).unwrap();
    let err = mock_validator
        .comm_boost
        .client
        .post(url)
        .body(body)
        .header(CONTENT_TYPE, "application/garbage")
        .send()
        .await?;

    assert_eq!(err.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        err.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "error body must be JSON per the Builder API",
    );
    let json: serde_json::Value = err.json().await?;
    assert_eq!(json["code"], 415);
    assert!(json["message"].is_string(), "error must carry a message string");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn submit_block_impl(
    api_version: BuilderApiVersion,
    accept_types: Vec<EncodingType>,
    relay_types: HashSet<EncodingType>,
    serialization_mode: EncodingType,
    expected_try_count: u64,
    expected_code: StatusCode,
    remove_v2_support: bool,
    force_404s: bool,
) -> Result<Response> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    // Run a mock relay
    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    let mut mock_relay_state = MockRelayState::new(chain, signer);
    mock_relay_state.supported_content_types = Arc::new(relay_types);
    if remove_v2_support {
        mock_relay_state = mock_relay_state.with_no_submit_block_v2();
    }
    if force_404s {
        mock_relay_state = mock_relay_state.with_not_found_for_submit_block();
    }
    let mock_state = Arc::new(mock_relay_state);
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    // Run the PBS service
    let pbs_config = get_pbs_config(pbs_port);
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    // leave some time to start servers
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send the submit block request
    let signed_blinded_block = load_test_signed_blinded_block();
    let mock_validator = MockValidator::new(pbs_port)?;
    info!("Sending submit block");
    let res = match api_version {
        BuilderApiVersion::V1 => {
            mock_validator
                .do_submit_block_v1(
                    Some(signed_blinded_block),
                    accept_types,
                    serialization_mode,
                    ForkName::Electra,
                )
                .await?
        }
        BuilderApiVersion::V2 => {
            mock_validator
                .do_submit_block_v2(
                    Some(signed_blinded_block),
                    accept_types,
                    serialization_mode,
                    ForkName::Electra,
                )
                .await?
        }
    };
    let expected_count = if force_404s { 0 } else { expected_try_count };
    assert_eq!(mock_state.received_submit_block(), expected_count);
    assert_eq!(res.status(), expected_code);
    Ok(res)
}

// Retry-as-JSON trigger must be restricted
// to 406 Not Acceptable and 415 Unsupported Media Type. Any other 4xx is
// orthogonal to encoding and MUST surface unchanged.

/// Shared fixture: relay returns `ssz_status` when the PBS sends SSZ,
/// everything else takes the happy path. Returns `(Response, attempt_count)`.
/// `api_version` picks v1 or v2 endpoint; `relay_types` controls what the
/// relay advertises as supported so the happy JSON path works when retried.
async fn submit_block_ssz_override(
    api_version: BuilderApiVersion,
    ssz_status: StatusCode,
) -> Result<(Response, u64)> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    let mut mock_relay_state = MockRelayState::new(chain, signer);
    // Relay only advertises JSON so the retry (which goes out as JSON) lands
    // on a clean success path. The SSZ-status override below intercepts
    // before the supported-types check, so the first SSZ attempt still hits
    // our injected status regardless of what's advertised here.
    mock_relay_state.supported_content_types = Arc::new(HashSet::from([EncodingType::Json]));
    mock_relay_state = mock_relay_state.with_submit_block_ssz_status(ssz_status);
    let mock_state = Arc::new(mock_relay_state);
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let pbs_config = get_pbs_config(pbs_port);
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let signed_blinded_block = load_test_signed_blinded_block();
    let mock_validator = MockValidator::new(pbs_port)?;
    // The BN sends SSZ; PBS forwards SSZ first, that's what our override hits.
    let accept_types = vec![EncodingType::Ssz, EncodingType::Json];
    let res = match api_version {
        BuilderApiVersion::V1 => {
            mock_validator
                .do_submit_block_v1(
                    Some(signed_blinded_block),
                    accept_types,
                    EncodingType::Ssz,
                    ForkName::Electra,
                )
                .await?
        }
        BuilderApiVersion::V2 => {
            mock_validator
                .do_submit_block_v2(
                    Some(signed_blinded_block),
                    accept_types,
                    EncodingType::Ssz,
                    ForkName::Electra,
                )
                .await?
        }
    };
    Ok((res, mock_state.received_submit_block()))
}

/// 406 is the spec-defined "retry with a different media type" signal, so we
/// MUST retry as JSON and succeed.
#[tokio::test]
async fn test_submit_block_ssz_retries_as_json_on_406() -> Result<()> {
    let (res, attempts) =
        submit_block_ssz_override(BuilderApiVersion::V1, StatusCode::NOT_ACCEPTABLE).await?;
    assert_eq!(res.status(), StatusCode::OK, "retry-as-JSON must succeed on 406");
    assert_eq!(attempts, 2, "expected SSZ attempt + JSON retry");
    Ok(())
}

/// 415 is the other spec-defined media-type rejection status; same retry.
#[tokio::test]
async fn test_submit_block_ssz_retries_as_json_on_415() -> Result<()> {
    let (res, attempts) =
        submit_block_ssz_override(BuilderApiVersion::V1, StatusCode::UNSUPPORTED_MEDIA_TYPE)
            .await?;
    assert_eq!(res.status(), StatusCode::OK, "retry-as-JSON must succeed on 415");
    assert_eq!(attempts, 2);
    Ok(())
}

/// 400 Bad Request is a validation failure — encoding is not the problem.
/// Retrying doubles relay load and hides the real error. MUST NOT retry.
#[tokio::test]
async fn test_submit_block_ssz_does_not_retry_on_400() -> Result<()> {
    let (_res, attempts) =
        submit_block_ssz_override(BuilderApiVersion::V1, StatusCode::BAD_REQUEST).await?;
    assert_eq!(attempts, 1, "400 is not a media-type error; must not retry");
    Ok(())
}

/// 401 Unauthorized — auth problem, not encoding. No retry.
#[tokio::test]
async fn test_submit_block_ssz_does_not_retry_on_401() -> Result<()> {
    let (_res, attempts) =
        submit_block_ssz_override(BuilderApiVersion::V1, StatusCode::UNAUTHORIZED).await?;
    assert_eq!(attempts, 1);
    Ok(())
}

/// 409 Conflict — state mismatch. No retry.
#[tokio::test]
async fn test_submit_block_ssz_does_not_retry_on_409() -> Result<()> {
    let (_res, attempts) =
        submit_block_ssz_override(BuilderApiVersion::V1, StatusCode::CONFLICT).await?;
    assert_eq!(attempts, 1);
    Ok(())
}

/// 429 Too Many Requests — `PbsError::should_retry` already excludes this;
/// retrying as JSON would add insult to injury. No retry.
#[tokio::test]
async fn test_submit_block_ssz_does_not_retry_on_429() -> Result<()> {
    let (_res, attempts) =
        submit_block_ssz_override(BuilderApiVersion::V1, StatusCode::TOO_MANY_REQUESTS).await?;
    assert_eq!(attempts, 1);
    Ok(())
}

/// Same policy applies to the v2 endpoint.
#[tokio::test]
async fn test_submit_block_v2_ssz_retries_as_json_on_415() -> Result<()> {
    let (res, attempts) =
        submit_block_ssz_override(BuilderApiVersion::V2, StatusCode::UNSUPPORTED_MEDIA_TYPE)
            .await?;
    assert_eq!(res.status(), StatusCode::ACCEPTED, "v2 success is 202 Accepted");
    assert_eq!(attempts, 2);
    Ok(())
}

/// v2 + 400: same no-retry rule as v1.
#[tokio::test]
async fn test_submit_block_v2_ssz_does_not_retry_on_400() -> Result<()> {
    let (_res, attempts) =
        submit_block_ssz_override(BuilderApiVersion::V2, StatusCode::BAD_REQUEST).await?;
    assert_eq!(attempts, 1);
    Ok(())
}

/// PBS must accept relay `Content-Type: application/octet-stream;
/// charset=binary` on `submit_block` responses. The audit fix for C2 switched
/// `EncodingType::from_str` to parse via the `mediatype` crate; this test
/// exercises the full relay→PBS→BN path to guard against regressions on the
/// v1 submit path.
#[tokio::test]
async fn test_submit_block_tolerates_mime_params_in_content_type() -> Result<()> {
    setup_test_env();
    let signer = random_secret();
    let pubkey = signer.public_key();
    let chain = Chain::Holesky;
    let pbs_listener = get_free_listener().await;
    let relay_listener = get_free_listener().await;
    let pbs_port = pbs_listener.local_addr().unwrap().port();
    let relay_port = relay_listener.local_addr().unwrap().port();

    let mock_relay = generate_mock_relay(relay_port, pubkey)?;
    let mut mock_relay_state = MockRelayState::new(chain, signer)
        .with_response_content_type("application/octet-stream; charset=binary");
    mock_relay_state.supported_content_types = Arc::new(HashSet::from([EncodingType::Ssz]));
    let mock_state = Arc::new(mock_relay_state);
    tokio::spawn(start_mock_relay_service_with_listener(mock_state.clone(), relay_listener));

    let pbs_config = get_pbs_config(pbs_port);
    let config = to_pbs_config(chain, pbs_config, vec![mock_relay]);
    let state = PbsState::new(config, PathBuf::new());
    tokio::spawn(PbsService::run_with_listener::<(), DefaultBuilderApi>(state, pbs_listener));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let signed_blinded_block = load_test_signed_blinded_block();
    let mock_validator = MockValidator::new(pbs_port)?;
    let res = mock_validator
        .do_submit_block_v1(
            Some(signed_blinded_block.clone()),
            vec![EncodingType::Ssz],
            EncodingType::Ssz,
            ForkName::Electra,
        )
        .await?;
    assert_eq!(res.status(), StatusCode::OK, "PBS should tolerate `; charset=binary` MIME param");
    assert_eq!(mock_state.received_submit_block(), 1);

    let bytes = res.bytes().await?;
    let response_body = PayloadAndBlobs::from_ssz_bytes_by_fork(&bytes, ForkName::Electra).unwrap();
    assert_eq!(
        response_body.execution_payload.block_hash(),
        signed_blinded_block.block_hash().into()
    );
    Ok(())
}
