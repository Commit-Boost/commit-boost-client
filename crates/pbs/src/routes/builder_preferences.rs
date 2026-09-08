use axum::{
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use cb_common::{
    pbs::{
        BuilderPreferencesRequest, RelayClient, SignedBuilderRequestAuth,
        SubmitBuilderPreferencesParams, error::PbsError,
    },
    types::Chain,
    wire::{decode_versioned_request_body, get_user_agent},
};
use reqwest::StatusCode;
use ssz::Encode;
use tracing::{debug, error, info};

use crate::{
    PbsStateGuard,
    constants::SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG,
    error::PbsClientError,
    state::{BuilderApiState, PbsState},
    utils::{
        epbs_base_send_headers, join_detached_sends, log_mux_selection, post_ssz_expect_accepted,
        record_beacon_status, record_client_error, record_request_failure,
        resolve_addressed_relays, validate_auth_data, verify_auth_signature,
    },
};

/// The body is the required `BuilderPreferencesRequest`; like the bid
/// endpoint it is fork-versioned per builder-specs, and `Eth-Consensus-Version`
/// is required for JSON and SSZ alike
pub async fn handle_submit_builder_preferences<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<SubmitBuilderPreferencesParams>,
    body: Bytes,
) -> Result<impl IntoResponse, PbsClientError> {
    let request =
        decode_versioned_request_body::<BuilderPreferencesRequest>(&req_headers, &body)
            .map_err(|err| record_client_error(err, SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG))?;
    tracing::Span::current().record("validator", tracing::field::debug(&params.proposer_pubkey));
    tracing::Span::current().record("slot", request.auth.message.slot.as_u64());

    let state = state.read().clone();
    let ua = get_user_agent(&req_headers);
    info!(
        ua,
        slot = %request.auth.message.slot,
        max_execution_payment = request.preferences.max_execution_payment,
        "new request"
    );

    match submit_builder_preferences(params, request, req_headers, state).await {
        Ok(()) => {
            record_beacon_status("202", SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG);
            Ok(StatusCode::ACCEPTED.into_response())
        }
        Err(err) => Err(record_request_failure(err, SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG)),
    }
}

/// Implements https://ethereum.github.io/builder-specs/?urls.primaryName=dev#/Builder/submitBuilderPreferences
/// Ok(()) if at least one addressed builder accepted (-> 202).
pub async fn submit_builder_preferences<S: BuilderApiState>(
    params: SubmitBuilderPreferencesParams,
    request: BuilderPreferencesRequest,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> Result<(), PbsClientError> {
    let (pbs_config, relays, maybe_mux_id) = state.mux_config_and_relays(&params.proposer_pubkey);

    log_mux_selection(maybe_mux_id, relays.len(), &params.proposer_pubkey);

    // Validate before any outbound work so a rejected request costs nothing
    validate_preferences_auth(
        &request.auth,
        &params,
        state.config.chain,
        pbs_config.verify_builder_request_auth,
    )?;

    let relays = resolve_addressed_relays(
        relays,
        request.auth.message.data.as_ref(),
        &pbs_config.advertised_urls,
        &state.pipe_client,
    )
    .await?;

    let send_headers = epbs_base_send_headers(&req_headers)?;

    // The builder decodes what the proposer signed either way, and SSZ is the
    // faster wire format on the relay hop; encoded once, shared by every send
    let body = Bytes::from(request.as_ssz_bytes());

    // Preferences are submitted an epoch ahead, so they share the registration
    // timeout rather than the block-production one
    let timeout_ms = pbs_config.timeout_register_validator_ms;

    let results = join_detached_sends(relays.iter().map(|relay| {
        send_one_submit_builder_preferences(
            params.proposer_pubkey.clone(),
            body.clone(),
            relay.clone(),
            send_headers.clone(),
            timeout_ms,
        )
    }))
    .await;
    let mut accepted = 0;
    let mut lone_rejection = None;
    for (res, relay) in results.into_iter().zip(relays.iter()) {
        let relay_id = relay.id.as_str();
        match res {
            Ok(()) => accepted += 1,
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => {
                // Only a single addressed builder's verdict is unambiguous enough
                // to hand back to the proposer
                if relays.len() == 1 {
                    lone_rejection = err.relay_status_code();
                }
                error!(%err, relay_id)
            }
        }
    }

    // One accepting builder is a successful submission: the others are separate
    // destinations, not replicas, and the proposer addressed each by auth data
    if accepted == 0 {
        // A lone builder's own 400/401 tells the proposer whether its auth data or
        // its signature was rejected, which a blanket 502 would hide
        return Err(match lone_rejection {
            Some(code @ (400 | 401)) => PbsClientError::BuilderRejected { code },
            _ => PbsClientError::NoBuilderResponse,
        });
    }

    info!(accepted, addressed = relays.len(), "builder preferences submitted");
    Ok(())
}

/// Validates the caller's `SignedBuilderRequestAuth`. CB is a blind pipe for
/// preferences: it does not gate on the auth slot. Freshness (rejecting a stale
/// or replayed submission that would roll a proposer's preferences back) is the
/// builder's call, not the relay's, so CB forwards regardless of slot age. All
/// that is required here is `auth.message.data` (non-empty; which builder it
/// addresses is the demux's job, `match_relays_by_auth_data`) and, when
/// enabled, the request-auth signature.
fn validate_preferences_auth(
    auth: &SignedBuilderRequestAuth,
    params: &SubmitBuilderPreferencesParams,
    chain: Chain,
    verify_signature: bool,
) -> Result<(), PbsClientError> {
    validate_auth_data(auth)?;

    verify_auth_signature(&params.proposer_pubkey, auth, chain, verify_signature)
}

async fn send_one_submit_builder_preferences(
    proposer_pubkey: cb_common::types::BlsPublicKey,
    body: Bytes,
    relay: RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
) -> Result<(), PbsError> {
    let url = relay.submit_builder_preferences_url(&proposer_pubkey)?;

    let request_latency = post_ssz_expect_accepted(
        &relay,
        url,
        body,
        headers,
        timeout_ms,
        SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG,
    )
    .await?;

    debug!(relay_id = relay.id.as_ref(), latency = ?request_latency, "preferences accepted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use cb_common::{
        pbs::{BuilderPreferences, BuilderRequestAuth},
        types::BlsSignature,
        utils::utcnow_sec,
        wire::{BodyDeserializeError, CONSENSUS_VERSION_HEADER},
    };

    use super::*;

    fn current_slot(chain: Chain) -> u64 {
        (utcnow_sec() - chain.genesis_time_sec()) / chain.slot_time_sec()
    }

    fn sample_request() -> BuilderPreferencesRequest {
        BuilderPreferencesRequest {
            auth: SignedBuilderRequestAuth {
                message: BuilderRequestAuth {
                    data: Default::default(),
                    slot: lh_types::Slot::new(3),
                },
                signature: BlsSignature::empty(),
            },
            preferences: BuilderPreferences { max_execution_payment: 7 },
        }
    }

    // Empty `auth.message.data` is rejected before sigverify, so it cannot slip
    // through a catch-all relay match. Guards the wiring of the shared
    // `validate_auth_data` into this endpoint.
    #[test]
    fn validate_preferences_auth_rejects_empty_data() {
        use cb_common::types::BlsSecretKey;

        let chain = Chain::Hoodi;
        let params =
            SubmitBuilderPreferencesParams { proposer_pubkey: BlsSecretKey::random().public_key() };
        let empty = SignedBuilderRequestAuth {
            message: BuilderRequestAuth {
                data: Default::default(),
                slot: lh_types::Slot::new(current_slot(chain)),
            },
            signature: BlsSignature::empty(),
        };
        for verify in [false, true] {
            assert!(matches!(
                validate_preferences_auth(&empty, &params, chain, verify),
                Err(PbsClientError::EmptyAuthData)
            ));
        }
    }

    #[test]
    fn decode_rejects_an_empty_body() {
        let err = decode_versioned_request_body::<BuilderPreferencesRequest>(
            &HeaderMap::new(),
            &Bytes::new(),
        )
        .expect_err("an empty body is not a request");
        assert!(matches!(err, BodyDeserializeError::MissingBody));
    }

    /// This endpoint's no-preference default is SSZ, not the shared JSON one,
    /// and `Eth-Consensus-Version` is required regardless of encoding.
    #[test]
    fn decode_defaults_to_ssz_without_a_content_type() {
        let body = Bytes::from(sample_request().as_ssz_bytes());

        // Missing the header, the SSZ-default body is rejected, not misparsed
        let err =
            decode_versioned_request_body::<BuilderPreferencesRequest>(&HeaderMap::new(), &body)
                .expect_err("ssz without the version header must be rejected");
        assert!(matches!(err, BodyDeserializeError::MissingVersionHeader));

        let mut headers = HeaderMap::new();
        headers.insert(CONSENSUS_VERSION_HEADER, axum::http::HeaderValue::from_static("gloas"));
        let decoded = decode_versioned_request_body::<BuilderPreferencesRequest>(&headers, &body)
            .expect("ssz body decodes without a content type");
        assert_eq!(decoded.preferences.max_execution_payment, 7);
        assert_eq!(decoded.auth.message.slot.as_u64(), 3);

        // gloas is the ONLY supported value: fulu is rejected
        // at the wire layer like every other deprecated fork
        let mut headers = HeaderMap::new();
        headers.insert(CONSENSUS_VERSION_HEADER, axum::http::HeaderValue::from_static("fulu"));
        let err = decode_versioned_request_body::<BuilderPreferencesRequest>(&headers, &body)
            .expect_err("fulu must be rejected on the gloas-only endpoints");
        assert!(matches!(err, BodyDeserializeError::InvalidVersionHeader(ref v) if v == "fulu"));

        // A DEPRECATED fork name (recognized by lighthouse, outside the gloas-only
        // window) is rejected as unsupported
        let mut headers = HeaderMap::new();
        headers.insert(CONSENSUS_VERSION_HEADER, axum::http::HeaderValue::from_static("electra"));
        let err = decode_versioned_request_body::<BuilderPreferencesRequest>(&headers, &body)
            .expect_err("a deprecated fork must be rejected");
        assert!(matches!(err, BodyDeserializeError::InvalidVersionHeader(ref v) if v == "electra"));

        // Case is folded before the window check (lighthouse FromStr
        // lowercases), so an uppercase spelling of the one legal value passes.
        // Pinned: if the spec is ever read as lowercase-only, this is the
        // deliberate place to change it.
        let mut headers = HeaderMap::new();
        headers.insert(CONSENSUS_VERSION_HEADER, axum::http::HeaderValue::from_static("GLOAS"));
        decode_versioned_request_body::<BuilderPreferencesRequest>(&headers, &body)
            .expect("case-insensitive gloas is accepted");
    }

    /// builder-specs marks `Eth-Consensus-Version` required on this endpoint
    /// for JSON and SSZ alike (builder-specs #165): JSON without it is a 400,
    /// not a best-effort decode. Since spec PR #165 the same rule covers
    /// `submitSignedBeaconBlock` too — no endpoint is lenient.
    #[test]
    fn decode_rejects_json_without_the_version_header() {
        let body = Bytes::from(serde_json::to_vec(&sample_request()).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        let err = decode_versioned_request_body::<BuilderPreferencesRequest>(&headers, &body)
            .expect_err("json without the version header must be rejected");
        assert!(matches!(err, BodyDeserializeError::MissingVersionHeader));

        headers.insert(CONSENSUS_VERSION_HEADER, axum::http::HeaderValue::from_static("gloas"));
        decode_versioned_request_body::<BuilderPreferencesRequest>(&headers, &body)
            .expect("the same json body decodes once the header is present");
    }

    /// An unrecognized fork name is a 400 per builder-specs, and the error
    /// names the value rather than claiming the header is missing.
    #[test]
    fn decode_rejects_an_unrecognized_fork_value() {
        let request = sample_request();
        for (ct, body) in [
            ("application/json", Bytes::from(serde_json::to_vec(&request).unwrap())),
            ("application/octet-stream", Bytes::from(request.as_ssz_bytes())),
        ] {
            let mut headers = HeaderMap::new();
            headers
                .insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static(ct));
            headers.insert(
                CONSENSUS_VERSION_HEADER,
                axum::http::HeaderValue::from_static("futurefork"),
            );
            let err = decode_versioned_request_body::<BuilderPreferencesRequest>(&headers, &body)
                .expect_err("an unrecognized fork value must be rejected");
            assert!(
                matches!(err, BodyDeserializeError::InvalidVersionHeader(ref v) if v == "futurefork"),
                "{ct}: wrong error: {err}"
            );
        }
    }
}
