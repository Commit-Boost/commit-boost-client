use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use cb_common::{
    pbs::{
        BuilderPreferencesRequest, RelayClient, SignedRequestAuth, SubmitBuilderPreferencesParams,
        error::PbsError,
    },
    types::Chain,
    utils::ms_into_slot,
    wire::{EncodingType, decode_versioned_request_body, get_user_agent, safe_read_http_response},
};
use futures::future::join_all;
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::Encode;
use tracing::{Instrument, debug, error, info, warn};

use crate::{
    PbsStateGuard,
    constants::{MAX_SIZE_DEFAULT, SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG},
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsState},
    utils::{
        epbs_base_send_headers, expect_status, match_relays_by_auth_data, send_to_relay,
        verify_auth_signature,
    },
};

/// The body is the required `BuilderPreferencesRequest`; like the bid
/// endpoint it is fork-versioned per builder-specs, so the SSZ form requires
/// `Eth-Consensus-Version` (JSON is best effort per CB policy).
pub async fn handle_submit_builder_preferences<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<SubmitBuilderPreferencesParams>,
    body: Bytes,
) -> Result<impl IntoResponse, PbsClientError> {
    let request = decode_versioned_request_body::<BuilderPreferencesRequest>(&req_headers, &body)?;
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
            BEACON_NODE_STATUS
                .with_label_values(&["202", SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG])
                .inc();
            Ok(StatusCode::ACCEPTED.into_response())
        }
        Err(err) => {
            error!(%err, "submit_builder_preferences failed");

            BEACON_NODE_STATUS
                .with_label_values(&[
                    err.status_code().as_str(),
                    SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG,
                ])
                .inc();
            Err(err)
        }
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

    if let Some(mux_id) = maybe_mux_id {
        debug!(mux_id, relays = relays.len(), pubkey = %params.proposer_pubkey, "using mux config");
    } else {
        debug!(relays = relays.len(), pubkey = %params.proposer_pubkey, "using default config");
    }

    // Validate before any outbound work so a rejected request costs nothing
    validate_preferences_auth(
        &request.auth,
        &params,
        state.config.chain,
        pbs_config.verify_request_auth,
    )?;

    let relays = match_relays_by_auth_data(
        relays,
        request.auth.message.data.as_ref(),
        pbs_config.strict_auth_data,
    );
    if relays.is_empty() {
        return Err(PbsClientError::AuthDataMismatch);
    }

    let send_headers = epbs_base_send_headers(&req_headers)?;

    // Preferences are submitted an epoch ahead, so they share the registration
    // timeout rather than the block-production one
    let timeout_ms = pbs_config.timeout_register_validator_ms;

    let mut handles = Vec::with_capacity(relays.len());
    for &relay in relays.iter() {
        handles.push(
            send_one_submit_builder_preferences(
                params.proposer_pubkey.clone(),
                request.clone(),
                relay.clone(),
                send_headers.clone(),
                timeout_ms,
            )
            .in_current_span(),
        );
    }

    let results = join_all(handles).await;
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
            _ => PbsClientError::NoResponse,
        });
    }

    info!(accepted, addressed = relays.len(), "builder preferences submitted");
    Ok(())
}

/// Validates the caller's `SignedRequestAuth`. There is no slot in the
/// request path here, so instead of matching one we reject a slot that has
/// already ended: preferences are submitted an epoch ahead, and a replayed
/// submission must not be able to roll a proposer's preferences back to a stale
/// value. The `auth.message.data` check is the demux's job
/// (`match_relays_by_auth_data`).
fn validate_preferences_auth(
    auth: &SignedRequestAuth,
    params: &SubmitBuilderPreferencesParams,
    chain: Chain,
    verify_signature: bool,
) -> Result<(), PbsClientError> {
    if slot_has_passed(auth.message.slot.as_u64(), chain) {
        warn!(auth_slot = %auth.message.slot, "auth slot already passed");
        return Err(PbsClientError::AuthSlotPassed);
    }

    verify_auth_signature(&params.proposer_pubkey, auth, chain, verify_signature)
}

/// `ms_into_slot` saturates at 0 for a future slot, so a full slot's worth of
/// elapsed time means the slot is over.
fn slot_has_passed(slot: u64, chain: Chain) -> bool {
    ms_into_slot(slot, chain) >= chain.slot_time_sec() * 1000
}

async fn send_one_submit_builder_preferences(
    proposer_pubkey: cb_common::types::BlsPublicKey,
    request: BuilderPreferencesRequest,
    relay: RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
) -> Result<(), PbsError> {
    let url = relay.submit_builder_preferences_url(&proposer_pubkey)?;

    // The builder decodes what the proposer signed either way, and SSZ is the
    // faster wire format on the relay hop
    let req = relay
        .client
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers)
        .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
        .body(request.as_ssz_bytes());
    let (res, request_latency) =
        send_to_relay(req, &relay, SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG).await?;
    let code = res.status();

    // Cap the read like every other relay call: a builder is untrusted and must
    // not be able to stream an unbounded error body into memory and the logs
    safe_read_http_response(res, MAX_SIZE_DEFAULT).await?;

    // The spec makes 202 the only success: another 2xx means the builder did not
    // commit to storing these preferences
    expect_status(code, StatusCode::ACCEPTED)?;

    debug!(relay_id = relay.id.as_ref(), latency = ?request_latency, "preferences accepted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use cb_common::{
        pbs::{BuilderPreferences, RequestAuth},
        types::BlsSignature,
        utils::{timestamp_of_slot_start_sec, utcnow_ms, utcnow_sec},
        wire::{BodyDeserializeError, CONSENSUS_VERSION_HEADER},
    };

    use super::*;

    fn current_slot(chain: Chain) -> u64 {
        (utcnow_sec() - chain.genesis_time_sec()) / chain.slot_time_sec()
    }

    /// The boundary is the slot's END, not its start: a proposer legitimately
    /// submits for a slot that is still in progress.
    #[test]
    fn slot_has_passed_is_exclusive_of_the_current_slot() {
        let chain = Chain::Hoodi;
        let now = current_slot(chain);

        assert!(!slot_has_passed(now, chain), "the in-progress slot has not passed");
        assert!(!slot_has_passed(now + 1, chain), "the next slot has not passed");
        assert!(!slot_has_passed(now + 1_000, chain), "a far future slot has not passed");
        assert!(slot_has_passed(now - 1, chain), "the previous slot has passed");
        assert!(slot_has_passed(0, chain), "slot 0 has long passed");
    }

    /// A slot is over exactly one slot-duration after it began, so the check
    /// must not fire a millisecond early or a millisecond late.
    #[test]
    fn slot_has_passed_flips_one_slot_after_the_start() {
        let chain = Chain::Hoodi;
        let now = current_slot(chain);
        let elapsed_ms = utcnow_ms() - timestamp_of_slot_start_sec(now, chain) * 1_000;

        // Whatever point of the slot the test runs at, exactly one slot's worth
        // of elapsed time separates "not passed" from "passed"
        assert!(elapsed_ms < chain.slot_time_sec() * 1_000);
        assert!(!slot_has_passed(now, chain));
        assert!(slot_has_passed(now - 1, chain));
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
    /// and the SSZ form requires `Eth-Consensus-Version` (fork-versioned type).
    #[test]
    fn decode_defaults_to_ssz_without_a_content_type() {
        let request = BuilderPreferencesRequest {
            auth: SignedRequestAuth {
                message: RequestAuth { data: Default::default(), slot: lh_types::Slot::new(3) },
                signature: BlsSignature::empty(),
            },
            preferences: BuilderPreferences { max_execution_payment: 7 },
        };
        let body = Bytes::from(request.as_ssz_bytes());

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

        // Intentional leniency: the body shape is fork-invariant, so only the
        // header's presence is checked, not its value (the outbound hop
        // re-derives gloas regardless). Pinned so a change here is deliberate.
        let mut headers = HeaderMap::new();
        headers.insert(CONSENSUS_VERSION_HEADER, axum::http::HeaderValue::from_static("electra"));
        decode_versioned_request_body::<BuilderPreferencesRequest>(&headers, &body)
            .expect("a parseable non-gloas fork is accepted, value ignored");
    }
}
