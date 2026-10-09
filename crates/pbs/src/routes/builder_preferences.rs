use axum::{
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use cb_common::{
    pbs::{BuilderPreferencesRequest, SubmitBuilderPreferencesParams},
    wire::{decode_versioned_request_body, get_user_agent},
};
use reqwest::StatusCode;
use ssz::Encode;
use tracing::{error, info};

use crate::{
    PbsStateGuard,
    constants::SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG,
    error::PbsClientError,
    state::{BuilderApiState, PbsState},
    utils::{
        Addressed, builder_rejection, epbs_base_send_headers, log_mux_selection,
        post_ssz_expect_accepted, record_beacon_status, record_request_failure,
        resolve_addressed_relay,
    },
};

pub async fn handle_submit_builder_preferences<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<SubmitBuilderPreferencesParams>,
    body: Bytes,
) -> Result<impl IntoResponse, PbsClientError> {
    let request =
        decode_versioned_request_body::<BuilderPreferencesRequest>(&req_headers, &body)
            .map_err(|err| record_request_failure(err, SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG))?;
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
/// Returns 202 if the addressed builder accepts
pub async fn submit_builder_preferences<S: BuilderApiState>(
    params: SubmitBuilderPreferencesParams,
    request: BuilderPreferencesRequest,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> Result<(), PbsClientError> {
    let (pbs_config, relays, maybe_mux_id) = state.mux_config_and_relays(&params.proposer_pubkey);

    log_mux_selection(maybe_mux_id, relays.len(), &params.proposer_pubkey);

    // Preferences are submitted an epoch ahead, so they share the registration
    // timeout rather than the block-production one
    let addressed = Addressed {
        endpoint: SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG,
        pubkey: &params.proposer_pubkey,
        mux_id: maybe_mux_id,
        all_relays: state.all_relays(),
    };
    let (relay, timeout_ms) = resolve_addressed_relay(
        relays,
        request.auth.message.data.as_ref(),
        &req_headers,
        pbs_config.timeout_register_validator_ms,
        &addressed,
    )
    .await?;

    let send_headers = epbs_base_send_headers(&req_headers)?;

    // SSZ on the relay hop
    let body = Bytes::from(request.as_ssz_bytes());

    let relay_id = relay.id.as_ref();
    let sent = match relay.submit_builder_preferences_url(&params.proposer_pubkey) {
        Ok(url) => {
            post_ssz_expect_accepted(
                &relay,
                url,
                body,
                send_headers,
                timeout_ms,
                SUBMIT_BUILDER_PREFERENCES_ENDPOINT_TAG,
            )
            .await
        }
        Err(err) => Err(err),
    };
    match sent {
        Ok(latency) => {
            info!(relay_id, ?latency, "builder preferences submitted");
            Ok(())
        }
        Err(err) => {
            if err.is_timeout() {
                error!(err = "Timed Out", relay_id);
            } else {
                error!(%err, relay_id);
            }
            Err(builder_rejection(&err).unwrap_or(PbsClientError::NoBuilderResponse))
        }
    }
}
