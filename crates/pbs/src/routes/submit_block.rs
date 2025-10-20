use axum::{Json, extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::{
    pbs::{BuilderApiVersion, GetPayloadInfo, SignedBlindedBeaconBlock},
    utils::{get_user_agent, timestamp_of_slot_start_millis, utcnow_ms},
};
use reqwest::StatusCode;
use tracing::{error, info, trace};

use crate::{
    api::BuilderApi,
    constants::SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

pub async fn handle_submit_block_v1<S: BuilderApiState, A: BuilderApi<S>>(
    state: State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    signed_blinded_block: Json<SignedBlindedBeaconBlock>,
) -> Result<impl IntoResponse, PbsClientError> {
    handle_submit_block_impl::<S, A>(
        state,
        req_headers,
        signed_blinded_block,
        BuilderApiVersion::V1,
    )
    .await
}

pub async fn handle_submit_block_v2<S: BuilderApiState, A: BuilderApi<S>>(
    state: State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    signed_blinded_block: Json<SignedBlindedBeaconBlock>,
) -> Result<impl IntoResponse, PbsClientError> {
    handle_submit_block_impl::<S, A>(
        state,
        req_headers,
        signed_blinded_block,
        BuilderApiVersion::V2,
    )
    .await
}

async fn handle_submit_block_impl<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Json(signed_blinded_block): Json<SignedBlindedBeaconBlock>,
    api_version: BuilderApiVersion,
) -> Result<impl IntoResponse, PbsClientError> {
    tracing::Span::current().record("slot", signed_blinded_block.slot().as_u64() as i64);
    tracing::Span::current()
        .record("block_hash", tracing::field::debug(signed_blinded_block.block_hash()));
    tracing::Span::current().record("block_number", signed_blinded_block.block_number());
    tracing::Span::current()
        .record("parent_hash", tracing::field::debug(signed_blinded_block.parent_hash()));

    let state = state.read().clone();

    let now = utcnow_ms();
    let slot = signed_blinded_block.slot();
    let block_hash = signed_blinded_block.block_hash();
    let slot_start_ms = timestamp_of_slot_start_millis(slot.into(), state.config.chain);
    let ua = get_user_agent(&req_headers);

    info!(ua, ms_into_slot = now.saturating_sub(slot_start_ms), "new request");

    match A::submit_block(signed_blinded_block, req_headers, state, &api_version).await {
        Ok(res) => match res {
            Some(block_response) => {
                trace!(?block_response);
                info!("received unblinded block (v1)");

                BEACON_NODE_STATUS
                    .with_label_values(&["200", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                    .inc();
                Ok((StatusCode::OK, Json(block_response).into_response()))
            }
            None => {
                info!("received unblinded block (v2)");

                BEACON_NODE_STATUS
                    .with_label_values(&["202", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                    .inc();
                Ok((StatusCode::ACCEPTED, "".into_response()))
            }
        },

        Err(err) => {
            error!(%err, %block_hash, "CRITICAL: no payload received from relays. Check previous logs or use the Relay Data API");

            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
