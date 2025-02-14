use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use cb_common::{
    pbs::{BuilderEvent, SignedBlindedBeaconBlock},
    utils::{get_user_agent, timestamp_of_slot_start_millis, utcnow_ms},
};
use reqwest::StatusCode;
use tracing::{error, info, trace};
use uuid::Uuid;

use crate::{
    api::BuilderApi,
    constants::SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

fn log_submit_block(
    user_agent: String,
    ms_into_slot: u64,
    block_hash: alloy::primitives::B256,
    slot: u64,
    parent_hash: alloy::primitives::B256,
    success: bool,
    relays: Vec<String>,
) {
    info!(
        msg = if success { "received unblinded block" } else { "failed to receive unblinded block" },
        ua = ?user_agent,
        msIntoSlot = ms_into_slot,
        slot = slot,
        parentHash = %parent_hash,
        blockHash = %block_hash,
        relays = ?relays,
    );
}

#[tracing::instrument(skip_all, name = "submit_blinded_block", fields(req_id = %Uuid::new_v4(), slot = signed_blinded_block.message.slot))]
pub async fn handle_submit_block<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Json(signed_blinded_block): Json<SignedBlindedBeaconBlock>,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.read().clone();

    trace!(?signed_blinded_block);
    state.publish_event(BuilderEvent::SubmitBlockRequest(Box::new(signed_blinded_block.clone())));

    // inputs for logging
    let now = utcnow_ms();
    let slot = signed_blinded_block.message.slot;
    let block_hash = signed_blinded_block.block_hash();
    let slot_start_ms = timestamp_of_slot_start_millis(slot, state.config.chain);
    let ua = get_user_agent(&req_headers);
    let ms_into_slot = now.saturating_sub(slot_start_ms);
    let relays = state.config.all_relays.iter().map(|r| (*r.id).clone()).collect::<Vec<_>>();
    let parent_hash = signed_blinded_block.message.body.execution_payload_header.parent_hash;

    match A::submit_block(signed_blinded_block, req_headers, state.clone()).await {
        Ok(res) => {
            trace!(?res);
            log_submit_block(ua, ms_into_slot, block_hash, slot, parent_hash, true, relays);
            state.publish_event(BuilderEvent::SubmitBlockResponse(Box::new(res.clone())));

            BEACON_NODE_STATUS.with_label_values(&["200", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG]).inc();
            Ok((StatusCode::OK, Json(res).into_response()))
        }

        Err(err) => {
            error!(%err, %block_hash, "CRITICAL: no payload received from relays. Check previous logs or use the Relay Data API");
            log_submit_block(ua, ms_into_slot, block_hash, slot, parent_hash, false, relays);
            state.publish_event(BuilderEvent::MissedPayload { block_hash });

            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
