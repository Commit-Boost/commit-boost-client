use axum::{extract::State, http::HeaderMap, Json};
use cb_common::utils::{get_user_agent, timestamp_of_slot_start_millis, utcnow_ms};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    boost::BuilderApi,
    error::PbsClientError,
    metrics::REQUESTS_RECEIVED,
    state::{BuilderApiState, PbsState},
    types::{SignedBlindedBeaconBlock, SubmitBlindedBlockResponse},
    BuilderEvent,
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock
/// Returns error if the corresponding is not delivered by any relay
pub async fn handle_submit_block<S: BuilderApiState, T: BuilderApi<S>>(
    State(state): State<PbsState<S>>,
    req_headers: HeaderMap,
    Json(signed_blinded_block): Json<SignedBlindedBeaconBlock>,
) -> Result<Json<SubmitBlindedBlockResponse>, PbsClientError> {
    let req_id = Uuid::new_v4();
    let now = utcnow_ms();
    let slot = signed_blinded_block.message.slot;
    let block_hash = signed_blinded_block.message.body.execution_payload_header.block_hash;
    let slot_start_ms = timestamp_of_slot_start_millis(slot, state.config.chain);

    let ua = get_user_agent(&req_headers);

    REQUESTS_RECEIVED.with_label_values(&["submit_block"]).inc();

    state.publish_event(BuilderEvent::SubmitBlockRequest(Box::new(signed_blinded_block.clone())));

    let (curr_slot, slot_uuid) = state.get_slot_and_uuid();
    info!(method = "submit_block", %req_id, ?ua, slot, %slot_uuid, ms_into_slot=now.saturating_sub(slot_start_ms), %block_hash);

    if curr_slot != signed_blinded_block.message.slot {
        warn!(%req_id, expected = curr_slot, got = slot, "blinded beacon slot mismatch")
    }

    match T::submit_block(signed_blinded_block, req_headers, state.clone()).await {
        Ok(res) => {
            state.publish_event(BuilderEvent::SubmitBlockResponse(Box::new(res.clone())));
            Ok(Json(res))
        }
        Err(err) => {
            if let Some(fault_pubkeys) = state.get_relays_by_block_hash(slot, block_hash) {
                let fault_relays = state
                    .relays()
                    .to_vec()
                    .into_iter()
                    .filter(|relay| fault_pubkeys.contains(&relay.pubkey))
                    .map(|relay| relay.id)
                    .collect::<Vec<_>>()
                    .join(",");

                error!(%req_id, ?err, %block_hash, ?fault_relays, "CRITICAL: no payload delivered successfully");

                state.publish_event(BuilderEvent::MissedPayload {
                    block_hash,
                    relays: fault_relays,
                });
            } else {
                error!(%req_id, ?err, %slot_uuid, %block_hash, "CRITICAL: no payload delivered and no relay for block hash. Was getHeader even called?");
            };

            Err(PbsClientError::NoPayload)
        }
    }
}
