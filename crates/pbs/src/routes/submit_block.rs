use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use cb_common::utils::{get_user_agent, timestamp_of_slot_start_millis, utcnow_ms};
use reqwest::StatusCode;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    boost::BuilderApi,
    error::PbsClientError,
    metrics::REQUESTS_RECEIVED,
    state::{BuilderApiState, PbsState},
    types::SignedBlindedBeaconBlock,
    BuilderEvent,
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock
/// Returns error if the corresponding is not delivered by any relay
pub async fn handle_submit_block<S: BuilderApiState, T: BuilderApi<S>>(
    State(state): State<PbsState<S>>,
    req_headers: HeaderMap,
    Json(signed_blinded_block): Json<SignedBlindedBeaconBlock>,
) -> Result<impl IntoResponse, PbsClientError> {
    REQUESTS_RECEIVED.with_label_values(&["submit_block"]).inc();
    state.publish_event(BuilderEvent::SubmitBlockRequest(Box::new(signed_blinded_block.clone())));

    let req_id = Uuid::new_v4();
    let now = utcnow_ms();
    let slot = signed_blinded_block.message.slot;
    let block_hash = signed_blinded_block.message.body.execution_payload_header.block_hash;
    let slot_start_ms = timestamp_of_slot_start_millis(slot, state.config.chain);
    let ua = get_user_agent(&req_headers);
    let (curr_slot, slot_uuid) = state.get_slot_and_uuid();

    info!(method = "submit_block", %req_id, ?ua, slot, %slot_uuid, ms_into_slot=now.saturating_sub(slot_start_ms), %block_hash);

    if curr_slot != signed_blinded_block.message.slot {
        warn!(%req_id, expected = curr_slot, got = slot, "blinded beacon slot mismatch")
    }

    match T::submit_block(signed_blinded_block, req_headers, state.clone()).await {
        Ok(res) => {
            state.publish_event(BuilderEvent::SubmitBlockResponse(Box::new(res.clone())));

            info!(method="submit_block", %req_id, "received unblinded block");
            Ok((StatusCode::OK, Json(res).into_response()))
        }

        Err(err) => {
            if let Some(fault_pubkeys) = state.get_relays_by_block_hash(slot, block_hash) {
                let fault_relays = state
                    .relays()
                    .iter()
                    .filter(|relay| fault_pubkeys.contains(&relay.pubkey))
                    .map(|relay| relay.id.clone())
                    .collect::<Vec<_>>()
                    .join(",");

                error!(method="submit_block", %req_id, ?err, %block_hash, ?fault_relays, "CRITICAL: no payload received from relays");

                state.publish_event(BuilderEvent::MissedPayload {
                    block_hash,
                    relays: fault_relays,
                });
            } else {
                error!(method="submit_block", %req_id, ?err, %slot_uuid, %block_hash, "CRITICAL: no payload delivered and no relay for block hash. Was getHeader even called?");
                state.publish_event(BuilderEvent::MissedPayload {
                    block_hash,
                    relays: String::default(),
                });
            };

            Err(PbsClientError::NoPayload)
        }
    }
}
