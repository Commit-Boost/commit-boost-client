use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use cb_common::utils::{get_user_agent, timestamp_of_slot_start_millis, utcnow_ms};
use reqwest::StatusCode;
use tracing::{error, info, trace, warn};
use uuid::Uuid;

use crate::{
    boost::BuilderApi,
    constants::SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsState},
    types::SignedBlindedBeaconBlock,
    BuilderEvent,
};

#[tracing::instrument(skip_all, name = "submit_blinded_block", fields(req_id = %Uuid::new_v4(), slot = signed_blinded_block.message.slot))]
pub async fn handle_submit_block<S: BuilderApiState, T: BuilderApi<S>>(
    State(state): State<PbsState<S>>,
    req_headers: HeaderMap,
    Json(signed_blinded_block): Json<SignedBlindedBeaconBlock>,
) -> Result<impl IntoResponse, PbsClientError> {
    trace!(?signed_blinded_block);
    state.publish_event(BuilderEvent::SubmitBlockRequest(Box::new(signed_blinded_block.clone())));

    let now = utcnow_ms();
    let slot = signed_blinded_block.message.slot;
    let block_hash = signed_blinded_block.message.body.execution_payload_header.block_hash;
    let slot_start_ms = timestamp_of_slot_start_millis(slot, state.config.chain);
    let ua = get_user_agent(&req_headers);
    let (curr_slot, slot_uuid) = state.get_slot_and_uuid();

    info!(?ua, %slot_uuid, ms_into_slot=now.saturating_sub(slot_start_ms), %block_hash);

    if curr_slot != signed_blinded_block.message.slot {
        warn!(expected = curr_slot, got = slot, "blinded beacon slot mismatch")
    }

    match T::submit_block(signed_blinded_block, req_headers, state.clone()).await {
        Ok(res) => {
            trace!(?res);
            state.publish_event(BuilderEvent::SubmitBlockResponse(Box::new(res.clone())));
            info!("received unblinded block");

            BEACON_NODE_STATUS.with_label_values(&["200", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG]).inc();
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

                error!(?err, %block_hash, fault_relays, "CRITICAL: no payload received from relays");
                state.publish_event(BuilderEvent::MissedPayload {
                    block_hash,
                    relays: fault_relays,
                });
            } else {
                error!(?err, %block_hash, "CRITICAL: no payload delivered and no relay for block hash. Was getHeader even called?");
                state.publish_event(BuilderEvent::MissedPayload {
                    block_hash,
                    relays: String::default(),
                });
            };

            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
