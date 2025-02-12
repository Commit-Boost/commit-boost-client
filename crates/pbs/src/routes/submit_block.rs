use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use cb_common::{
    pbs::{BuilderEvent, EthSpec, SignedBlindedBeaconBlock},
    utils::{get_user_agent, timestamp_of_slot_start_millis, utcnow_ms},
};
use reqwest::StatusCode;
use serde::Deserialize;
use tracing::{error, info, trace};
use uuid::Uuid;

use crate::{
    api::BuilderApi,
    constants::SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

#[tracing::instrument(skip_all, name = "submit_blinded_block", fields(req_id = %Uuid::new_v4(), slot = signed_blinded_block.message.slot))]
pub async fn handle_submit_block<S: BuilderApiState, T, A: BuilderApi<S, T>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Json(signed_blinded_block): Json<SignedBlindedBeaconBlock<T>>,
) -> Result<impl IntoResponse, PbsClientError>
where
    T: EthSpec + for<'de> Deserialize<'de>,
{
    let state = state.read().clone();

    trace!(?signed_blinded_block);
    state.publish_event(BuilderEvent::SubmitBlockRequest(Box::new(signed_blinded_block.clone())));

    let now = utcnow_ms();
    let slot = signed_blinded_block.message.slot;
    let block_hash = signed_blinded_block.message.body.execution_payload_header.block_hash;
    let slot_start_ms = timestamp_of_slot_start_millis(slot, state.config.chain);
    let ua = get_user_agent(&req_headers);

    info!(ua,  ms_into_slot=now.saturating_sub(slot_start_ms), %block_hash);

    match A::submit_block(signed_blinded_block, req_headers, state.clone()).await {
        Ok(res) => {
            trace!(?res);
            state.publish_event(BuilderEvent::SubmitBlockResponse(Box::new(res.clone())));
            info!("received unblinded block");

            BEACON_NODE_STATUS.with_label_values(&["200", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG]).inc();
            Ok((StatusCode::OK, Json(res).into_response()))
        }

        Err(err) => {
            error!(%err, %block_hash, "CRITICAL: no payload received from relays. Check previous logs or use the Relay Data API");
            state.publish_event(BuilderEvent::<T>::MissedPayload { block_hash });

            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
