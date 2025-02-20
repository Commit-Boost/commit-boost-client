use alloy::primitives::utils::format_ether;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use cb_common::{
    pbs::{BuilderEvent, GetHeaderParams, GetHeaderResponse},
    utils::{get_user_agent, ms_into_slot},
};
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    api::BuilderApi,
    constants::GET_HEADER_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

fn log_get_header(
    params: GetHeaderParams,
    user_agent: String,
    ms_into_slot: u64,
    relays: Vec<String>,
    max_bid: &Option<GetHeaderResponse>,
) {
    if let Some(max_bid) = max_bid {
        info!(
            msg = "received header",
            ua = ?user_agent,
            msIntoSlot = ms_into_slot,
            parentHash = %params.parent_hash,
            pubkey = %max_bid.pubkey(),
            slot = params.slot,
            relays = ?relays,
            valueEth = %format_ether(max_bid.value()),
            blockHash = %max_bid.block_hash(),
            blockNumber = %max_bid.block_number(),
            gasLimit = %max_bid.gas_limit(),
        );
    } else {
        info!(
            msg = "no header available for slot",
            ua = ?user_agent,
            msIntoSlot = ms_into_slot,
            parentHash = %params.parent_hash,
            pubkey = %params.pubkey,
            slot = params.slot,
            relays = ?relays,
        );
    }
}

#[tracing::instrument(skip_all, name = "get_header", fields(req_id = %Uuid::new_v4(), slot = params.slot))]
pub async fn handle_get_header<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetHeaderParams>,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.read().clone();
    state.publish_event(BuilderEvent::GetHeaderRequest(params));

    // inputs for logging
    let relays = state.config.all_relays.iter().map(|r| (*r.id).clone()).collect::<Vec<_>>();
    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);

    match A::get_header(params, req_headers.clone(), state.clone()).await {
        Ok(res) => {
            log_get_header(params, ua, ms_into_slot, relays, &res);
            state.publish_event(BuilderEvent::GetHeaderResponse(Box::new(res.clone())));

            if let Some(max_bid) = res {
                BEACON_NODE_STATUS.with_label_values(&["200", GET_HEADER_ENDPOINT_TAG]).inc();
                Ok((StatusCode::OK, axum::Json(max_bid)).into_response())
            } else {
                BEACON_NODE_STATUS.with_label_values(&["204", GET_HEADER_ENDPOINT_TAG]).inc();
                Ok(StatusCode::NO_CONTENT.into_response())
            }
        }
        Err(err) => {
            log_get_header(params, ua, ms_into_slot, relays, &None);
            error!(%err, "no header available from relays");

            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), GET_HEADER_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
