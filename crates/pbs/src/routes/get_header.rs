use alloy::primitives::utils::format_ether;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use cb_common::{
    pbs::{GetHeaderInfo, GetHeaderParams},
    utils::{get_user_agent, ms_into_slot},
};
use reqwest::StatusCode;
use tracing::{error, info};

use crate::{
    api::BuilderApi,
    constants::GET_HEADER_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

pub async fn handle_get_header<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetHeaderParams>,
) -> Result<impl IntoResponse, PbsClientError> {
    tracing::Span::current().record("slot", params.slot);
    tracing::Span::current().record("parent_hash", tracing::field::debug(params.parent_hash));
    tracing::Span::current().record("validator", tracing::field::debug(&params.pubkey));

    let state = state.read().clone();

    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);

    info!(ua, ms_into_slot, "new request");

    match A::get_header(params, req_headers, state).await {
        Ok(res) => {
            if let Some(max_bid) = res {
                info!(value_eth = format_ether(*max_bid.data.message.value()), block_hash =% max_bid.block_hash(), "received header");

                BEACON_NODE_STATUS.with_label_values(&["200", GET_HEADER_ENDPOINT_TAG]).inc();
                Ok((StatusCode::OK, axum::Json(max_bid)).into_response())
            } else {
                // spec: return 204 if request is valid but no bid available
                info!("no header available for slot");

                BEACON_NODE_STATUS.with_label_values(&["204", GET_HEADER_ENDPOINT_TAG]).inc();
                Ok(StatusCode::NO_CONTENT.into_response())
            }
        }
        Err(err) => {
            error!(%err, "no header available from relays");

            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), GET_HEADER_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
