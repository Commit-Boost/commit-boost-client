use alloy::primitives::utils::format_ether;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    pbs::{GetHeaderInfo, GetHeaderParams},
    utils::ms_into_slot,
    wire::{
        AcceptedEncodingsError, CONSENSUS_VERSION_HEADER, EncodingType, get_accept_types,
        get_user_agent,
    },
};
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::Encode;
use tracing::{debug, error, info};

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
    let accept_types = get_accept_types(&req_headers).inspect_err(|err| {
        error!(%err, "error parsing accept header");
    })?;

    // Honor caller q-value preference: pick the highest-priority encoding that
    // we can actually produce. Server preference for tiebreaks is SSZ first.
    let response_encoding = accept_types.preferred(&[EncodingType::Ssz, EncodingType::Json]);

    info!(ua, ms_into_slot, "new request");

    match A::get_header(params, req_headers, state).await {
        Ok(res) => {
            if let Some(max_bid) = res {
                // Respond based on requester accept types
                info!(value_eth = format_ether(*max_bid.data.message.value()), block_hash =% max_bid.block_hash(), "received header");

                // Three arms: no viable encoding (unreachable in
                // practice — `get_accept_types` errors earlier if
                // the caller offers nothing we support), SSZ, or JSON.
                match response_encoding {
                    None => {
                        BEACON_NODE_STATUS
                            .with_label_values(&["406", GET_HEADER_ENDPOINT_TAG])
                            .inc();
                        Err(PbsClientError::HeaderError(
                            AcceptedEncodingsError::UnsupportedAcceptType,
                        ))
                    }
                    Some(EncodingType::Ssz) => {
                        BEACON_NODE_STATUS
                            .with_label_values(&["200", GET_HEADER_ENDPOINT_TAG])
                            .inc();
                        // ForkName::to_string() always yields valid
                        // ASCII, so HeaderValue::from_str cannot
                        // fail here.
                        let consensus_version_header =
                            HeaderValue::from_str(&max_bid.version.to_string())
                                .expect("fork name is always a valid header value");
                        let content_type_header = EncodingType::Ssz.content_type_header().clone();

                        let mut res = max_bid.data.as_ssz_bytes().into_response();
                        res.headers_mut()
                            .insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
                        res.headers_mut().insert(CONTENT_TYPE, content_type_header);
                        debug!("sending get_header response to BN as SSZ");
                        Ok(res)
                    }
                    Some(EncodingType::Json) => {
                        BEACON_NODE_STATUS
                            .with_label_values(&["200", GET_HEADER_ENDPOINT_TAG])
                            .inc();
                        debug!("sending get_header response to BN as JSON");
                        Ok((StatusCode::OK, axum::Json(max_bid)).into_response())
                    }
                }
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
