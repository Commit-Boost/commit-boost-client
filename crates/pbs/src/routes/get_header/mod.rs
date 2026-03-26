mod relay;
mod validation;

use std::{collections::HashSet, sync::Arc};

use alloy::primitives::U256;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    config::HeaderValidationMode,
    pbs::{GetHeaderInfo, GetHeaderParams, HEADER_TIMEOUT_MS, error::PbsError},
    utils::{
        CONSENSUS_VERSION_HEADER, EncodingType, get_accept_types, get_user_agent,
        get_user_agent_with_version, ms_into_slot,
    },
};
use futures::future::join_all;
use parking_lot::RwLock;
use relay::{RequestInfo, ValidationContext, send_timed_get_header};
use reqwest::{
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
};
use tracing::{Instrument, debug, error, info, warn};

use super::CompoundGetHeaderResponse;
use crate::{
    error::PbsClientError,
    metrics::{BEACON_NODE_STATUS, RELAY_HEADER_VALUE, RELAY_LAST_SLOT},
    state::{PbsState, PbsStateGuard},
};

pub async fn handle_get_header(
    State(state): State<PbsStateGuard>,
    req_headers: HeaderMap,
    Path(params): Path<GetHeaderParams>,
) -> Result<impl IntoResponse, PbsClientError> {
    tracing::Span::current().record("slot", params.slot);
    tracing::Span::current().record("parent_hash", tracing::field::debug(params.parent_hash));
    tracing::Span::current().record("validator", tracing::field::debug(&params.pubkey));

    let state = state.read().clone();

    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);
    let accept_types = get_accept_types(&req_headers).map_err(|e| {
        error!(%e, "error parsing accept header");
        PbsClientError::DecodeError(format!("error parsing accept header: {e}"))
    })?;
    let accepts_ssz = accept_types.contains(&EncodingType::Ssz);
    let accepts_json = accept_types.contains(&EncodingType::Json);

    info!(ua, ms_into_slot, "new request");

    match get_header(params, req_headers, state, accept_types).await {
        Ok(res) => {
            if let Some(max_bid) = res {
                BEACON_NODE_STATUS
                    .with_label_values(&["200", crate::constants::GET_HEADER_ENDPOINT_TAG])
                    .inc();
                match max_bid {
                    CompoundGetHeaderResponse::Light(light_bid) => {
                        // Light validation mode, so just forward the raw response
                        info!(
                            value_eth = alloy::primitives::utils::format_ether(light_bid.value),
                            "received header (unvalidated)"
                        );

                        // Create the headers
                        let consensus_version_header =
                            match HeaderValue::from_str(&light_bid.version.to_string()) {
                                Ok(consensus_version_header) => {
                                    Ok::<HeaderValue, PbsClientError>(consensus_version_header)
                                }
                                Err(e) => {
                                    return Err(PbsClientError::RelayError(format!(
                                        "error decoding consensus version from relay payload: {e}"
                                    )));
                                }
                            }?;
                        let content_type = light_bid.encoding_type.content_type();
                        let content_type_header = HeaderValue::from_str(content_type).unwrap();

                        // Build response
                        let mut res = light_bid.raw_bytes.into_response();
                        res.headers_mut()
                            .insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
                        res.headers_mut().insert(CONTENT_TYPE, content_type_header);
                        info!("sending response as {} (light)", content_type);
                        Ok(res)
                    }
                    CompoundGetHeaderResponse::Full(max_bid) => {
                        // Full validation mode, so respond based on requester accept types
                        info!(value_eth = alloy::primitives::utils::format_ether(*max_bid.data.message.value()), block_hash =% max_bid.block_hash(), "received header");

                        // Handle SSZ
                        if accepts_ssz {
                            use ssz::Encode;
                            let mut res = max_bid.data.as_ssz_bytes().into_response();
                            let consensus_version_header = match HeaderValue::from_str(
                                &max_bid.version.to_string(),
                            ) {
                                Ok(consensus_version_header) => {
                                    Ok::<HeaderValue, PbsClientError>(consensus_version_header)
                                }
                                Err(e) => {
                                    if accepts_json {
                                        info!("sending response as JSON");
                                        return Ok(
                                            (StatusCode::OK, axum::Json(max_bid)).into_response()
                                        );
                                    } else {
                                        return Err(PbsClientError::RelayError(format!(
                                            "error decoding consensus version from relay payload: {e}"
                                        )));
                                    }
                                }
                            }?;

                            // This won't actually fail since the string is a const
                            let content_type_header =
                                HeaderValue::from_str(EncodingType::Ssz.content_type()).unwrap();

                            res.headers_mut()
                                .insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
                            res.headers_mut().insert(CONTENT_TYPE, content_type_header);
                            info!("sending response as SSZ");
                            return Ok(res);
                        }

                        // Handle JSON
                        if accepts_json {
                            Ok((StatusCode::OK, axum::Json(max_bid)).into_response())
                        } else {
                            // This shouldn't ever happen but the compiler needs it
                            Err(PbsClientError::DecodeError(
                                "no viable accept types in request".to_string(),
                            ))
                        }
                    }
                }
            } else {
                // spec: return 204 if request is valid but no bid available
                info!("no header available for slot");

                BEACON_NODE_STATUS
                    .with_label_values(&["204", crate::constants::GET_HEADER_ENDPOINT_TAG])
                    .inc();
                Ok(StatusCode::NO_CONTENT.into_response())
            }
        }
        Err(err) => {
            error!(%err, "no header available from relays");

            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[
                    err.status_code().as_str(),
                    crate::constants::GET_HEADER_ENDPOINT_TAG,
                ])
                .inc();
            Err(err)
        }
    }
}

// ── Relay logic ──────────────────────────────────────────────────────────────

/// Implements https://ethereum.github.io/builder-specs/#/Builder/getHeader
/// Returns 200 if at least one relay returns 200, else 204
pub async fn get_header(
    params: GetHeaderParams,
    req_headers: HeaderMap,
    state: PbsState,
    accepted_types: HashSet<EncodingType>,
) -> eyre::Result<Option<CompoundGetHeaderResponse>> {
    let parent_block = Arc::new(RwLock::new(None));
    let extra_validation_enabled =
        state.config.pbs_config.header_validation_mode == HeaderValidationMode::Extra;
    if extra_validation_enabled && let Some(rpc_url) = state.pbs_config().rpc_url.clone() {
        tokio::spawn(
            validation::fetch_parent_block(rpc_url, params.parent_hash, parent_block.clone())
                .in_current_span(),
        );
    }

    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);
    let (pbs_config, relays, maybe_mux_id) = state.mux_config_and_relays(&params.pubkey);

    if let Some(mux_id) = maybe_mux_id {
        debug!(mux_id, relays = relays.len(), pubkey = %params.pubkey, "using mux config");
    } else {
        debug!(relays = relays.len(), pubkey = %params.pubkey, "using default config");
    }

    let max_timeout_ms = pbs_config
        .timeout_get_header_ms
        .min(pbs_config.late_in_slot_time_ms.saturating_sub(ms_into_slot));

    if max_timeout_ms == 0 {
        warn!(
            ms_into_slot,
            threshold = pbs_config.late_in_slot_time_ms,
            "late in slot, skipping relay requests"
        );

        return Ok(None);
    }

    // Use the minimum of the time left and the user provided timeout header
    let max_timeout_ms = req_headers
        .get(HEADER_TIMEOUT_MS)
        .map(|header| match header.to_str().ok().and_then(|v| v.parse::<u64>().ok()) {
            None | Some(0) => {
                // Header can't be stringified, or parsed, or it's set to 0
                warn!(?header, "invalid user-supplied timeout header, using {max_timeout_ms}ms");
                max_timeout_ms
            }
            Some(user_timeout) => user_timeout.min(max_timeout_ms),
        })
        .unwrap_or(max_timeout_ms);

    // prepare headers, except for start time which is set in `send_one_get_header`
    let mut send_headers = HeaderMap::new();
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers)?);

    // Create the Accept headers for requests
    let mode = state.pbs_config().header_validation_mode;
    let accept_types_str = match mode {
        HeaderValidationMode::None => {
            // No validation mode, so only request what the user wants because the response
            // will be forwarded directly
            accepted_types.iter().map(|t| t.content_type()).collect::<Vec<&str>>().join(",")
        }
        _ => {
            // We're unpacking the body, so request both types since we can handle both
            [EncodingType::Ssz.content_type(), EncodingType::Json.content_type()].join(",")
        }
    };
    send_headers.insert(
        ACCEPT,
        HeaderValue::from_str(&accept_types_str)
            .map_err(|e| PbsError::GeneralRequest(format!("invalid accept header value: {e}")))?,
    );

    // Send requests to all relays concurrently
    let slot = params.slot as i64;
    let request_info = Arc::new(RequestInfo {
        params,
        headers: Arc::new(send_headers),
        chain: state.config.chain,
        validation: ValidationContext {
            skip_sigverify: state.pbs_config().skip_sigverify,
            min_bid_wei: state.pbs_config().min_bid_wei,
            mode,
            parent_block,
        },
        accepted_types,
    });
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(
            send_timed_get_header(
                request_info.clone(),
                relay.clone(),
                ms_into_slot,
                max_timeout_ms,
            )
            .in_current_span(),
        );
    }

    let results = join_all(handles).await;
    let mut relay_bids = Vec::with_capacity(relays.len());
    for (i, res) in results.into_iter().enumerate() {
        let relay_id = relays[i].id.as_str();

        match res {
            Ok(Some(res)) => {
                let value = match &res {
                    CompoundGetHeaderResponse::Full(full) => *full.value(),
                    CompoundGetHeaderResponse::Light(light) => light.value,
                };
                RELAY_LAST_SLOT.with_label_values(&[relay_id]).set(slot);
                let value_gwei = (value / U256::from(1_000_000_000)).try_into().unwrap_or_default();
                RELAY_HEADER_VALUE.with_label_values(&[relay_id]).set(value_gwei);

                relay_bids.push(res)
            }
            Ok(_) => {}
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => error!(%err, relay_id),
        }
    }

    let max_bid = relay_bids.into_iter().max_by_key(|bid| match bid {
        CompoundGetHeaderResponse::Full(full) => *full.value(),
        CompoundGetHeaderResponse::Light(light) => light.value,
    });

    Ok(max_bid)
}
