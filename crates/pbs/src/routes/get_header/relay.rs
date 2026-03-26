use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::primitives::{U256, utils::format_ether};
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    config::HeaderValidationMode,
    pbs::{
        ExecutionPayloadHeaderRef, ForkName, GetHeaderInfo, GetHeaderParams, GetHeaderResponse,
        HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS, RelayClient,
        error::{PbsError, ValidationError},
    },
    types::Chain,
    utils::{
        EncodingType, get_bid_value_from_signed_builder_bid_ssz, get_consensus_version_header,
        read_chunked_body_with_max, utcnow_ms,
    },
};
use parking_lot::RwLock;
use reqwest::{StatusCode, header::CONTENT_TYPE};
use tokio::time::sleep;
use tracing::{Instrument, debug, error, warn};
use url::Url;

use super::{
    super::{CompoundGetHeaderResponse, LightGetHeaderResponse},
    validation::{
        HeaderData, decode_json_payload, decode_ssz_payload, extra_validation,
        get_light_info_from_json, validate_header_data, validate_signature,
    },
};
use crate::constants::{
    GET_HEADER_ENDPOINT_TAG, MAX_SIZE_GET_HEADER_RESPONSE, TIMEOUT_ERROR_CODE,
    TIMEOUT_ERROR_CODE_STR,
};

/// Info about an incoming get_header request.
/// Sent from get_header to each send_timed_get_header call.
#[derive(Clone)]
pub struct RequestInfo {
    /// The blockchain parameters of the get_header request (what slot it's for,
    /// which pubkey is requesting it, etc)
    pub params: GetHeaderParams,

    /// Common baseline of headers to send with each request
    pub headers: Arc<HeaderMap>,

    /// The chain the request is for
    pub chain: Chain,

    /// Context for validating the header returned by the relay
    pub validation: ValidationContext,

    /// The accepted encoding types from the original request
    pub accepted_types: HashSet<EncodingType>,
}

/// Used internally to provide info and context about a get_header request and
/// its response
struct GetHeaderResponseInfo {
    /// ID of the relay the response came from
    relay_id: Arc<String>,

    /// The raw body of the response
    response_bytes: Vec<u8>,

    /// The content type the response is encoded with
    content_type: EncodingType,

    /// Which fork the response bid is for (if provided as a header, rather than
    /// part of the body)
    fork: Option<ForkName>,

    /// The status code of the response, for logging
    code: StatusCode,

    /// The round-trip latency of the request
    request_latency: Duration,
}

/// Context for validating the header
#[derive(Clone)]
pub struct ValidationContext {
    /// Whether to skip signature verification
    pub skip_sigverify: bool,

    /// Minimum acceptable bid, in wei
    pub min_bid_wei: U256,

    /// The mode used for response validation
    pub mode: HeaderValidationMode,

    /// The parent block, if fetched
    pub parent_block: Arc<RwLock<Option<alloy::rpc::types::Block>>>,
}

pub async fn send_timed_get_header(
    request_info: Arc<RequestInfo>,
    relay: RelayClient,
    ms_into_slot: u64,
    mut timeout_left_ms: u64,
) -> Result<Option<CompoundGetHeaderResponse>, PbsError> {
    let params = &request_info.params;
    let url = Arc::new(relay.get_header_url(params.slot, &params.parent_hash, &params.pubkey)?);

    if relay.config.enable_timing_games {
        if let Some(target_ms) = relay.config.target_first_request_ms {
            // sleep until target time in slot

            let delay = target_ms.saturating_sub(ms_into_slot);
            if delay > 0 {
                debug!(
                    relay_id = relay.id.as_ref(),
                    target_ms, ms_into_slot, "TG: waiting to send first header request"
                );
                timeout_left_ms = timeout_left_ms.saturating_sub(delay);
                sleep(Duration::from_millis(delay)).await;
            } else {
                debug!(
                    relay_id = relay.id.as_ref(),
                    target_ms, ms_into_slot, "TG: request already late enough in slot"
                );
            }
        }

        if let Some(send_freq_ms) = relay.config.frequency_get_header_ms {
            let mut handles = Vec::new();

            debug!(
                relay_id = relay.id.as_ref(),
                send_freq_ms, timeout_left_ms, "TG: sending multiple header requests"
            );

            loop {
                handles.push(tokio::spawn(
                    send_one_get_header(
                        request_info.clone(),
                        relay.clone(),
                        url.clone(),
                        timeout_left_ms,
                    )
                    .in_current_span(),
                ));

                if timeout_left_ms > send_freq_ms {
                    // enough time for one more
                    timeout_left_ms = timeout_left_ms.saturating_sub(send_freq_ms);
                    sleep(Duration::from_millis(send_freq_ms)).await;
                } else {
                    break;
                }
            }

            let results = futures::future::join_all(handles).await;
            let mut n_headers = 0;

            if let Some((_, maybe_header)) = results
                .into_iter()
                .filter_map(|res| {
                    // ignore join error and timeouts, log other errors
                    res.ok().and_then(|inner_res| match inner_res {
                        Ok(maybe_header) => {
                            if maybe_header.1.is_some() {
                                n_headers += 1;
                                Some(maybe_header)
                            } else {
                                // filter out 204 responses that are returned if the request
                                // is after the relay cutoff
                                None
                            }
                        }
                        Err(err) if err.is_timeout() => None,
                        Err(err) => {
                            error!(relay_id = relay.id.as_ref(),%err, "TG: error sending header request");
                            None
                        }
                    })
                })
                .max_by_key(|(start_time, _)| *start_time)
            {
                debug!(relay_id = relay.id.as_ref(), n_headers, "TG: received headers from relay");
                return Ok(maybe_header);
            } else {
                // all requests failed
                warn!(relay_id = relay.id.as_ref(), "TG: no headers received");

                return Err(PbsError::RelayResponse {
                    error_msg: "no headers received".to_string(),
                    code: TIMEOUT_ERROR_CODE,
                });
            }
        }
    }

    // if no timing games or no repeated send, just send one request
    send_one_get_header(request_info, relay, url, timeout_left_ms)
        .await
        .map(|(_, maybe_header)| maybe_header)
}

/// Handles requesting a header from a relay, decoding, and validation.
/// Used by send_timed_get_header to handle each individual request.
async fn send_one_get_header(
    request_info: Arc<RequestInfo>,
    relay: RelayClient,
    url: Arc<Url>,
    timeout_left_ms: u64,
) -> Result<(u64, Option<CompoundGetHeaderResponse>), PbsError> {
    match request_info.validation.mode {
        HeaderValidationMode::None => {
            // Minimal processing: extract fork and value, forward response bytes directly.
            // Expensive crypto/structural validation is skipped (sigverify, parent hash,
            // timestamp), but the min_bid check is applied.
            let (start_request_time, get_header_response) = send_get_header_light(
                &relay,
                url,
                timeout_left_ms,
                (*request_info.headers).clone(), /* Create a copy of the HeaderMap because the
                                                  * impl
                                                  * will
                                                  * modify it */
            )
            .await?;
            match get_header_response {
                None => Ok((start_request_time, None)),
                Some(res) => {
                    let min_bid = request_info.validation.min_bid_wei;
                    if res.value < min_bid {
                        return Err(PbsError::Validation(ValidationError::BidTooLow {
                            min: min_bid,
                            got: res.value,
                        }));
                    }

                    // Make sure the response is encoded in one of the accepted
                    // types since we're passing the raw response directly to the client
                    if !request_info.accepted_types.contains(&res.encoding_type) {
                        return Err(PbsError::RelayResponse {
                            error_msg: format!(
                                "relay returned unsupported encoding type for get_header in no-validation mode: {:?}",
                                res.encoding_type
                            ),
                            code: 406, // Not Acceptable
                        });
                    }
                    Ok((start_request_time, Some(CompoundGetHeaderResponse::Light(res))))
                }
            }
        }
        _ => {
            // Full processing: decode full response and validate
            let (start_request_time, get_header_response) = send_get_header_full(
                &relay,
                url,
                timeout_left_ms,
                (*request_info.headers).clone(), /* Create a copy of the HeaderMap because the
                                                  * impl
                                                  * will
                                                  * modify it */
            )
            .await?;
            let get_header_response = match get_header_response {
                None => {
                    // Break if there's no header
                    return Ok((start_request_time, None));
                }
                Some(res) => res,
            };

            // Extract the basic header data needed for validation
            let header_data = match &get_header_response.data.message.header() {
                ExecutionPayloadHeaderRef::Bellatrix(_) |
                ExecutionPayloadHeaderRef::Capella(_) |
                ExecutionPayloadHeaderRef::Deneb(_) |
                ExecutionPayloadHeaderRef::Gloas(_) => {
                    Err(PbsError::Validation(ValidationError::UnsupportedFork))
                }
                ExecutionPayloadHeaderRef::Electra(res) => Ok(HeaderData {
                    block_hash: res.block_hash.0,
                    parent_hash: res.parent_hash.0,
                    tx_root: res.transactions_root,
                    value: *get_header_response.value(),
                    timestamp: res.timestamp,
                }),
                ExecutionPayloadHeaderRef::Fulu(res) => Ok(HeaderData {
                    block_hash: res.block_hash.0,
                    parent_hash: res.parent_hash.0,
                    tx_root: res.transactions_root,
                    value: *get_header_response.value(),
                    timestamp: res.timestamp,
                }),
            }?;

            // Validate the header
            let chain = request_info.chain;
            let params = &request_info.params;
            let validation = &request_info.validation;
            validate_header_data(
                &header_data,
                chain,
                params.parent_hash,
                validation.min_bid_wei,
                params.slot,
            )?;

            // Validate the relay signature
            if !validation.skip_sigverify {
                validate_signature(
                    chain,
                    relay.pubkey(),
                    get_header_response.data.message.pubkey(),
                    &get_header_response.data.message,
                    &get_header_response.data.signature,
                )?;
            }

            // Validate the parent block if enabled
            if validation.mode == HeaderValidationMode::Extra {
                let parent_block = validation.parent_block.read();
                if let Some(parent_block) = parent_block.as_ref() {
                    extra_validation(parent_block, &get_header_response)?;
                } else {
                    warn!(
                        relay_id = relay.id.as_ref(),
                        "parent block not found, skipping extra validation"
                    );
                }
            }

            Ok((
                start_request_time,
                Some(CompoundGetHeaderResponse::Full(Box::new(get_header_response))),
            ))
        }
    }
}

/// Send and decode a full get_header response, will all of the fields.
async fn send_get_header_full(
    relay: &RelayClient,
    url: Arc<Url>,
    timeout_left_ms: u64,
    headers: HeaderMap,
) -> Result<(u64, Option<GetHeaderResponse>), PbsError> {
    // Send the request
    let (start_request_time, info) =
        send_get_header_impl(relay, url, timeout_left_ms, headers).await?;
    let info = match info {
        Some(info) => info,
        None => {
            return Ok((start_request_time, None));
        }
    };

    // Decode the response
    let get_header_response = match info.content_type {
        EncodingType::Json => decode_json_payload(&info.response_bytes)?,
        EncodingType::Ssz => {
            let fork = info.fork.ok_or(PbsError::RelayResponse {
                error_msg: "relay did not provide consensus version header for ssz payload"
                    .to_string(),
                code: info.code.as_u16(),
            })?;
            decode_ssz_payload(&info.response_bytes, fork)?
        }
    };

    // Log and return
    debug!(
        relay_id = info.relay_id.as_ref(),
        header_size_bytes = info.response_bytes.len(),
        latency = ?info.request_latency,
        version =? get_header_response.version,
        value_eth = format_ether(*get_header_response.value()),
        block_hash = %get_header_response.block_hash(),
        content_type = ?info.content_type,
        "received new header"
    );
    Ok((start_request_time, Some(get_header_response)))
}

/// Send a get_header request and decode only the fork and bid value from the
/// response, leaving the raw bytes intact for direct forwarding to the caller.
/// Used in `HeaderValidationMode::None` where expensive crypto/structural
/// checks are skipped.
async fn send_get_header_light(
    relay: &RelayClient,
    url: Arc<Url>,
    timeout_left_ms: u64,
    headers: HeaderMap,
) -> Result<(u64, Option<LightGetHeaderResponse>), PbsError> {
    // Send the request
    let (start_request_time, info) =
        send_get_header_impl(relay, url, timeout_left_ms, headers).await?;
    let info = match info {
        Some(info) => info,
        None => {
            return Ok((start_request_time, None));
        }
    };

    // Decode the value / fork from the response
    let (fork, value) = match info.content_type {
        EncodingType::Json => get_light_info_from_json(&info.response_bytes)?,
        EncodingType::Ssz => {
            let fork = info.fork.ok_or(PbsError::RelayResponse {
                error_msg: "relay did not provide consensus version header for ssz payload"
                    .to_string(),
                code: info.code.as_u16(),
            })?;
            (fork, get_bid_value_from_signed_builder_bid_ssz(&info.response_bytes, fork)?)
        }
    };

    // Log and return
    debug!(
        relay_id = info.relay_id.as_ref(),
        header_size_bytes = info.response_bytes.len(),
        latency = ?info.request_latency,
        version =? fork,
        value_eth = format_ether(value),
        content_type = ?info.content_type,
        "received new header (light processing)"
    );
    Ok((
        start_request_time,
        Some(LightGetHeaderResponse {
            version: fork,
            value,
            raw_bytes: info.response_bytes,
            encoding_type: info.content_type,
        }),
    ))
}

/// Sends a get_header request to a relay, returning the response, the time the
/// request was started, and the encoding type of the response (if any).
/// Used by send_one_get_header to perform the actual request submission.
async fn send_get_header_impl(
    relay: &RelayClient,
    url: Arc<Url>,
    timeout_left_ms: u64,
    mut headers: HeaderMap,
) -> Result<(u64, Option<GetHeaderResponseInfo>), PbsError> {
    // the timestamp in the header is the consensus block time which is fixed,
    // use the beginning of the request as proxy to make sure we use only the
    // last one received
    let start_request = Instant::now();
    let start_request_time = utcnow_ms();
    headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(start_request_time));

    // The timeout header indicating how long a relay has to respond, so they can
    // minimize timing games without losing the bid
    headers.insert(HEADER_TIMEOUT_MS, HeaderValue::from(timeout_left_ms));

    let res = match relay
        .client
        .get(url.as_ref().clone())
        .timeout(Duration::from_millis(timeout_left_ms))
        .headers(headers)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            crate::metrics::RELAY_STATUS_CODE
                .with_label_values(&[TIMEOUT_ERROR_CODE_STR, GET_HEADER_ENDPOINT_TAG, &relay.id])
                .inc();
            return Err(err.into());
        }
    };

    // Log the response code and latency
    let code = res.status();
    let request_latency = start_request.elapsed();
    super::super::record_relay_metrics(GET_HEADER_ENDPOINT_TAG, &relay.id, code, request_latency);

    // According to the spec, OK is the only allowed success code so this can break
    // early
    if code != StatusCode::OK {
        if code == StatusCode::NO_CONTENT {
            let response_bytes =
                read_chunked_body_with_max(res, MAX_SIZE_GET_HEADER_RESPONSE).await?;
            debug!(
                relay_id = relay.id.as_ref(),
                ?code,
                latency = ?request_latency,
                response = ?response_bytes,
                "no header from relay"
            );
            return Ok((start_request_time, None));
        } else {
            return Err(PbsError::RelayResponse {
                error_msg: format!("unexpected status code from relay: {code}"),
                code: code.as_u16(),
            });
        }
    }

    // Get the content type
    let content_type = match res.headers().get(CONTENT_TYPE) {
        None => {
            // Assume a missing content type means JSON; shouldn't happen in practice with
            // any respectable HTTP server but just in case
            EncodingType::Json
        }
        Some(header_value) => match header_value.to_str().map_err(|e| PbsError::RelayResponse {
            error_msg: format!("cannot decode content-type header: {e}").to_string(),
            code: (code.as_u16()),
        })? {
            header_str if header_str.eq_ignore_ascii_case(&EncodingType::Ssz.to_string()) => {
                EncodingType::Ssz
            }
            header_str if header_str.eq_ignore_ascii_case(&EncodingType::Json.to_string()) => {
                EncodingType::Json
            }
            header_str => {
                return Err(PbsError::RelayResponse {
                    error_msg: format!("unsupported content type: {header_str}"),
                    code: code.as_u16(),
                })
            }
        },
    };

    // Decode the body
    let fork = get_consensus_version_header(res.headers());
    let response_bytes = read_chunked_body_with_max(res, MAX_SIZE_GET_HEADER_RESPONSE).await?;
    Ok((
        start_request_time,
        Some(GetHeaderResponseInfo {
            relay_id: relay.id.clone(),
            response_bytes,
            content_type,
            fork,
            code,
            request_latency,
        }),
    ))
}
