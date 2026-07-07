use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::{
    consensus::BlockHeader,
    primitives::{B256, U256, aliases::B32, utils::format_ether},
    providers::Provider,
    rpc::types::Block,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    constants::APPLICATION_BUILDER_DOMAIN,
    pbs::{
        GetExecutionPayloadBidInfo, GetExecutionPayloadBidParams, GetExecutionPayloadBidResponse,
        HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS, RelayClient, SignedRequestAuthV1,
        error::{PbsError, ValidationError},
    },
    signature::verify_signed_message,
    types::{BlsPublicKey, BlsSignature, Chain},
    utils::{ms_into_slot, utcnow_ms},
    wire::{get_user_agent, get_user_agent_with_version, safe_read_http_response},
};
use futures::future::join_all;
use parking_lot::RwLock;
use reqwest::{StatusCode, header::USER_AGENT};
use tokio::time::sleep;
use tracing::{Instrument, debug, error, info, warn};
use tree_hash::TreeHash;
use url::Url;

use crate::{
    PbsStateGuard,
    constants::{
        GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG, GET_HEADER_ENDPOINT_TAG,
        MAX_SIZE_GET_HEADER_RESPONSE, TIMEOUT_ERROR_CODE, TIMEOUT_ERROR_CODE_STR,
    },
    error::PbsClientError,
    metrics::{
        BEACON_NODE_STATUS, RELAY_HEADER_VALUE, RELAY_LAST_SLOT, RELAY_LATENCY, RELAY_STATUS_CODE,
    },
    state::{BuilderApiState, PbsState},
    utils::check_gas_limit,
};

pub async fn handle_get_execution_payload_bid<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetExecutionPayloadBidParams>,
    body: Option<Json<Arc<SignedRequestAuthV1>>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let body = body.map(|Json(auth)| auth);
    tracing::Span::current().record("slot", params.slot);
    tracing::Span::current().record("parent_hash", tracing::field::debug(params.parent_hash));
    tracing::Span::current().record("parent_root", tracing::field::debug(params.parent_root));
    tracing::Span::current().record("validator", tracing::field::debug(&params.pubkey));

    let state = state.read().clone();

    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);

    info!(ua, ms_into_slot, "new request");

    // TODO match over the body
    // if SignedRequestAuthV1 points to builder-> route to URL via
    // send_timed_get_execution_payload_bid else -> route to CB-owned builder
    // list (current get_execution_payload_bid logic)

    match get_execution_payload_bid(params, body, req_headers, state).await {
        Ok(res) => {
            if let Some(max_bid) = res {
                info!(trustless_bid_eth = format_ether(max_bid.value()), execution_payment_eth = format_ether(max_bid.execution_payment()), block_hash =% max_bid.block_hash(), builder_index = max_bid.builder_index(), "received header");

                BEACON_NODE_STATUS
                    .with_label_values(&["200", GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG])
                    .inc();
                Ok((StatusCode::OK, axum::Json(max_bid)).into_response())
            } else {
                // spec: return 204 if request is valid but no bid available
                info!("no header available for slot");

                BEACON_NODE_STATUS
                    .with_label_values(&["204", GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG])
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
                    GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG,
                ])
                .inc();
            Err(err)
        }
    }
}

/// Implements https://ethereum.github.io/builder-specs/?urls.primaryName=dev#/Builder/getExecutionPayloadBid
/// Returns 200 if at least one relay returns 200, else 204
pub async fn get_execution_payload_bid<S: BuilderApiState>(
    params: GetExecutionPayloadBidParams,
    body: Option<Arc<SignedRequestAuthV1>>,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<Option<GetExecutionPayloadBidResponse>> {
    let parent_block = Arc::new(RwLock::new(None));
    if state.extra_validation_enabled() &&
        let Some(rpc_url) = state.pbs_config().rpc_url.clone()
    {
        tokio::spawn(
            fetch_parent_block(rpc_url, params.parent_hash, parent_block.clone()).in_current_span(),
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

    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(
            send_timed_get_execution_payload_bid(
                params.clone(),
                body.clone(),
                relay.clone(),
                send_headers.clone(),
                ms_into_slot,
                max_timeout_ms,
                ValidationContext {
                    skip_sigverify: state.pbs_config().skip_sigverify,
                    min_trustless_bid_gwei: 0, // todo add param
                    max_trusted_bid_gwei: 0,   // todo add param
                    extra_validation_enabled: state.extra_validation_enabled(),
                    parent_block: parent_block.clone(),
                    chain: state.config.chain,
                },
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
                RELAY_LAST_SLOT.with_label_values(&[relay_id]).set(params.slot as i64);
                // TODO bid-sorting policy should use execution payload
                let value_gwei = (U256::from(res.value()) / U256::from(1_000_000_000))
                    .try_into()
                    .unwrap_or_default();
                RELAY_HEADER_VALUE.with_label_values(&[relay_id]).set(value_gwei);

                relay_bids.push((relay_id, res))
            }
            Ok(_) => {}
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => error!(%err, relay_id),
        }
    }

    let max_bid = relay_bids.into_iter().max_by_key(|(_, bid)| bid.value());

    if let Some((winning_relay_id, ref bid)) = max_bid {
        info!(
            relay_id = winning_relay_id,
            bid_eth = format_ether(bid.value() + bid.execution_payment()),
            trustless_bid_eth = format_ether(bid.value()),
            execution_payment_eth = format_ether(bid.execution_payment()),
            block_hash = %bid.block_hash(),
            "auction winner"
        );
    }

    Ok(max_bid.map(|(_, bid)| bid))
}

/// Fetch the parent block from the RPC URL for extra validation of the header.
/// Extra validation will be skipped if:
/// - relay returns header before parent block is fetched
/// - parent block is not found, eg because of a RPC delay
async fn fetch_parent_block(
    rpc_url: Url,
    parent_hash: B256,
    parent_block: Arc<RwLock<Option<Block>>>,
) {
    let provider = alloy::providers::ProviderBuilder::new().connect_http(rpc_url).to_owned();

    debug!(%parent_hash, "fetching parent block");

    match provider.get_block_by_hash(parent_hash).await {
        Ok(maybe_block) => {
            debug!(block_found = maybe_block.is_some(), "fetched parent block");
            let mut guard = parent_block.write();
            *guard = maybe_block;
        }
        Err(err) => {
            error!(%err, "fetch failed");
        }
    }
}

async fn send_timed_get_execution_payload_bid(
    params: GetExecutionPayloadBidParams,
    body: Option<Arc<SignedRequestAuthV1>>,
    relay: RelayClient,
    headers: HeaderMap,
    ms_into_slot: u64,
    mut timeout_left_ms: u64,
    validation: ValidationContext,
) -> Result<Option<GetExecutionPayloadBidResponse>, PbsError> {
    let url = relay.get_execution_payload_bid_url(
        params.slot,
        &params.parent_hash,
        &params.parent_root,
        &params.pubkey,
    )?;

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
                let params = params.clone();
                handles.push(tokio::spawn(
                    send_one_get_execution_payload_bid(
                        params,
                        body.clone(),
                        relay.clone(),
                        RequestContext {
                            timeout_ms: timeout_left_ms,
                            url: url.clone(),
                            headers: headers.clone(),
                        },
                        validation.clone(),
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

            let results = join_all(handles).await;
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
    send_one_get_execution_payload_bid(
        params,
        body,
        relay,
        RequestContext { timeout_ms: timeout_left_ms, url, headers },
        validation,
    )
    .await
    .map(|(_, maybe_header)| maybe_header)
}

struct RequestContext {
    url: Url,
    timeout_ms: u64,
    headers: HeaderMap,
}

#[derive(Clone)]
struct ValidationContext {
    skip_sigverify: bool,
    min_trustless_bid_gwei: u64,
    max_trusted_bid_gwei: u64,
    extra_validation_enabled: bool,
    parent_block: Arc<RwLock<Option<Block>>>,
    chain: Chain,
}

async fn send_one_get_execution_payload_bid(
    params: GetExecutionPayloadBidParams,
    body: Option<Arc<SignedRequestAuthV1>>,
    relay: RelayClient,
    mut req_config: RequestContext,
    validation: ValidationContext,
) -> Result<(u64, Option<GetExecutionPayloadBidResponse>), PbsError> {
    // the timestamp in the header is the consensus block time which is fixed,
    // use the beginning of the request as proxy to make sure we use only the
    // last one received
    let start_request_time = utcnow_ms();
    req_config.headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(start_request_time));

    // The timeout header indicating how long a relay has to respond, so they can
    // minimize timing games without losing the bid
    req_config.headers.insert(HEADER_TIMEOUT_MS, HeaderValue::from(req_config.timeout_ms));

    let start_request = Instant::now();
    let res = match relay
        .client
        .post(req_config.url)
        .timeout(Duration::from_millis(req_config.timeout_ms))
        .headers(req_config.headers)
        .json(&body)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            RELAY_STATUS_CODE
                .with_label_values(&[TIMEOUT_ERROR_CODE_STR, GET_HEADER_ENDPOINT_TAG, &relay.id])
                .inc();
            return Err(err.into());
        }
    };

    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[GET_HEADER_ENDPOINT_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());

    let code = res.status();
    RELAY_STATUS_CODE.with_label_values(&[code.as_str(), GET_HEADER_ENDPOINT_TAG, &relay.id]).inc();

    let response_bytes = safe_read_http_response(res, MAX_SIZE_GET_HEADER_RESPONSE).await?;
    let header_size_bytes = response_bytes.len();
    if code == StatusCode::NO_CONTENT {
        debug!(
            relay_id = relay.id.as_ref(),
            ?code,
            latency = ?request_latency,
            response = ?response_bytes,
            "no header from relay"
        );
        return Ok((start_request_time, None));
    }

    let get_header_response =
        match serde_json::from_slice::<GetExecutionPayloadBidResponse>(&response_bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                return Err(PbsError::JsonDecode {
                    err,
                    raw: String::from_utf8_lossy(&response_bytes).into_owned(),
                });
            }
        };

    info!(
        relay_id = relay.id.as_ref(),
        header_size_bytes,
        latency = ?request_latency,
        version =? get_header_response.version,
        bid_eth = format_ether(get_header_response.data.message.value + get_header_response.data.message.execution_payment),
        trustless_bid_eth = format_ether(get_header_response.data.message.value),
        execution_payment_eth = format_ether(get_header_response.data.message.execution_payment),
        block_hash = %get_header_response.data.message.block_hash,
        "received new header"
    );

    let header_info = HeaderInfo {
        block_hash: get_header_response.block_hash(),
        parent_hash: get_header_response.parent_hash(),
        parent_root: get_header_response.parent_root(),
        slot: get_header_response.slot(),
        trustless_payment: get_header_response.value(),
        trusted_payment: get_header_response.execution_payment(),
        gas_limit: get_header_response.gas_limit(),
    };

    validate_header_data(
        &header_info,
        &params,
        validation.min_trustless_bid_gwei,
        validation.max_trusted_bid_gwei,
    )?;

    if !validation.skip_sigverify {
        validate_signature(
            validation.chain,
            relay.pubkey(),
            &get_header_response.data.message,
            &get_header_response.data.signature,
        )?;
    }

    if validation.extra_validation_enabled {
        let parent_block = validation.parent_block.read();
        if let Some(parent_block) = parent_block.as_ref() {
            extra_validation(parent_block, &header_info, &params)?;
        } else {
            warn!(
                relay_id = relay.id.as_ref(),
                "parent block not found, skipping extra validation"
            );
        }
    }

    Ok((start_request_time, Some(get_header_response)))
}

struct HeaderInfo {
    block_hash: B256,
    parent_hash: B256,
    parent_root: B256,
    slot: u64,
    trustless_payment: u64,
    trusted_payment: u64,
    gas_limit: u64,
}

fn validate_header_data(
    header_info: &HeaderInfo,
    params: &GetExecutionPayloadBidParams,
    min_trustless_bid_gwei: u64,
    max_trusted_bid_gwei: u64,
) -> Result<(), ValidationError> {
    if header_info.block_hash == B256::ZERO {
        return Err(ValidationError::EmptyBlockhash);
    }

    if params.parent_hash != header_info.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            expected: params.parent_hash,
            got: header_info.parent_hash,
        });
    }

    if params.parent_root != header_info.parent_root {
        return Err(ValidationError::ParentRootMismatch {
            expected: params.parent_root,
            got: header_info.parent_root,
        });
    }

    if params.slot != header_info.slot {
        return Err(ValidationError::SlotNumberMismatch {
            expected: params.slot,
            got: header_info.slot,
        });
    }

    if header_info.trustless_payment < min_trustless_bid_gwei {
        return Err(ValidationError::TrustlessBidTooLow {
            min: min_trustless_bid_gwei,
            got: header_info.trustless_payment,
        });
    }

    if header_info.trusted_payment > max_trusted_bid_gwei {
        return Err(ValidationError::TrustedBidTooHigh {
            max: max_trusted_bid_gwei,
            got: header_info.trusted_payment,
        });
    }

    Ok(())
}

fn validate_signature<T: TreeHash>(
    chain: Chain,
    expected_pubkey: &BlsPublicKey,
    message: &T,
    signature: &BlsSignature,
) -> Result<(), ValidationError> {
    if !verify_signed_message(
        chain,
        expected_pubkey,
        &message,
        signature,
        None,
        &B32::from(APPLICATION_BUILDER_DOMAIN),
    ) {
        return Err(ValidationError::Sigverify);
    }

    Ok(())
}

fn extra_validation(
    parent_block: &Block,
    header_info: &HeaderInfo,
    params: &GetExecutionPayloadBidParams,
) -> Result<(), ValidationError> {
    if parent_block.hash() != params.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            got: parent_block.header.parent_hash,
            expected: params.parent_hash,
        });
    };

    let Some(parent_root) = parent_block.header.parent_beacon_block_root() else {
        tracing::error!("parent block is missing parent_beacon_block_root");
        return Err(ValidationError::EmptyParentRoot);
    };

    if parent_root != params.parent_root {
        return Err(ValidationError::ParentRootMismatch {
            got: parent_root,
            expected: params.parent_root,
        });
    }

    // TODO potentially check builder index -> pubkey mapping

    if !check_gas_limit(header_info.gas_limit, parent_block.header.gas_limit) {
        return Err(ValidationError::GasLimit {
            parent: parent_block.header.gas_limit,
            header: header_info.gas_limit,
        });
    };

    Ok(())
}

#[cfg(test)]
mod tests {

    use alloy::primitives::B256;
    use cb_common::{
        pbs::error::ValidationError,
        signature::sign_builder_message,
        types::{BlsSecretKey, Chain},
        utils::TestRandomSeed,
    };

    use super::{validate_header_data, *};

    #[test]
    fn test_validate_header() {
        let slot = 5;
        let parent_hash = B256::from_slice(&[1; 32]);
        let parent_root = B256::from_slice(&[2; 32]);
        let min_trustless_payment = 500;
        let max_trusted_payment = 1000;
        let secret_key = BlsSecretKey::test_random();
        let pubkey = secret_key.public_key();

        let mock_params = GetExecutionPayloadBidParams {
            slot,
            parent_hash: parent_hash.clone(),
            parent_root: parent_root.clone(),
            pubkey,
        };

        let mut mock_header_data = HeaderInfo {
            block_hash: B256::default(),
            parent_hash: B256::default(),
            parent_root: B256::default(),
            slot: 0,
            trustless_payment: min_trustless_payment - 1,
            trusted_payment: max_trusted_payment + 1,
            gas_limit: 0,
        };

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_trustless_payment,
                max_trusted_payment,
            ),
            Err(ValidationError::EmptyBlockhash)
        );

        mock_header_data.block_hash.0[1] = 1;

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_trustless_payment,
                max_trusted_payment,
            ),
            Err(ValidationError::ParentHashMismatch {
                expected: mock_params.parent_hash,
                got: B256::default()
            })
        );

        mock_header_data.parent_hash = parent_hash;

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_trustless_payment,
                max_trusted_payment,
            ),
            Err(ValidationError::ParentRootMismatch {
                expected: mock_params.parent_root,
                got: B256::default()
            })
        );

        mock_header_data.parent_root = parent_root;

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_trustless_payment,
                max_trusted_payment,
            ),
            Err(ValidationError::SlotNumberMismatch { expected: slot, got: 0 })
        );

        mock_header_data.slot = slot;

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_trustless_payment,
                max_trusted_payment,
            ),
            Err(ValidationError::TrustlessBidTooLow {
                min: min_trustless_payment,
                got: mock_header_data.trustless_payment,
            })
        );

        mock_header_data.trustless_payment = min_trustless_payment;

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_trustless_payment,
                max_trusted_payment,
            ),
            Err(ValidationError::TrustedBidTooHigh {
                max: max_trusted_payment,
                got: mock_header_data.trusted_payment,
            })
        );

        mock_header_data.trusted_payment = max_trusted_payment;

        validate_header_data(
            &mock_header_data,
            &mock_params,
            min_trustless_payment,
            max_trusted_payment,
        )
        .unwrap();
    }

    #[test]
    fn test_validate_signature() {
        let secret_key = BlsSecretKey::test_random();
        let pubkey = secret_key.public_key();
        let wrong_signature = BlsSignature::test_random();

        let message = B256::random();

        let signature = sign_builder_message(Chain::Holesky, &secret_key, &message);

        assert!(matches!(
            validate_signature(Chain::Holesky, &pubkey, &message, &wrong_signature),
            Err(ValidationError::Sigverify)
        ));

        assert!(validate_signature(Chain::Holesky, &pubkey, &message, &signature).is_ok());
    }
}
