use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::{
    primitives::{utils::format_ether, B256, U256},
    providers::Provider,
    rpc::types::{beacon::BlsPublicKey, Block, BlockTransactionsKind},
};
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    constants::APPLICATION_BUILDER_DOMAIN,
    pbs::{
        error::{PbsError, ValidationError},
        GetHeaderParams, GetHeaderResponse, RelayClient, SignedExecutionPayloadHeader,
        EMPTY_TX_ROOT_HASH, HEADER_SLOT_UUID_KEY, HEADER_START_TIME_UNIX_MS,
    },
    signature::verify_signed_message,
    types::Chain,
    utils::{get_user_agent_with_version, ms_into_slot, timestamp_of_slot_start_sec, utcnow_ms},
};
use futures::future::join_all;
use parking_lot::RwLock;
use reqwest::{header::USER_AGENT, StatusCode};
use tokio::time::sleep;
use tracing::{debug, error, warn, Instrument};
use url::Url;

use crate::{
    constants::{
        GET_HEADER_ENDPOINT_TAG, MAX_SIZE_GET_HEADER, TIMEOUT_ERROR_CODE, TIMEOUT_ERROR_CODE_STR,
    },
    metrics::{RELAY_HEADER_VALUE, RELAY_LAST_SLOT, RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
    utils::{check_gas_limit, read_chunked_body_with_max},
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/getHeader
/// Returns 200 if at least one relay returns 200, else 204
pub async fn get_header<S: BuilderApiState>(
    params: GetHeaderParams,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<Option<GetHeaderResponse>> {
    let parent_block = Arc::new(RwLock::new(None));
    if state.extra_validation_enabled() {
        if let Some(rpc_url) = state.pbs_config().rpc_url.clone() {
            tokio::spawn(fetch_parent_block(rpc_url, params.parent_hash, parent_block.clone()));
        }
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

    let (_, slot_uuid) = state.get_slot_and_uuid();

    // prepare headers, except for start time which is set in `send_one_get_header`
    let mut send_headers = HeaderMap::new();
    send_headers.insert(HEADER_SLOT_UUID_KEY, HeaderValue::from_str(&slot_uuid.to_string())?);
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers)?);

    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(send_timed_get_header(
            params,
            relay.clone(),
            state.config.chain,
            send_headers.clone(),
            ms_into_slot,
            max_timeout_ms,
            ValidationContext {
                skip_sigverify: state.pbs_config().skip_sigverify,
                min_bid_wei: state.pbs_config().min_bid_wei,
                extra_validation_enabled: state.extra_validation_enabled(),
                parent_block: parent_block.clone(),
            },
        ));
    }

    let results = join_all(handles).await;
    let mut relay_bids = Vec::with_capacity(relays.len());
    for (i, res) in results.into_iter().enumerate() {
        let relay_id = relays[i].id.as_str();

        match res {
            Ok(Some(res)) => {
                RELAY_LAST_SLOT.with_label_values(&[relay_id]).set(params.slot as i64);
                let value_gwei =
                    (res.value() / U256::from(1_000_000_000)).try_into().unwrap_or_default();
                RELAY_HEADER_VALUE.with_label_values(&[relay_id]).set(value_gwei);

                relay_bids.push(res)
            }
            Ok(_) => {}
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => error!(%err, relay_id),
        }
    }

    Ok(state.add_bids(params.slot, relay_bids))
}

/// Fetch the parent block from the RPC URL for extra validation of the header.
/// Extra validation will be skipped if:
/// - relay returns header before parent block is fetched
/// - parent block is not found, eg because of a RPC delay
#[tracing::instrument(skip_all, name = "parent_block_fetch")]
async fn fetch_parent_block(
    rpc_url: Url,
    parent_hash: B256,
    parent_block: Arc<RwLock<Option<Block>>>,
) {
    let provider = alloy::providers::ProviderBuilder::new().on_http(rpc_url).to_owned();

    debug!(%parent_hash, "fetching parent block");

    match provider.get_block_by_hash(parent_hash, BlockTransactionsKind::Hashes).await {
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

#[tracing::instrument(skip_all, name = "handler", fields(relay_id = relay.id.as_ref()))]
async fn send_timed_get_header(
    params: GetHeaderParams,
    relay: RelayClient,
    chain: Chain,
    headers: HeaderMap,
    ms_into_slot: u64,
    mut timeout_left_ms: u64,
    validation: ValidationContext,
) -> Result<Option<GetHeaderResponse>, PbsError> {
    let url = relay.get_header_url(params.slot, params.parent_hash, params.pubkey)?;

    if relay.config.enable_timing_games {
        if let Some(target_ms) = relay.config.target_first_request_ms {
            // sleep until target time in slot

            let delay = target_ms.saturating_sub(ms_into_slot);
            if delay > 0 {
                debug!(target_ms, ms_into_slot, "TG: waiting to send first header request");
                timeout_left_ms = timeout_left_ms.saturating_sub(delay);
                sleep(Duration::from_millis(delay)).await;
            } else {
                debug!(target_ms, ms_into_slot, "TG: request already late enough in slot");
            }
        }

        if let Some(send_freq_ms) = relay.config.frequency_get_header_ms {
            let mut handles = Vec::new();

            debug!(send_freq_ms, timeout_left_ms, "TG: sending multiple header requests");

            loop {
                handles.push(tokio::spawn(
                    send_one_get_header(
                        params,
                        relay.clone(),
                        chain,
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
                            error!(%err, "TG: error sending header request");
                            None
                        }
                    })
                })
                .max_by_key(|(start_time, _)| *start_time)
            {
                debug!(n_headers, "TG: received headers from relay");
                return Ok(maybe_header);
            } else {
                // all requests failed
                warn!("TG: no headers received");

                return Err(PbsError::RelayResponse {
                    error_msg: "no headers received".to_string(),
                    code: TIMEOUT_ERROR_CODE,
                });
            }
        }
    }

    // if no timing games or no repeated send, just send one request
    send_one_get_header(
        params,
        relay,
        chain,
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
    min_bid_wei: U256,
    extra_validation_enabled: bool,
    parent_block: Arc<RwLock<Option<Block>>>,
}

async fn send_one_get_header(
    params: GetHeaderParams,
    relay: RelayClient,
    chain: Chain,
    mut req_config: RequestContext,
    validation: ValidationContext,
) -> Result<(u64, Option<GetHeaderResponse>), PbsError> {
    // the timestamp in the header is the consensus block time which is fixed,
    // use the beginning of the request as proxy to make sure we use only the
    // last one received
    let start_request_time = utcnow_ms();
    req_config.headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(start_request_time));

    let start_request = Instant::now();
    let res = match relay
        .client
        .get(req_config.url)
        .timeout(Duration::from_millis(req_config.timeout_ms))
        .headers(req_config.headers)
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

    let response_bytes = read_chunked_body_with_max(res, MAX_SIZE_GET_HEADER).await?;
    if !code.is_success() {
        return Err(PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        });
    };
    if code == StatusCode::NO_CONTENT {
        debug!(
            ?code,
            latency = ?request_latency,
            response = ?response_bytes,
            "no header from relay"
        );
        return Ok((start_request_time, None));
    }

    let get_header_response = match serde_json::from_slice::<GetHeaderResponse>(&response_bytes) {
        Ok(parsed) => parsed,
        Err(err) => {
            return Err(PbsError::JsonDecode {
                err,
                raw: String::from_utf8_lossy(&response_bytes).into_owned(),
            });
        }
    };

    debug!(
        latency = ?request_latency,
        value_eth = format_ether(get_header_response.value()),
        block_hash = %get_header_response.block_hash(),
        "received new header"
    );

    validate_header(
        &get_header_response.data,
        chain,
        relay.pubkey(),
        params.parent_hash,
        validation.skip_sigverify,
        validation.min_bid_wei,
        params.slot,
    )?;

    if validation.extra_validation_enabled {
        let parent_block = validation.parent_block.read();
        if let Some(parent_block) = parent_block.as_ref() {
            extra_validation(parent_block, &get_header_response.data)?;
        } else {
            warn!("parent block not found, skipping extra validation");
        }
    }

    Ok((start_request_time, Some(get_header_response)))
}

fn validate_header(
    signed_header: &SignedExecutionPayloadHeader,
    chain: Chain,
    expected_relay_pubkey: BlsPublicKey,
    parent_hash: B256,
    skip_sig_verify: bool,
    minimum_bid_wei: U256,
    slot: u64,
) -> Result<(), ValidationError> {
    let block_hash = signed_header.message.header.block_hash;
    let received_relay_pubkey = signed_header.message.pubkey;
    let tx_root = signed_header.message.header.transactions_root;
    let value = signed_header.message.value;

    if block_hash == B256::ZERO {
        return Err(ValidationError::EmptyBlockhash);
    }

    if parent_hash != signed_header.message.header.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            expected: parent_hash,
            got: signed_header.message.header.parent_hash,
        });
    }

    if tx_root == EMPTY_TX_ROOT_HASH {
        return Err(ValidationError::EmptyTxRoot);
    }

    if value < minimum_bid_wei {
        return Err(ValidationError::BidTooLow { min: minimum_bid_wei, got: value });
    }

    let expected_timestamp = timestamp_of_slot_start_sec(slot, chain);
    if expected_timestamp != signed_header.message.header.timestamp {
        return Err(ValidationError::TimestampMismatch {
            expected: expected_timestamp,
            got: signed_header.message.header.timestamp,
        });
    }

    if !skip_sig_verify {
        if expected_relay_pubkey != received_relay_pubkey {
            return Err(ValidationError::PubkeyMismatch {
                expected: expected_relay_pubkey,
                got: received_relay_pubkey,
            });
        }

        verify_signed_message(
            chain,
            &received_relay_pubkey,
            &signed_header.message,
            &signed_header.signature,
            APPLICATION_BUILDER_DOMAIN,
        )
        .map_err(ValidationError::Sigverify)?;
    }

    Ok(())
}

fn extra_validation(
    parent_block: &Block,
    signed_header: &SignedExecutionPayloadHeader,
) -> Result<(), ValidationError> {
    if signed_header.message.header.block_number != parent_block.header.number + 1 {
        return Err(ValidationError::BlockNumberMismatch {
            parent: parent_block.header.number,
            header: signed_header.message.header.block_number,
        });
    }

    if !check_gas_limit(signed_header.message.header.gas_limit, parent_block.header.gas_limit) {
        return Err(ValidationError::GasLimit {
            parent: parent_block.header.number,
            header: signed_header.message.header.block_number,
        });
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{B256, U256},
        rpc::types::beacon::BlsPublicKey,
    };
    use blst::min_pk;
    use cb_common::{
        pbs::{error::ValidationError, SignedExecutionPayloadHeader, EMPTY_TX_ROOT_HASH},
        signature::sign_builder_message,
        types::Chain,
        utils::timestamp_of_slot_start_sec,
    };

    use super::validate_header;

    #[test]
    fn test_validate_header() {
        let mut mock_header = SignedExecutionPayloadHeader::default();

        let slot = 5;
        let parent_hash = B256::from_slice(&[1; 32]);
        let chain = Chain::Holesky;
        let min_bid = U256::from(10);

        let secret_key = min_pk::SecretKey::from_bytes(&[
            0, 136, 227, 100, 165, 57, 106, 129, 181, 15, 235, 189, 200, 120, 70, 99, 251, 144,
            137, 181, 230, 124, 189, 193, 115, 153, 26, 0, 197, 135, 103, 63,
        ])
        .unwrap();
        let pubkey = BlsPublicKey::from_slice(&secret_key.sk_to_pk().to_bytes());

        mock_header.message.header.transactions_root = EMPTY_TX_ROOT_HASH;

        assert_eq!(
            validate_header(
                &mock_header,
                chain,
                BlsPublicKey::default(),
                parent_hash,
                false,
                min_bid,
                slot,
            ),
            Err(ValidationError::EmptyBlockhash)
        );

        mock_header.message.header.block_hash.0[1] = 1;

        assert_eq!(
            validate_header(
                &mock_header,
                chain,
                BlsPublicKey::default(),
                parent_hash,
                false,
                min_bid,
                slot,
            ),
            Err(ValidationError::ParentHashMismatch {
                expected: parent_hash,
                got: B256::default()
            })
        );

        mock_header.message.header.parent_hash = parent_hash;

        assert_eq!(
            validate_header(
                &mock_header,
                chain,
                BlsPublicKey::default(),
                parent_hash,
                false,
                min_bid,
                slot,
            ),
            Err(ValidationError::EmptyTxRoot)
        );

        mock_header.message.header.transactions_root = Default::default();

        assert_eq!(
            validate_header(
                &mock_header,
                chain,
                BlsPublicKey::default(),
                parent_hash,
                false,
                min_bid,
                slot,
            ),
            Err(ValidationError::BidTooLow { min: min_bid, got: U256::ZERO })
        );

        mock_header.message.value = U256::from(11);

        let expected = timestamp_of_slot_start_sec(slot, chain);
        assert_eq!(
            validate_header(&mock_header, chain, pubkey, parent_hash, false, min_bid, slot,),
            Err(ValidationError::TimestampMismatch { expected, got: 0 })
        );

        mock_header.message.header.timestamp = expected;
        mock_header.message.pubkey = pubkey;

        assert_eq!(
            validate_header(
                &mock_header,
                chain,
                BlsPublicKey::default(),
                parent_hash,
                false,
                min_bid,
                slot,
            ),
            Err(ValidationError::PubkeyMismatch { expected: BlsPublicKey::default(), got: pubkey })
        );

        assert!(matches!(
            validate_header(&mock_header, chain, pubkey, parent_hash, false, min_bid, slot),
            Err(ValidationError::Sigverify(_))
        ));
        assert!(
            validate_header(&mock_header, chain, pubkey, parent_hash, true, min_bid, slot).is_ok()
        );

        mock_header.signature = sign_builder_message(chain, &secret_key, &mock_header.message);

        assert!(
            validate_header(&mock_header, chain, pubkey, parent_hash, false, min_bid, slot).is_ok()
        );
    }
}
