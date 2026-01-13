use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::{
    primitives::{B256, U256, utils::format_ether},
    providers::Provider,
    rpc::types::Block,
};
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    config::HeaderValidationMode,
    constants::APPLICATION_BUILDER_DOMAIN,
    pbs::{
        EMPTY_TX_ROOT_HASH, ExecutionPayloadHeaderRef, ForkName, ForkVersionDecode, GetHeaderInfo,
        GetHeaderParams, GetHeaderResponse, HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS,
        RelayClient, SignedBuilderBid,
        error::{PbsError, ValidationError},
    },
    signature::verify_signed_message,
    types::{BlsPublicKey, BlsPublicKeyBytes, BlsSignature, Chain},
    utils::{
        EncodingType, get_consensus_version_header, get_user_agent_with_version, ms_into_slot,
        read_chunked_body_with_max, timestamp_of_slot_start_sec, utcnow_ms,
    },
};
use futures::future::join_all;
use lh_types::{ContextDeserialize, ForkVersionedResponse};
use parking_lot::RwLock;
use reqwest::{
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
};
use ssz::Encode;
use tokio::time::sleep;
use tracing::{Instrument, debug, error, warn};
use tree_hash::TreeHash;
use url::Url;

use crate::{
    LightBuilderBidWrapper, LightHeaderResponse,
    constants::{
        GET_HEADER_ENDPOINT_TAG, MAX_SIZE_GET_HEADER_RESPONSE, TIMEOUT_ERROR_CODE,
        TIMEOUT_ERROR_CODE_STR,
    },
    metrics::{RELAY_HEADER_VALUE, RELAY_LAST_SLOT, RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
    utils::check_gas_limit,
};

/// Info about an incoming get_header request.
/// Sent from get_header to each send_timed_get_header call.
#[derive(Clone)]
struct RequestInfo {
    /// The blockchain parameters of the get_header request (what slot it's for,
    /// which pubkey is requesting it, etc)
    params: GetHeaderParams,

    /// Common baseline of headers to send with each request
    headers: Arc<HeaderMap>,

    /// The chain the request is for
    chain: Chain,

    /// Context for validating the header returned by the relay
    validation: ValidationContext,
}

// Context for validating the header
#[derive(Clone)]
struct ValidationContext {
    // Whether to skip signature verification
    skip_sigverify: bool,

    // Minimum acceptable bid, in wei
    min_bid_wei: U256,

    // Whether extra validation of the parent block is enabled
    extra_validation_enabled: bool,

    // The parent block, if fetched
    parent_block: Arc<RwLock<Option<Block>>>,
}

/// Implements https://ethereum.github.io/builder-specs/#/Builder/getHeader
/// Returns 200 if at least one relay returns 200, else 204
pub async fn get_header<S: BuilderApiState>(
    params: GetHeaderParams,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<Option<GetHeaderResponse>> {
    let parent_block = Arc::new(RwLock::new(None));
    let extra_validation_enabled =
        state.config.pbs_config.header_validation_mode == HeaderValidationMode::Extra;
    if extra_validation_enabled && let Some(rpc_url) = state.pbs_config().rpc_url.clone() {
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

    // Create the Accept headers for requests since the module handles both SSZ and
    // JSON
    let accept_types =
        [EncodingType::Ssz.content_type(), EncodingType::Json.content_type()].join(",");
    send_headers.insert(ACCEPT, HeaderValue::from_str(&accept_types).unwrap());

    // Send requests to all relays concurrently
    let slot = params.slot as i64;
    let request_info = Arc::new(RequestInfo {
        params,
        headers: Arc::new(send_headers),
        chain: state.config.chain,
        validation: ValidationContext {
            skip_sigverify: state.pbs_config().skip_sigverify,
            min_bid_wei: state.pbs_config().min_bid_wei,
            extra_validation_enabled,
            parent_block,
        },
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
                RELAY_LAST_SLOT.with_label_values(&[relay_id]).set(slot);
                let value_gwei = (res.data.message.value() / U256::from(1_000_000_000))
                    .try_into()
                    .unwrap_or_default();
                RELAY_HEADER_VALUE.with_label_values(&[relay_id]).set(value_gwei);

                relay_bids.push(res)
            }
            Ok(_) => {}
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => error!(%err, relay_id),
        }
    }

    let max_bid = relay_bids.into_iter().max_by_key(|bid| *bid.value());

    Ok(max_bid)
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

async fn send_timed_get_header(
    request_info: Arc<RequestInfo>,
    relay: RelayClient,
    ms_into_slot: u64,
    mut timeout_left_ms: u64,
) -> Result<Option<GetHeaderResponse>, PbsError> {
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
) -> Result<(u64, Option<GetHeaderResponse>), PbsError> {
    // Send the header request
    let (start_request_time, get_header_response) = send_get_header_impl(
        &relay,
        url,
        timeout_left_ms,
        (*request_info.headers).clone(), /* Create a copy of the HeaderMap because the impl will
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
    if validation.extra_validation_enabled {
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

    Ok((start_request_time, Some(get_header_response)))
}

/// Sends a get_header request to a relay, returning the response, the time the
/// request was started, and the encoding type of the response (if any).
/// Used by send_one_get_header to perform the actual request submission.
async fn send_get_header_impl(
    relay: &RelayClient,
    url: Arc<Url>,
    timeout_left_ms: u64,
    mut headers: HeaderMap,
) -> Result<(u64, Option<GetHeaderResponse>), PbsError> {
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
            RELAY_STATUS_CODE
                .with_label_values(&[TIMEOUT_ERROR_CODE_STR, GET_HEADER_ENDPOINT_TAG, &relay.id])
                .inc();
            return Err(err.into());
        }
    };

    // Log the response code and latency
    let code = res.status();
    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[GET_HEADER_ENDPOINT_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());
    RELAY_STATUS_CODE.with_label_values(&[code.as_str(), GET_HEADER_ENDPOINT_TAG, &relay.id]).inc();

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
    let get_header_response = match content_type {
        EncodingType::Json => decode_json_payload::<SignedBuilderBid>(&response_bytes)?,
        EncodingType::Ssz => {
            let fork = fork.ok_or(PbsError::RelayResponse {
                error_msg: "relay did not provide consensus version header for ssz payload"
                    .to_string(),
                code: code.as_u16(),
            })?;
            decode_ssz_payload(&response_bytes, fork)?
        }
    };

    // Log and return
    debug!(
        relay_id = relay.id.as_ref(),
        header_size_bytes = response_bytes.len(),
        latency = ?request_latency,
        version =? get_header_response.version,
        value_eth = format_ether(*get_header_response.value()),
        block_hash = %get_header_response.block_hash(),
        content_type = ?content_type,
        "received new header"
    );
    Ok((start_request_time, Some(get_header_response)))
}

/// Decode a JSON-encoded get_header response
fn decode_json_payload<'de, T>(
    response_bytes: &'de [u8],
) -> Result<ForkVersionedResponse<T>, PbsError>
where
    T: ContextDeserialize<'de, ForkName>,
{
    match serde_json::from_slice::<ForkVersionedResponse<T>>(response_bytes) {
        Ok(parsed) => Ok(parsed),
        Err(err) => Err(PbsError::JsonDecode {
            err,
            raw: String::from_utf8_lossy(response_bytes).into_owned(),
        }),
    }
}

/// Decode a JSON-encoded get_header response
fn decode_json_payload_orig(response_bytes: &[u8]) -> Result<GetHeaderResponse, PbsError> {
    match serde_json::from_slice::<GetHeaderResponse>(response_bytes) {
        Ok(parsed) => Ok(parsed),
        Err(err) => Err(PbsError::JsonDecode {
            err,
            raw: String::from_utf8_lossy(response_bytes).into_owned(),
        }),
    }
}

/// Decode an SSZ-encoded get_header response
fn decode_ssz_payload(
    response_bytes: &[u8],
    fork: ForkName,
) -> Result<GetHeaderResponse, PbsError> {
    let data = SignedBuilderBid::from_ssz_bytes_by_fork(response_bytes, fork).map_err(|e| {
        PbsError::RelayResponse {
            error_msg: (format!("error decoding relay payload: {e:?}")).to_string(),
            code: 200,
        }
    })?;
    /*
    ///

        let header_size = match fork {
            ForkName::Bellatrix => {
                let header = ExecutionPayloadHeaderBellatrix::default();


                ExecutionPayloadHeaderBellatrix::ssz_bytes_len(&self)
            }
        }

            let mut builder = ssz::SszDecoderBuilder::new(bytes);

            builder.register_type()

            builder.register_anonymous_variable_length_item()?;
            builder.register_type::<Signature>()?;

            let mut decoder = builder.build()?;
            let message = decoder
                .decode_next_with(|bytes| BuilderBid::from_ssz_bytes_by_fork(bytes, fork_name))?;
            let signature = decoder.decode_next()?;

            Ok(Self { message, signature })


    ///
    */

    Ok(GetHeaderResponse { version: fork, data, metadata: Default::default() })
}

struct HeaderData {
    block_hash: B256,
    parent_hash: B256,
    tx_root: B256,
    value: U256,
    timestamp: u64,
}

fn validate_header_data(
    header_data: &HeaderData,
    chain: Chain,
    expected_parent_hash: B256,
    minimum_bid_wei: U256,
    slot: u64,
) -> Result<(), ValidationError> {
    if header_data.block_hash == B256::ZERO {
        return Err(ValidationError::EmptyBlockhash);
    }

    if expected_parent_hash != header_data.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            expected: expected_parent_hash,
            got: header_data.parent_hash,
        });
    }

    if header_data.tx_root == EMPTY_TX_ROOT_HASH {
        return Err(ValidationError::EmptyTxRoot);
    }

    if header_data.value < minimum_bid_wei {
        return Err(ValidationError::BidTooLow { min: minimum_bid_wei, got: header_data.value });
    }

    let expected_timestamp = timestamp_of_slot_start_sec(slot, chain);
    if expected_timestamp != header_data.timestamp {
        return Err(ValidationError::TimestampMismatch {
            expected: expected_timestamp,
            got: header_data.timestamp,
        });
    }

    Ok(())
}

fn validate_signature<T: TreeHash>(
    chain: Chain,
    expected_relay_pubkey: &BlsPublicKey,
    received_relay_pubkey: &BlsPublicKeyBytes,
    message: &T,
    signature: &BlsSignature,
) -> Result<(), ValidationError> {
    if expected_relay_pubkey.serialize() != received_relay_pubkey.as_serialized() {
        return Err(ValidationError::PubkeyMismatch {
            expected: BlsPublicKeyBytes::from(expected_relay_pubkey),
            got: *received_relay_pubkey,
        });
    }

    if !verify_signed_message(
        chain,
        expected_relay_pubkey,
        &message,
        signature,
        APPLICATION_BUILDER_DOMAIN,
    ) {
        return Err(ValidationError::Sigverify);
    }

    Ok(())
}

fn extra_validation(
    parent_block: &Block,
    signed_header: &GetHeaderResponse,
) -> Result<(), ValidationError> {
    if signed_header.block_number() != parent_block.header.number + 1 {
        return Err(ValidationError::BlockNumberMismatch {
            parent: parent_block.header.number,
            header: signed_header.block_number(),
        });
    }

    if !check_gas_limit(signed_header.gas_limit(), parent_block.header.gas_limit) {
        return Err(ValidationError::GasLimit {
            parent: parent_block.header.gas_limit,
            header: signed_header.gas_limit(),
        });
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{B256, U256};
    use cb_common::{
        pbs::*,
        signature::sign_builder_message,
        types::{BlsSecretKey, Chain},
        utils::{TestRandomSeed, timestamp_of_slot_start_sec},
    };
    use lh_types::{MainnetEthSpec, Signature};
    use serde::de::value;
    use serde_utils::hex;
    use ssz::BYTES_PER_LENGTH_OFFSET;

    use super::{validate_header_data, *};

    #[test]
    fn test_validate_header() {
        let slot = 5;
        let parent_hash = B256::from_slice(&[1; 32]);
        let chain = Chain::Holesky;
        let min_bid = U256::from(10);

        let mut mock_header_data = HeaderData {
            block_hash: B256::default(),
            parent_hash: B256::default(),
            tx_root: EMPTY_TX_ROOT_HASH,
            value: U256::default(),
            timestamp: 0,
        };

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::EmptyBlockhash)
        );

        mock_header_data.block_hash.0[1] = 1;

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::ParentHashMismatch {
                expected: parent_hash,
                got: B256::default()
            })
        );

        mock_header_data.parent_hash = parent_hash;

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::EmptyTxRoot)
        );

        mock_header_data.tx_root = Default::default();

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::BidTooLow { min: min_bid, got: U256::ZERO })
        );

        mock_header_data.value = U256::from(11);

        let expected = timestamp_of_slot_start_sec(slot, chain);
        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::TimestampMismatch { expected, got: 0 })
        );

        mock_header_data.timestamp = expected;

        assert!(validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot).is_ok());
    }

    #[test]
    fn test_validate_signature() {
        let secret_key = BlsSecretKey::test_random();
        let pubkey = secret_key.public_key();
        let wrong_pubkey = BlsPublicKeyBytes::test_random();
        let wrong_signature = BlsSignature::test_random();

        let message = B256::random();

        let signature = sign_builder_message(Chain::Holesky, &secret_key, &message);

        assert_eq!(
            validate_signature(Chain::Holesky, &pubkey, &wrong_pubkey, &message, &wrong_signature),
            Err(ValidationError::PubkeyMismatch {
                expected: BlsPublicKeyBytes::from(&pubkey),
                got: wrong_pubkey
            })
        );

        assert!(matches!(
            validate_signature(
                Chain::Holesky,
                &pubkey,
                &BlsPublicKeyBytes::from(&pubkey),
                &message,
                &wrong_signature
            ),
            Err(ValidationError::Sigverify)
        ));

        assert!(
            validate_signature(
                Chain::Holesky,
                &pubkey,
                &BlsPublicKeyBytes::from(&pubkey),
                &message,
                &signature
            )
            .is_ok()
        );
    }

    #[test]
    fn test_ssz_sandbox() {
        // Load the Fulu get_header JSON from test data
        let json_bytes = include_bytes!("../../../../tests/data/get_header/fulu.json");
        let decoded = decode_json_payload_orig(json_bytes).expect("failed to decode fulu JSON");

        // Encode as SSZ
        let encoded = decoded.data.as_ssz_bytes();

        // Extract the bid value from the SSZ
        let bid_value = get_bid_value_from_ssz(&encoded, ForkName::Fulu)
            .expect("failed to extract bid value from SSZ");

        // Compare to the original value
        println!("Original value: {}", decoded.value());
        println!("Extracted value: {}", bid_value);
        assert_eq!(*decoded.value(), bid_value);

        // Print the encoded data in a hex string
        //println!("Encoded SSZ: {}", hex::encode(encoded));
    }

    fn get_bid_value_from_ssz(response_bytes: &[u8], fork: ForkName) -> Result<U256, PbsError> {
        let message_offset = match fork {
            ForkName::Bellatrix => get_message_offset::<BuilderBidBellatrix>(),
            ForkName::Capella => get_message_offset::<BuilderBidCapella>(),
            ForkName::Deneb => get_message_offset::<BuilderBidDeneb>(),
            ForkName::Electra => get_message_offset::<BuilderBidElectra>(),
            ForkName::Fulu => get_message_offset::<BuilderBidFulu>(),
            ForkName::Gloas => get_message_offset::<BuilderBidGloas>(),
            _ => {
                return Err(PbsError::Validation(ValidationError::UnsupportedFork));
            }
        };

        // The offset for the start of the `value` field in the SignedBuilderBid's SSZ
        // data. Determined by the structure of the SSZ data, which comes from
        // the fork choice.
        let value_offset_in_message = match fork {
            ForkName::Bellatrix => {
                // Message goes header -> value -> pubkey
                get_length_of_field::<ExecutionPayloadHeaderBellatrix>()
            }

            ForkName::Capella => {
                // Message goes header -> value -> pubkey
                get_length_of_field::<ExecutionPayloadHeaderCapella>()
            }

            ForkName::Deneb => {
                // Message goes header -> blob_kzg_commitments -> value -> pubkey
                let mut offset = 0;
                offset += get_length_of_field::<ExecutionPayloadHeaderDeneb>();
                offset += get_length_of_field::<KzgCommitments>();
                offset
            }

            ForkName::Electra => {
                // Message goes header -> blob_kzg_commitments -> execution_requests -> value ->
                // pubkey
                let mut offset = 0;
                offset += get_length_of_field::<ExecutionPayloadHeaderElectra>();
                offset += get_length_of_field::<KzgCommitments>();
                offset += get_length_of_field::<ExecutionRequests>();
                offset
            }

            ForkName::Fulu => {
                // Message goes header -> blob_kzg_commitments -> execution_requests -> value ->
                // pubkey
                let mut offset = 0;
                offset += get_length_of_field::<ExecutionPayloadHeaderFulu>();
                offset += get_length_of_field::<KzgCommitments>();
                offset += get_length_of_field::<ExecutionRequests>();
                offset
            }

            ForkName::Gloas => {
                // Message goes header -> blob_kzg_commitments -> execution_requests -> value ->
                // pubkey
                let mut offset = 0;
                offset += get_length_of_field::<ExecutionPayloadHeaderGloas>();
                offset += get_length_of_field::<KzgCommitments>();
                offset += get_length_of_field::<ExecutionRequests>();
                offset
            }
            _ => {
                return Err(PbsError::Validation(ValidationError::UnsupportedFork));
            }
        };

        // Get the offset of the value in the full response bytes
        let value_offset = message_offset + value_offset_in_message;

        // Sanity check the response length so we don't panic trying to slice it
        let end_offset = value_offset + U256::ssz_fixed_len();
        if response_bytes.len() < end_offset - 1 {
            return Err(PbsError::RelayResponse {
                error_msg: format!(
                    "response bytes too short to extract value: expected at least {} bytes, got {} bytes",
                    end_offset,
                    response_bytes.len()
                ),
                code: 200,
            });
        }

        // Extract the value bytes and convert to U256
        let value_bytes = &response_bytes[value_offset..value_offset + U256::ssz_fixed_len()];
        let value = U256::from_le_slice(value_bytes);
        Ok(value)
    }

    // Get the offset where the `message` field starts in some SignedBuilderBid SSZ
    // data. Requires that SignedBuilderBid always has the following structure:
    // message -> signature
    // where `message` is a BuilderBid type determined by the fork choice, and
    // `signature` is a fixed-length Signature type.
    fn get_message_offset<BuilderBidType>() -> usize
    where
        BuilderBidType: ssz::Encode,
    {
        // Since `message` is the first field, its offset is always 0
        let mut offset = 0;

        // If it's variable length, then it will be represented by a pointer to
        // the actual data, so we need to get the location of where that data starts
        if !BuilderBidType::is_ssz_fixed_len() {
            offset += BYTES_PER_LENGTH_OFFSET + Signature::ssz_fixed_len();
        }

        offset
    }

    // Get the length of some field type in SSZ encoding, accounting for whether
    // it's fixed or variable length. Needed to know how many bytes to skip when
    // skipping that field.
    fn get_length_of_field<FieldType>() -> usize
    where
        FieldType: ssz::Encode,
    {
        if FieldType::is_ssz_fixed_len() {
            // If it's fixed length, the field will be represented directly in-place as
            // binary; return the fixed length
            return FieldType::ssz_fixed_len();
        }
        // If it's variable length, the field will actually be a pointer to some
        // location where the actual data is stored; return the size of that
        // pointer
        BYTES_PER_LENGTH_OFFSET
    }
}

/*
64000000 // 100 (ptr to the byte offset where MESSAGE starts), 4 bytes
a9f158bca1d9d6b93a9104f48bd2d1e7689bef3fc974651fc755cc6f50d3649c5153a342a12f95cd8f9cac4f90144985189f498a7e0e1cb202ed5e7c98f3f504f371a53b9293bdd973fbb019c91242f808072d0ffcd9d17e2404baea3190fd18 // Signature, 96 bytes)

// Message (100 relative to start of buffer)
5c000000 // 92, ptr to the byte offset (relative to this) where HEADER starts, 4 bytes
be020000 // 702, ptr to the byte offset (relative to this) where BLOB_KZG_COMMITMENTS starts, 4 bytes
de030000 // 990, ptr to the byte offset (relative to this) where EXECUTION_REQUESTS starts, 4 bytes
d202964900000000000000000000000000000000000000000000000000000000 // Value, uint256, 32 bytes
883827193f7627cd04e621e1e8d56498362a52b2a30c9a1c72036eb935c4278dee23d38a24d2f7dda62689886f0c39f4 // Pubkey, 48 bytes

// Message -> Header (92 relative to start of Message)
114d1897fefa402a01a653c21a7f1f1db049d1373a5e73a2d25d7a8045dc02a1 // parent_hash, 32 bytes
477cc10a5b54aed5c88544c2e71ea0581cf64593 // fee_recipient, 20 bytes
6724be16ef8e65681cb66f9c144da67347b8983aa5e3f4662c9b5dba90ab5bc6 // state_root, 32 bytes
f2f6d2fe6960e4dedad18cca0c7881e6509d551d3e04c1879a627fb8aba30272 // receipts_root, 32 bytes
00000400000000000000848008100000000000000000000004000000010080000000000100000400000000000000000000000000020100000000000000000000080004000000000800008008000000000000000020004000000400000000000000000000000400000000000000000000000000000010000002000010000000000000000000800000200100000000000000004000000000200002000004000000000800000000000000000000000000008000000000000000800000008000000400012002000000000000000000000000000200000000000000000000000000040000000000000000000000000000000000408000000000040000000000000000 // logs_bloom: FixedVector, BYTES_PER_LOGS_BLOOM (256 bytes for mainnet, comes from Beacon config spec)
0fde820be6404bcb71d7bbeee140c16cd28b1940a40fa8a4e2c493114a08b38a // prev_randao, 32 bytes
5262180000000000 // block_number, little-endian 8 bytes
80c3c90100000000 // gas_limit, LE 8 bytes
c4981d0000000000 // gas_used, LE 8 bytes
2c6f4f6600000000 // timestamp, LE 8 bytes
48020000 // 584, PTR to where extra_data starts, 4 bytes
f3807e4b00000000000000000000000000000000000000000000000000000000 // base_fee_per_gas (u256), 32 bytes
0d9eccac62175d903e4242783d7252f4ab6cdd35995810646bda627b4c35adac // block_hash, 32 bytes
9dca93e8c6c9a1b5fcc850990ed95cd44af96ff0a6094c87b119a34259eb64b0 // transactions_root, 32 bytes
2daccf0e476ca3e2644afbd13b2621d55b4d515b813a3b867cdacea24bb352d1 // withdrawals_root, 32 bytes
00000c0000000000 // blob_gas_used, LE 8 bytes
0000ac0500000000 // excess_blob_gas, LE 8 bytes

// Message -> Header -> Extra Data: VariableList<u8> (584 relative to start of header)
d983010d0c846765746889676f312e32312e3130856c696e7578 // extra_data, MAX_EXTRA_DATA_BYTES (32 bytes for Mainnet, comes from Beacon config spec), so padding is cut off and not included cause it's not a fixed size. It must know that based on the offsets. Size of this is 26 bytes.

// Message -> Blob KZG Commitments: VariableList<KzgCommitment> (702 relative to start of Message)
9559cce9cd71a3416793c8e28d3aaaae9f53732180f57e046bf725c74ab348a7b16693fd03194cac9dd2199a526461b7 // BYTES_PER_COMMITMENT, 48 bytes
abc493f754d156c7156eb8365d28eee13e5b3413767356ce4cb30cb0306fbe0ed45eaba92936a94e81ed976aa0d787c2 // ""
a5d87332b5dd391ed3153fe36dbd67775dcbc1818cbf6a68d2089a5c6015de1de02e5138f039f2375e6b3511cc94764b // ""
a49c576627561ec9ae1ef7494e7cee7ede7fa7695d4462436c3e549cc3ce78674b407e8b5f8903b80f77a68814642d6c // ""
83155fbeb04758d267193800fb89fa30eb13ac0e217005ae7e271733205ca8a6cd80fba08bf5c9a4a5cc0c9d463ac633 // ""
a20c71d1985996098aa63e8b5dc7b7fedb70de31478fe309dad3ac0e9b6d28d82be8e5e543021a0203dc785742e94b2f // ""

// Message -> Execution Requests: vanilla struct (990 relative to start of Message)
0c000000 // 12, ptr to deposits (relative)
cc000000 // 204, ptr to withdrawals (relative)
18010000 // 280, ptr to consolidations (relative)

// Message -> Execution Requests -> Deposits: VariableList<DepositRequest> (12 relative to start of Execution Requests)
ac0a230bd98a766b8e4156f0626ee679dd280dee5b0eedc2b9455ca3dacc4c7618da5010b9db609450a712f095c9f7a50f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f64000000000000008aeb4642fb2982039a43fd6a6d9cc0ebf7598dbf02343c4617d9a68d799393c162492add63f31099a25eacc2782ba27a190e977a8c58760b6636dccb503d528b3be9e885c93d5b79699e68fcca870b0c790cdb00d67604d8b4a3025ae75efa2f01000000000000001100000000000000000000000000000000000000ac0a230bd98a766b8e4156f0626ee679dd280dee5b0eedc2b9455ca3dacc4c7618da5010b9db609450a712f095c9f7a501000000000000001200000000000000000000000000000000000000ac0a230bd98a766b8e4156f0626ee679dd280dee5b0eedc2b9455ca3dacc4c7618da5010b9db609450a712f095c9f7a5ac0a230bd98a766b8e4156f0626ee679dd280dee5b0eedc2b9455ca3dacc4c7618da5010b9db609450a712f095c9f7a5

// Message -> Execution Requests -> Withdrawals: VariableList<WithdrawalRequest> (X relative to start of Execution Requests)

// Message -> Execution Requests -> Consolidations: VariableList<ConsolidationRequest> (X relative to start of Execution Requests)
*/
