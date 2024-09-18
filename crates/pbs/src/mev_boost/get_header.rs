use std::time::{Duration, Instant};

use alloy::{
    primitives::{utils::format_ether, B256, U256},
    rpc::types::beacon::BlsPublicKey,
};
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    config::PbsConfig,
    constants::APPLICATION_BUILDER_DOMAIN,
    pbs::{
        error::{PbsError, ValidationError},
        GetHeaderParams, GetHeaderResponse, RelayClient, SignedExecutionPayloadHeader,
        EMPTY_TX_ROOT_HASH, HEADER_SLOT_UUID_KEY, HEADER_START_TIME_UNIX_MS,
    },
    signature::verify_signed_message,
    types::Chain,
    utils::{get_user_agent_with_version, ms_into_slot, utcnow_ms},
};
use futures::future::join_all;
use reqwest::{header::USER_AGENT, StatusCode};
use tokio::time::sleep;
use tracing::{debug, error, warn, Instrument};
use url::Url;

use crate::{
    constants::{GET_HEADER_ENDPOINT_TAG, TIMEOUT_ERROR_CODE, TIMEOUT_ERROR_CODE_STR},
    metrics::{RELAY_LAST_SLOT, RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/getHeader
/// Returns 200 if at least one relay returns 200, else 204
pub async fn get_header<S: BuilderApiState>(
    params: GetHeaderParams,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<Option<GetHeaderResponse>> {
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);
    let max_timeout_ms = state
        .pbs_config()
        .timeout_get_header_ms
        .min(state.pbs_config().late_in_slot_time_ms.saturating_sub(ms_into_slot));

    if max_timeout_ms == 0 {
        warn!(
            ms_into_slot,
            threshold = state.pbs_config().late_in_slot_time_ms,
            "late in slot, skipping relay requests"
        );

        return Ok(None);
    }

    let (_, slot_uuid) = state.get_slot_and_uuid();

    // prepare headers, except for start time which is set in `send_one_get_header`
    let mut send_headers = HeaderMap::new();
    send_headers.insert(HEADER_SLOT_UUID_KEY, HeaderValue::from_str(&slot_uuid.to_string())?);
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers)?);

    let relays = state.relays();
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(send_timed_get_header(
            params,
            relay.clone(),
            state.config.chain,
            state.pbs_config(),
            send_headers.clone(),
            ms_into_slot,
            max_timeout_ms,
        ));
    }

    let results = join_all(handles).await;
    let mut relay_bids = Vec::with_capacity(relays.len());
    for (i, res) in results.into_iter().enumerate() {
        let relay_id = relays[i].id.as_ref();

        match res {
            Ok(Some(res)) => {
                RELAY_LAST_SLOT.with_label_values(&[relay_id]).set(params.slot as i64);
                relay_bids.push(res)
            }
            Ok(_) => {}
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => error!(?err, relay_id),
        }
    }

    Ok(state.add_bids(params.slot, relay_bids))
}

#[tracing::instrument(skip_all, name = "handler", fields(relay_id = relay.id.as_ref()))]
async fn send_timed_get_header(
    params: GetHeaderParams,
    relay: RelayClient,
    chain: Chain,
    pbs_config: &PbsConfig,
    headers: HeaderMap,
    ms_into_slot: u64,
    mut timeout_left_ms: u64,
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
                        pbs_config.skip_sigverify,
                        pbs_config.min_bid_wei,
                        RequestConfig {
                            timeout_ms: timeout_left_ms,
                            url: url.clone(),
                            headers: headers.clone(),
                        },
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
                            n_headers += 1;
                            Some(maybe_header)
                        }
                        Err(err) if err.is_timeout() => None,
                        Err(err) => {
                            error!(?err, "TG: error sending header request");
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
        pbs_config.skip_sigverify,
        pbs_config.min_bid_wei,
        RequestConfig { timeout_ms: timeout_left_ms, url, headers },
    )
    .await
    .map(|(_, maybe_header)| maybe_header)
}

struct RequestConfig {
    url: Url,
    timeout_ms: u64,
    headers: HeaderMap,
}

async fn send_one_get_header(
    params: GetHeaderParams,
    relay: RelayClient,
    chain: Chain,
    skip_sigverify: bool,
    min_bid_wei: U256,
    mut req_config: RequestConfig,
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

    let response_bytes = res.bytes().await?;
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

    let get_header_response: GetHeaderResponse = serde_json::from_slice(&response_bytes)?;

    debug!(
        latency = ?request_latency,
        block_hash = %get_header_response.block_hash(),
        value_eth = format_ether(get_header_response.value()),
        "received new header"
    );

    validate_header(
        &get_header_response.data,
        chain,
        relay.pubkey(),
        params.parent_hash,
        skip_sigverify,
        min_bid_wei,
    )?;

    Ok((start_request_time, Some(get_header_response)))
}

fn validate_header(
    signed_header: &SignedExecutionPayloadHeader,
    chain: Chain,
    expected_relay_pubkey: BlsPublicKey,
    parent_hash: B256,
    skip_sig_verify: bool,
    minimum_bid_wei: U256,
) -> Result<(), ValidationError> {
    let block_hash = signed_header.message.header.block_hash;
    let received_relay_pubkey = signed_header.message.pubkey;
    let tx_root = signed_header.message.header.transactions_root;
    let value = signed_header.message.value();

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

    if value <= minimum_bid_wei {
        return Err(ValidationError::BidTooLow { min: minimum_bid_wei, got: value });
    }

    if expected_relay_pubkey != received_relay_pubkey {
        return Err(ValidationError::PubkeyMismatch {
            expected: expected_relay_pubkey,
            got: received_relay_pubkey,
        });
    }

    if !skip_sig_verify {
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
    };

    use super::validate_header;

    #[test]
    fn test_validate_header() {
        let mut mock_header = SignedExecutionPayloadHeader::default();

        let parent_hash = B256::from_slice(&[1; 32]);
        let chain = Chain::Holesky;
        let min_bid = U256::ZERO;

        let secret_key = min_pk::SecretKey::from_bytes(&[
            0, 136, 227, 100, 165, 57, 106, 129, 181, 15, 235, 189, 200, 120, 70, 99, 251, 144,
            137, 181, 230, 124, 189, 193, 115, 153, 26, 0, 197, 135, 103, 63,
        ])
        .unwrap();
        let pubkey = BlsPublicKey::from_slice(&secret_key.sk_to_pk().to_bytes());

        mock_header.message.header.transactions_root =
            alloy::primitives::FixedBytes(EMPTY_TX_ROOT_HASH);

        assert_eq!(
            validate_header(
                &mock_header,
                chain,
                BlsPublicKey::default(),
                parent_hash,
                false,
                min_bid
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
                min_bid
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
                min_bid
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
                min_bid
            ),
            Err(ValidationError::BidTooLow { min: min_bid, got: U256::ZERO })
        );

        mock_header.message.set_value(U256::from(1));

        mock_header.message.pubkey = pubkey;

        assert_eq!(
            validate_header(
                &mock_header,
                chain,
                BlsPublicKey::default(),
                parent_hash,
                false,
                min_bid
            ),
            Err(ValidationError::PubkeyMismatch { expected: BlsPublicKey::default(), got: pubkey })
        );

        assert!(matches!(
            validate_header(&mock_header, chain, pubkey, parent_hash, false, min_bid),
            Err(ValidationError::Sigverify(_))
        ));
        assert!(validate_header(&mock_header, chain, pubkey, parent_hash, true, min_bid).is_ok());

        mock_header.signature = sign_builder_message(chain, &secret_key, &mock_header.message);

        assert!(validate_header(&mock_header, chain, pubkey, parent_hash, false, min_bid).is_ok())
    }
}
