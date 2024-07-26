use std::{ops::Mul, sync::Arc, time::Duration};

use alloy::{
    primitives::{utils::format_ether, B256, U256},
    rpc::types::beacon::BlsPublicKey,
};
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    config::PbsConfig,
    pbs::{RelayEntry, HEADER_SLOT_UUID_KEY, HEADER_START_TIME_UNIX_MS},
    signature::verify_signed_builder_message,
    types::Chain,
    utils::{get_user_agent, utcnow_ms},
};
use futures::future::join_all;
use reqwest::{header::USER_AGENT, StatusCode};
use tracing::{debug, error};

use crate::{
    constants::GET_HEADER_ENDPOINT_TAG,
    error::{PbsError, ValidationError},
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
    types::{SignedExecutionPayloadHeader, EMPTY_TX_ROOT_HASH},
    GetHeaderParams, GetHeaderReponse,
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/getHeader
/// Returns 200 if at least one relay returns 200, else 204
pub async fn get_header<S: BuilderApiState>(
    params: GetHeaderParams,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<Option<GetHeaderReponse>> {
    let GetHeaderParams { slot, parent_hash, pubkey: validator_pubkey } = params;
    let (_, slot_uuid) = state.get_slot_and_uuid();

    // prepare headers
    let mut send_headers = HeaderMap::new();
    send_headers.insert(HEADER_SLOT_UUID_KEY, HeaderValue::from_str(&slot_uuid.to_string())?);
    send_headers
        .insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from_str(&utcnow_ms().to_string())?);
    if let Some(ua) = get_user_agent(&req_headers) {
        send_headers.insert(USER_AGENT, HeaderValue::from_str(&ua)?);
    }

    let relays = state.relays();
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(send_get_header(
            send_headers.clone(),
            slot,
            parent_hash,
            validator_pubkey,
            relay.clone(),
            state.config.chain,
            state.config.pbs_config.clone(),
            state.relay_client(),
        ));
    }

    let results = join_all(handles).await;
    let mut relay_bids = Vec::with_capacity(relays.len());
    for (i, res) in results.into_iter().enumerate() {
        let relay_id = relays[i].id.clone();

        match res {
            Ok(Some(res)) => relay_bids.push(res),
            Ok(_) => {}
            Err(err) => match err {
                PbsError::Reqwest(req_err) if req_err.is_timeout() => {
                    error!(err = "Timed Out", relay_id)
                }

                _ => error!(?err, relay_id),
            },
        }
    }

    Ok(state.add_bids(slot, relay_bids))
}

#[tracing::instrument(skip_all, name = "handler", fields(relay_id = relay.id))]
async fn send_get_header(
    headers: HeaderMap,
    slot: u64,
    parent_hash: B256,
    validator_pubkey: BlsPublicKey,
    relay: RelayEntry,
    chain: Chain,
    config: Arc<PbsConfig>,
    client: reqwest::Client,
) -> Result<Option<GetHeaderReponse>, PbsError> {
    let url = relay.get_header_url(slot, parent_hash, validator_pubkey);

    let timer =
        RELAY_LATENCY.with_label_values(&[GET_HEADER_ENDPOINT_TAG, &relay.id]).start_timer();
    let res = client
        .get(url)
        .timeout(Duration::from_millis(config.timeout_get_header_ms))
        .headers(headers)
        .send()
        .await?;
    let latency_ms = timer.stop_and_record().mul(1000.0).ceil() as u64;

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
            latency_ms,
            response = ?response_bytes,
            "no header from relay"
        );
        return Ok(None)
    }

    let get_header_response: GetHeaderReponse = serde_json::from_slice(&response_bytes)?;

    debug!(
        latency_ms,
        block_hash = %get_header_response.block_hash(),
        value_eth = format_ether(get_header_response.value()),
        "received new header"
    );

    validate_header(
        &get_header_response.data,
        chain,
        &relay,
        parent_hash,
        config.skip_sigverify,
        config.min_bid_wei,
    )?;

    Ok(Some(get_header_response))
}

fn validate_header(
    signed_header: &SignedExecutionPayloadHeader,
    chain: Chain,
    relay: &RelayEntry,
    parent_hash: B256,
    skip_sig_verify: bool,
    minimum_bid_wei: U256,
) -> Result<(), ValidationError> {
    let block_hash = signed_header.message.header.block_hash;
    let relay_pubkey = signed_header.message.pubkey;
    let tx_root = signed_header.message.header.transactions_root;
    let value = signed_header.message.value();

    if block_hash == B256::ZERO {
        return Err(ValidationError::EmptyBlockhash)
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

    if relay.pubkey != relay_pubkey {
        return Err(ValidationError::PubkeyMismatch { expected: relay.pubkey, got: relay_pubkey })
    }

    if !skip_sig_verify {
        verify_signed_builder_message(
            chain,
            &relay_pubkey,
            &signed_header.message,
            &signed_header.signature,
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
    use cb_common::{pbs::RelayEntry, signature::sign_builder_message, types::Chain};

    use super::validate_header;
    use crate::{
        error::ValidationError,
        types::{SignedExecutionPayloadHeader, EMPTY_TX_ROOT_HASH},
    };

    #[test]
    fn test_validate_header() {
        let mut mock_header = SignedExecutionPayloadHeader::default();
        let mut mock_relay = RelayEntry::default();
        let parent_hash = B256::from_slice(&[1; 32]);
        let chain = Chain::Holesky;
        let min_bid = U256::ZERO;

        mock_header.message.header.transactions_root =
            alloy::primitives::FixedBytes(EMPTY_TX_ROOT_HASH);

        assert_eq!(
            validate_header(&mock_header, chain, &mock_relay, parent_hash, false, min_bid),
            Err(ValidationError::EmptyBlockhash)
        );

        mock_header.message.header.block_hash.0[1] = 1;

        assert_eq!(
            validate_header(&mock_header, chain, &mock_relay, parent_hash, false, min_bid),
            Err(ValidationError::ParentHashMismatch {
                expected: parent_hash,
                got: B256::default()
            })
        );

        mock_header.message.header.parent_hash = parent_hash;

        assert_eq!(
            validate_header(&mock_header, chain, &mock_relay, parent_hash, false, min_bid),
            Err(ValidationError::EmptyTxRoot)
        );

        mock_header.message.header.transactions_root = Default::default();

        assert_eq!(
            validate_header(&mock_header, chain, &mock_relay, parent_hash, false, min_bid),
            Err(ValidationError::BidTooLow { min: min_bid, got: U256::ZERO })
        );

        mock_header.message.set_value(U256::from(1));

        let secret_key = min_pk::SecretKey::from_bytes(&[
            0, 136, 227, 100, 165, 57, 106, 129, 181, 15, 235, 189, 200, 120, 70, 99, 251, 144,
            137, 181, 230, 124, 189, 193, 115, 153, 26, 0, 197, 135, 103, 63,
        ])
        .unwrap();
        let pubkey = BlsPublicKey::from_slice(&secret_key.sk_to_pk().to_bytes());
        mock_header.message.pubkey = pubkey;

        assert_eq!(
            validate_header(&mock_header, chain, &mock_relay, parent_hash, false, min_bid),
            Err(ValidationError::PubkeyMismatch { expected: BlsPublicKey::default(), got: pubkey })
        );

        mock_relay.pubkey = pubkey;

        assert!(matches!(
            validate_header(&mock_header, chain, &mock_relay, parent_hash, false, min_bid),
            Err(ValidationError::Sigverify(_))
        ));
        assert!(
            validate_header(&mock_header, chain, &mock_relay, parent_hash, true, min_bid).is_ok()
        );

        mock_header.signature = sign_builder_message(chain, &secret_key, &mock_header.message);

        assert!(
            validate_header(&mock_header, chain, &mock_relay, parent_hash, false, min_bid).is_ok()
        )
    }
}
