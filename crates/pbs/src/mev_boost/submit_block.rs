use std::{ops::Mul, sync::Arc, time::Duration};

use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    config::PbsConfig,
    pbs::{RelayEntry, HEADER_SLOT_UUID_KEY, HEADER_START_TIME_UNIX_MS},
    utils::{get_user_agent, utcnow_ms},
};
use futures::future::select_ok;
use reqwest::header::USER_AGENT;
use tracing::{debug, warn};

use crate::{
    constants::SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
    error::{PbsError, ValidationError},
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
    types::{SignedBlindedBeaconBlock, SubmitBlindedBlockResponse},
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock
pub async fn submit_block<S: BuilderApiState>(
    signed_blinded_block: SignedBlindedBeaconBlock,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<SubmitBlindedBlockResponse> {
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
        handles.push(Box::pin(send_submit_block(
            send_headers.clone(),
            relay.clone(),
            &signed_blinded_block,
            state.config.pbs_config.clone(),
            state.relay_client(),
        )));
    }

    let results = select_ok(handles).await;
    match results {
        Ok((res, _)) => Ok(res),
        Err(err) => Err(err.into()),
    }
}

// submits blinded signed block and expects the execution payload + blobs bundle
// back
#[tracing::instrument(skip_all, name = "handler", fields(relay_id = relay.id))]
async fn send_submit_block(
    headers: HeaderMap,
    relay: RelayEntry,
    signed_blinded_block: &SignedBlindedBeaconBlock,
    config: Arc<PbsConfig>,
    client: reqwest::Client,
) -> Result<SubmitBlindedBlockResponse, PbsError> {
    let url = relay.submit_block_url();

    let timer = RELAY_LATENCY
        .with_label_values(&[SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG, &relay.id])
        .start_timer();
    let res = client
        .post(url)
        .timeout(Duration::from_millis(config.timeout_get_payload_ms))
        .headers(headers)
        .json(&signed_blinded_block)
        .send()
        .await?;
    let latency_ms = timer.stop_and_record().mul(1000.0).ceil() as u64;

    let code = res.status();
    RELAY_STATUS_CODE
        .with_label_values(&[code.as_str(), SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG, &relay.id])
        .inc();

    let response_bytes = res.bytes().await?;
    if !code.is_success() {
        let err = PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        };

        // we request payload to all relays, but some may have not received it
        warn!(?err, "failed to get payload (this might be ok if other relays have it)");
        return Err(err)
    };

    let block_response: SubmitBlindedBlockResponse = serde_json::from_slice(&response_bytes)?;

    debug!(
        latency_ms,
        block_hash = %block_response.block_hash(),
        "received unblinded block"
    );

    if signed_blinded_block.block_hash() != block_response.block_hash() {
        return Err(PbsError::Validation(ValidationError::BlockHashMismatch {
            expected: signed_blinded_block.block_hash(),
            got: block_response.block_hash(),
        }))
    }

    if let Some(blobs) = &block_response.data.blobs_bundle {
        let expected_committments = &signed_blinded_block.message.body.blob_kzg_commitments;
        if expected_committments.len() != blobs.blobs.len() ||
            expected_committments.len() != blobs.commitments.len() ||
            expected_committments.len() != blobs.proofs.len()
        {
            return Err(PbsError::Validation(ValidationError::KzgCommitments {
                expected_blobs: expected_committments.len(),
                got_blobs: blobs.blobs.len(),
                got_commitments: blobs.commitments.len(),
                got_proofs: blobs.proofs.len(),
            }))
        }

        for (i, comm) in expected_committments.iter().enumerate() {
            // this is safe since we already know they are the same length
            if *comm != blobs.commitments[i] {
                return Err(PbsError::Validation(ValidationError::KzgMismatch {
                    expected: format!("{comm}"),
                    got: format!("{}", blobs.commitments[i]),
                    index: i,
                }))
            }
        }
    }

    Ok(block_response)
}
