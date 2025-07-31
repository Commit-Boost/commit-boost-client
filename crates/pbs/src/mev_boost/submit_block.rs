use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    pbs::{
        error::{PbsError, ValidationError},
        BlindedBeaconBlock, BlindedBeaconBlockElectra, BuilderApiVersion, PayloadAndBlobsElectra,
        RelayClient, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse, VersionedResponse,
        HEADER_START_TIME_UNIX_MS,
    },
    utils::{get_user_agent_with_version, read_chunked_body_with_max, utcnow_ms},
};
use futures::future::select_ok;
use reqwest::header::USER_AGENT;
use tracing::{debug, warn};
use url::Url;

use crate::{
    constants::{
        MAX_SIZE_SUBMIT_BLOCK_RESPONSE, SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG, TIMEOUT_ERROR_CODE_STR,
    },
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock and
/// https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlockV2. Use `api_version` to
/// distinguish between the two.
pub async fn submit_block<S: BuilderApiState>(
    signed_blinded_block: SignedBlindedBeaconBlock,
    req_headers: HeaderMap,
    state: PbsState<S>,
    api_version: &BuilderApiVersion,
) -> eyre::Result<SubmitBlindedBlockResponse> {
    // prepare headers
    let mut send_headers = HeaderMap::new();
    send_headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(utcnow_ms()));
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers)?);

    let relays = state.all_relays();
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(Box::pin(submit_block_with_timeout(
            &signed_blinded_block,
            relay,
            send_headers.clone(),
            state.pbs_config().timeout_get_payload_ms,
            api_version,
        )));
    }

    let results = select_ok(handles).await;
    match results {
        Ok((res, _)) => Ok(res),
        Err(err) => Err(err.into()),
    }
}

/// Submit blinded block to relay, retry connection errors until the
/// given timeout has passed
async fn submit_block_with_timeout(
    signed_blinded_block: &SignedBlindedBeaconBlock,
    relay: &RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
    api_version: &BuilderApiVersion,
) -> Result<SubmitBlindedBlockResponse, PbsError> {
    let url = relay.submit_block_url(api_version.clone())?;
    let mut remaining_timeout_ms = timeout_ms;
    let mut retry = 0;
    let mut backoff = Duration::from_millis(250);

    loop {
        let start_request = Instant::now();
        match send_submit_block(
            url.clone(),
            signed_blinded_block,
            relay,
            headers.clone(),
            remaining_timeout_ms,
            retry,
            *api_version == BuilderApiVersion::V1, // only validate unblinded block for v1
        )
        .await
        {
            Ok(response) => return Ok(response),

            Err(err) if err.should_retry() => {
                tokio::time::sleep(backoff).await;
                backoff += Duration::from_millis(250);

                remaining_timeout_ms =
                    timeout_ms.saturating_sub(start_request.elapsed().as_millis() as u64);

                if remaining_timeout_ms == 0 {
                    return Err(err);
                }
            }

            Err(err) => return Err(err),
        };

        retry += 1;
    }
}

// submits blinded signed block and expects the execution payload + blobs bundle
// back
async fn send_submit_block(
    url: Url,
    signed_blinded_block: &SignedBlindedBeaconBlock,
    relay: &RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
    retry: u32,
    validate_unblinded_block: bool,
) -> Result<SubmitBlindedBlockResponse, PbsError> {
    let start_request = Instant::now();
    let res = match relay
        .client
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers)
        .json(&signed_blinded_block)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            RELAY_STATUS_CODE
                .with_label_values(&[
                    TIMEOUT_ERROR_CODE_STR,
                    SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
                    &relay.id,
                ])
                .inc();
            return Err(err.into());
        }
    };
    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());

    let code = res.status();
    RELAY_STATUS_CODE
        .with_label_values(&[code.as_str(), SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG, &relay.id])
        .inc();

    let response_bytes = read_chunked_body_with_max(res, MAX_SIZE_SUBMIT_BLOCK_RESPONSE).await?;
    if !code.is_success() {
        let err = PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        };

        // we requested the payload from all relays, but some may have not received it
        warn!(relay_id = relay.id.as_ref(), retry, %err, "failed to get payload (this might be ok if other relays have it)");
        return Err(err);
    };

    let block_response = match serde_json::from_slice::<SubmitBlindedBlockResponse>(&response_bytes)
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return Err(PbsError::JsonDecode {
                err,
                raw: String::from_utf8_lossy(&response_bytes).into_owned(),
            });
        }
    };

    debug!(
        relay_id = relay.id.as_ref(),
        retry,
        latency = ?request_latency,
        version = block_response.version(),
        "received unblinded block"
    );

    if signed_blinded_block.block_hash() != block_response.block_hash() {
        return Err(PbsError::Validation(ValidationError::BlockHashMismatch {
            expected: signed_blinded_block.block_hash(),
            got: block_response.block_hash(),
        }));
    }

    // request has different type so cant be deserialized in the wrong version,
    // response has a "version" field
    if validate_unblinded_block {
        match (&signed_blinded_block.message, &block_response) {
            (
                BlindedBeaconBlock::Electra(signed_blinded_block),
                VersionedResponse::Electra(block_response),
            ) => validate_unblinded_block_electra(signed_blinded_block, block_response),
        }?;
    }

    Ok(block_response)
}

fn validate_unblinded_block_electra(
    signed_blinded_block: &BlindedBeaconBlockElectra,
    block_response: &PayloadAndBlobsElectra,
) -> Result<(), PbsError> {
    let blobs = &block_response.blobs_bundle;

    let expected_commitments = &signed_blinded_block.body.blob_kzg_commitments;
    if expected_commitments.len() != blobs.blobs.len() ||
        expected_commitments.len() != blobs.commitments.len() ||
        expected_commitments.len() != blobs.proofs.len()
    {
        return Err(PbsError::Validation(ValidationError::KzgCommitments {
            expected_blobs: expected_commitments.len(),
            got_blobs: blobs.blobs.len(),
            got_commitments: blobs.commitments.len(),
            got_proofs: blobs.proofs.len(),
        }));
    }

    for (i, comm) in expected_commitments.iter().enumerate() {
        // this is safe since we already know they are the same length
        if *comm != blobs.commitments[i] {
            return Err(PbsError::Validation(ValidationError::KzgMismatch {
                expected: format!("{comm}"),
                got: format!("{}", blobs.commitments[i]),
                index: i,
            }));
        }
    }

    Ok(())
}
