use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::http::HeaderMap;
use cb_common::{
    config::BlockValidationMode,
    pbs::{
        BlindedBeaconBlock, BuilderApiVersion, ForkName, RelayClient, SignedBlindedBeaconBlock,
        SubmitBlindedBlockResponse,
        error::{PbsError, ValidationError},
    },
    utils::{
        CONSENSUS_VERSION_HEADER, EncodingType, get_consensus_version_header,
        read_chunked_body_with_max,
    },
};
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::Encode;
use tracing::{debug, warn};
use url::Url;

use super::validation::{
    decode_json_payload, decode_ssz_payload, get_light_info_from_json, validate_unblinded_block,
};
use crate::{
    CompoundSubmitBlockResponse, LightSubmitBlockResponse, TIMEOUT_ERROR_CODE_STR,
    constants::{MAX_SIZE_SUBMIT_BLOCK_RESPONSE, SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG},
    metrics::RELAY_STATUS_CODE,
};

/// Info about a proposal submission request.
/// Sent from submit_block to the submit_block_with_timeout function.
#[derive(Clone)]
pub struct ProposalInfo {
    /// The signed blinded block to submit
    pub signed_blinded_block: Arc<SignedBlindedBeaconBlock>,

    /// Common baseline of headers to send with each request
    pub headers: Arc<HeaderMap>,

    /// The version of the submit_block route being used
    pub api_version: BuilderApiVersion,

    /// How to validate the block returned by the relay
    pub validation_mode: BlockValidationMode,

    /// The accepted encoding types from the original request
    pub accepted_types: HashSet<EncodingType>,
}

/// Used internally to provide info and context about a submit_block request and
/// its response
pub struct SubmitBlockResponseInfo {
    /// The raw body of the response
    pub response_bytes: Vec<u8>,

    /// The content type the response is encoded with
    pub content_type: EncodingType,

    /// Which fork the response bid is for (if provided as a header, rather than
    /// part of the body)
    pub fork: Option<ForkName>,

    /// The status code of the response, for logging
    pub code: StatusCode,

    /// The round-trip latency of the request
    pub request_latency: Duration,
}

/// Submit blinded block to relay, retry connection errors until the
/// given timeout has passed
pub async fn submit_block_with_timeout(
    proposal_info: Arc<ProposalInfo>,
    relay: RelayClient,
    timeout_ms: u64,
) -> Result<CompoundSubmitBlockResponse, PbsError> {
    let mut url = Arc::new(relay.submit_block_url(proposal_info.api_version)?);
    let mut remaining_timeout_ms = timeout_ms;
    let mut retry = 0;
    let mut backoff = Duration::from_millis(250);
    let mut request_api_version = proposal_info.api_version;

    loop {
        let start_request = Instant::now();
        match send_submit_block(
            proposal_info.clone(),
            url.clone(),
            &relay,
            remaining_timeout_ms,
            retry,
            request_api_version,
        )
        .await
        {
            Ok(response) => {
                // If the original request was for v2 but we had to fall back to v1, return a v2
                // response
                if request_api_version == BuilderApiVersion::V1 &&
                    proposal_info.api_version != request_api_version
                {
                    return Ok(CompoundSubmitBlockResponse::EmptyBody);
                }
                return Ok(response);
            }

            Err(err) if err.should_retry() => {
                tokio::time::sleep(backoff).await;
                backoff += Duration::from_millis(250);

                remaining_timeout_ms =
                    timeout_ms.saturating_sub(start_request.elapsed().as_millis() as u64);

                if remaining_timeout_ms == 0 {
                    return Err(err);
                }
            }

            Err(err)
                if err.is_not_found() && matches!(request_api_version, BuilderApiVersion::V2) =>
            {
                warn!(
                    relay_id = relay.id.as_ref(),
                    "relay does not support v2 endpoint, retrying with v1"
                );
                url = Arc::new(relay.submit_block_url(BuilderApiVersion::V1)?);
                request_api_version = BuilderApiVersion::V1;
            }

            Err(err) => return Err(err),
        };

        retry += 1;
    }
}

// submits blinded signed block and expects the execution payload + blobs bundle
// back
#[allow(clippy::too_many_arguments)]
async fn send_submit_block(
    proposal_info: Arc<ProposalInfo>,
    url: Arc<Url>,
    relay: &RelayClient,
    timeout_ms: u64,
    retry: u32,
    api_version: BuilderApiVersion,
) -> Result<CompoundSubmitBlockResponse, PbsError> {
    match proposal_info.validation_mode {
        BlockValidationMode::None => {
            // No validation so do some light processing and forward the response directly
            let response =
                send_submit_block_light(proposal_info.clone(), url, relay, timeout_ms, retry)
                    .await?;
            match response {
                None => Ok(CompoundSubmitBlockResponse::EmptyBody),
                Some(res) => {
                    // Make sure the response is encoded in one of the accepted
                    // types since we're passing the raw response directly to the client
                    if !proposal_info.accepted_types.contains(&res.encoding_type) {
                        return Err(PbsError::RelayResponse {
                            error_msg: format!(
                                "relay returned unsupported encoding type for submit_block in no-validation mode: {:?}",
                                res.encoding_type
                            ),
                            code: 406, // Not Acceptable
                        });
                    }
                    Ok(CompoundSubmitBlockResponse::Light(res))
                }
            }
        }
        _ => {
            // Full processing: decode full response and validate
            let response = send_submit_block_full(
                proposal_info.clone(),
                url,
                relay,
                timeout_ms,
                retry,
                api_version,
            )
            .await?;
            let response = match response {
                None => {
                    // v2 request with no body
                    return Ok(CompoundSubmitBlockResponse::EmptyBody);
                }
                Some(res) => res,
            };
            // Extract the info needed for validation
            let got_block_hash = response.data.execution_payload.block_hash().0;

            // request has different type so cant be deserialized in the wrong version,
            // response has a "version" field
            match &proposal_info.signed_blinded_block.message() {
                BlindedBeaconBlock::Electra(blinded_block) => {
                    let expected_block_hash =
                        blinded_block.body.execution_payload.execution_payload_header.block_hash.0;
                    let expected_commitments = &blinded_block.body.blob_kzg_commitments;

                    validate_unblinded_block(
                        expected_block_hash,
                        got_block_hash,
                        expected_commitments,
                        &response.data.blobs_bundle,
                        response.version,
                    )
                }

                BlindedBeaconBlock::Fulu(blinded_block) => {
                    let expected_block_hash =
                        blinded_block.body.execution_payload.execution_payload_header.block_hash.0;
                    let expected_commitments = &blinded_block.body.blob_kzg_commitments;

                    validate_unblinded_block(
                        expected_block_hash,
                        got_block_hash,
                        expected_commitments,
                        &response.data.blobs_bundle,
                        response.version,
                    )
                }

                _ => return Err(PbsError::Validation(ValidationError::UnsupportedFork)),
            }?;
            Ok(CompoundSubmitBlockResponse::Full(Box::new(response)))
        }
    }
}

/// Send and fully process a submit_block request, returning a complete decoded
/// response
async fn send_submit_block_full(
    proposal_info: Arc<ProposalInfo>,
    url: Arc<Url>,
    relay: &RelayClient,
    timeout_ms: u64,
    retry: u32,
    api_version: BuilderApiVersion,
) -> Result<Option<SubmitBlindedBlockResponse>, PbsError> {
    // Send the request
    let block_response = send_submit_block_impl(
        relay,
        url,
        timeout_ms,
        (*proposal_info.headers).clone(),
        &proposal_info.signed_blinded_block,
        retry,
        api_version,
    )
    .await?;

    // If this is not v1, there's no body to decode
    if api_version != BuilderApiVersion::V1 {
        return Ok(None);
    }

    // Decode the payload based on content type
    let decoded_response = match block_response.content_type {
        EncodingType::Json => decode_json_payload(&block_response.response_bytes)?,
        EncodingType::Ssz => {
            let fork = match block_response.fork {
                Some(fork) => fork,
                None => {
                    return Err(PbsError::RelayResponse {
                        error_msg: "missing fork version header in SSZ submit_block response"
                            .to_string(),
                        code: block_response.code.as_u16(),
                    });
                }
            };
            decode_ssz_payload(&block_response.response_bytes, fork)?
        }
    };

    // Log and return
    debug!(
        relay_id = relay.id.as_ref(),
        retry,
        latency = ?block_response.request_latency,
        version =% decoded_response.version,
        "received unblinded block"
    );

    Ok(Some(decoded_response))
}

/// Send and lightly process a submit_block request, minimizing the amount of
/// decoding and validation done
async fn send_submit_block_light(
    proposal_info: Arc<ProposalInfo>,
    url: Arc<Url>,
    relay: &RelayClient,
    timeout_ms: u64,
    retry: u32,
) -> Result<Option<LightSubmitBlockResponse>, PbsError> {
    // Send the request
    let block_response = send_submit_block_impl(
        relay,
        url,
        timeout_ms,
        (*proposal_info.headers).clone(),
        &proposal_info.signed_blinded_block,
        retry,
        proposal_info.api_version,
    )
    .await?;

    // If this is not v1, there's no body to decode
    if proposal_info.api_version != BuilderApiVersion::V1 {
        return Ok(None);
    }

    // Decode the payload based on content type
    let fork = match block_response.content_type {
        EncodingType::Json => get_light_info_from_json(&block_response.response_bytes)?,
        EncodingType::Ssz => match block_response.fork {
            Some(fork) => fork,
            None => {
                return Err(PbsError::RelayResponse {
                    error_msg: "missing fork version header in SSZ submit_block response"
                        .to_string(),
                    code: block_response.code.as_u16(),
                });
            }
        },
    };

    // Log and return
    debug!(
        relay_id = relay.id.as_ref(),
        retry,
        latency = ?block_response.request_latency,
        version =% fork,
        "received unblinded block (light processing)"
    );

    Ok(Some(LightSubmitBlockResponse {
        version: fork,
        encoding_type: block_response.content_type,
        raw_bytes: block_response.response_bytes,
    }))
}

/// Sends the actual HTTP request to the relay's submit_block endpoint,
/// returning the response (if applicable), the round-trip time, and the
/// encoding type used for the body (if any). Used by send_submit_block.
pub async fn send_submit_block_impl(
    relay: &RelayClient,
    url: Arc<Url>,
    timeout_ms: u64,
    headers: HeaderMap,
    signed_blinded_block: &SignedBlindedBeaconBlock,
    retry: u32,
    api_version: BuilderApiVersion,
) -> Result<SubmitBlockResponseInfo, PbsError> {
    let start_request = Instant::now();

    // Try SSZ first
    let mut res = match relay
        .client
        .post(url.as_ref().clone())
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers.clone())
        .body(signed_blinded_block.as_ssz_bytes())
        .header(CONTENT_TYPE, EncodingType::Ssz.to_string())
        .header(CONSENSUS_VERSION_HEADER, signed_blinded_block.fork_name_unchecked().to_string())
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

    // If we got a client error, retry with JSON - the spec says that this should be
    // a 406 or 415, but we're a little more permissive here
    if res.status().is_client_error() {
        warn!(
            relay_id = relay.id.as_ref(),
            "relay does not support SSZ, resubmitting block with JSON content-type"
        );
        res = match relay
            .client
            .post(url.as_ref().clone())
            .timeout(Duration::from_millis(timeout_ms))
            .headers(headers)
            .body(serde_json::to_vec(&signed_blinded_block).unwrap())
            .header(CONTENT_TYPE, EncodingType::Json.to_string())
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
    }

    // Log the response code and latency
    let code = res.status();
    let request_latency = start_request.elapsed();
    super::super::record_relay_metrics(
        SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
        &relay.id,
        code,
        request_latency,
    );

    // If this was API v2 and succeeded then we can just return here
    if api_version != BuilderApiVersion::V1 {
        debug!(
            relay_id = relay.id.as_ref(),
            retry,
            latency = ?request_latency,
            "received 202 Accepted for v2 submit_block"
        );

        match code {
            StatusCode::ACCEPTED => {
                return Ok(SubmitBlockResponseInfo {
                    response_bytes: Vec::new(),
                    content_type: EncodingType::Json, // dummy value
                    fork: None,
                    code,
                    request_latency,
                });
            }
            StatusCode::OK => {
                warn!(
                    relay_id = relay.id.as_ref(),
                    "relay sent OK response for v2 submit_block, expected 202 Accepted"
                );
                return Ok(SubmitBlockResponseInfo {
                    response_bytes: Vec::new(),
                    content_type: EncodingType::Json, // dummy value
                    fork: None,
                    code,
                    request_latency,
                });
            }
            _ => {
                return Err(PbsError::RelayResponse {
                    error_msg: format!(
                        "relay sent unexpected code for builder route v2 {}: {code}",
                        relay.id.as_ref()
                    ),
                    code: code.as_u16(),
                });
            }
        }
    }

    // If the code is not OK, return early
    if code != StatusCode::OK {
        let response_bytes =
            read_chunked_body_with_max(res, MAX_SIZE_SUBMIT_BLOCK_RESPONSE).await?;
        let err = PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        };

        // we requested the payload from all relays, but some may have not received it
        warn!(relay_id = relay.id.as_ref(), %err, "failed to get payload (this might be ok if other relays have it)");
        return Err(err);
    }

    // We're on v1 so decode the payload normally - get the content type
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
    let response_bytes = read_chunked_body_with_max(res, MAX_SIZE_SUBMIT_BLOCK_RESPONSE).await?;
    Ok(SubmitBlockResponseInfo { response_bytes, content_type, fork, code, request_latency })
}
