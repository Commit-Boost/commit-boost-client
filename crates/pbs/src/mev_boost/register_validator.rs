use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use alloy::primitives::Bytes;
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    pbs::{HEADER_START_TIME_UNIX_MS, RelayClient, error::PbsError},
    types::BlsPublicKey,
    utils::utcnow_ms,
    wire::{get_user_agent_with_version, safe_read_http_response},
};
use eyre::bail;
use futures::{
    FutureExt,
    future::{join_all, select_ok},
};
use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use tracing::{Instrument, debug, error};
use url::Url;
use ws_wire::messages::{SignedValidatorRegistrationV1, SubscriptionRequest};

use crate::{
    constants::{MAX_SIZE_DEFAULT, REGISTER_VALIDATOR_ENDPOINT_TAG, TIMEOUT_ERROR_CODE_STR},
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/registerValidator
/// Returns 200 if at least one relay returns 200, else 503.
///
/// Additionally, if the CB config has any relays with `websocket = true`,
/// forwards each registration to ONLY the WS clients for relays that the
/// registration's pubkey actually maps to via mux configuration (D2). REST
/// path is unchanged.
pub async fn register_validator<S: BuilderApiState>(
    registrations: Vec<serde_json::Value>,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<()> {
    // Forward to WS clients per mux. `forward_to_ws_clients` is a no-op
    // if no relay has `websocket = true`.
    forward_to_ws_clients(&state, &registrations);

    // --- Unchanged REST path below ---

    let mut send_headers = HeaderMap::new();
    send_headers
        .insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from_str(&utcnow_ms().to_string())?);
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers)?);

    let bodies: Box<dyn Iterator<Item = (usize, Bytes)>> =
        if let Some(batch_size) = state.config.pbs_config.validator_registration_batch_size {
            Box::new(registrations.chunks(batch_size).map(|batch| {
                let body = serde_json::to_vec(batch).unwrap();
                (batch.len(), Bytes::from(body))
            }))
        } else {
            let body = serde_json::to_vec(&registrations).unwrap();
            Box::new(std::iter::once((registrations.len(), Bytes::from(body))))
        };
    send_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let mut handles = Vec::with_capacity(state.all_relays().len());

    for (n_regs, body) in bodies {
        for relay in state.all_relays().iter().cloned() {
            handles.push(
                tokio::spawn(
                    send_register_validator_with_timeout(
                        n_regs,
                        body.clone(),
                        relay,
                        send_headers.clone(),
                        state.pbs_config().timeout_register_validator_ms,
                        state.pbs_config().register_validator_retry_limit,
                    )
                    .in_current_span(),
                )
                .map(|join_result| match join_result {
                    Ok(res) => res,
                    Err(err) => Err(PbsError::TokioJoinError(err)),
                }),
            );
        }
    }

    if state.pbs_config().wait_all_registrations {
        let results = join_all(handles).await;
        if results.into_iter().any(|res| res.is_ok()) {
            Ok(())
        } else {
            bail!("No relay passed register_validator successfully")
        }
    } else {
        let result = select_ok(handles).await;
        match result {
            Ok(_) => Ok(()),
            Err(_) => bail!("No relay passed register_validator successfully"),
        }
    }
}

// ---------------------------------------------------------------------------
// WS forwarder (ARCH §3.3 / D2)
// ---------------------------------------------------------------------------

/// Forward registrations to WS clients per mux. For each registration, look
/// up which relays the pubkey talks to via `state.mux_config_and_relays`
/// and only send to those relays' WS clients. Groups by relay so each WS
/// client receives at most one batch per forward.
///
/// Silently skips registrations with malformed JSON — REST will still try
/// those relays with the original JSON body.
fn forward_to_ws_clients<S: BuilderApiState>(
    state: &PbsState<S>,
    registrations: &[serde_json::Value],
) {
    let ws_clients = state.ws_clients.read();
    if ws_clients.is_empty() {
        return;
    }

    // Group by relay id. Each entry is a batch of the registrations whose
    // mux points at this relay.
    let mut by_relay: HashMap<String, Vec<SignedValidatorRegistrationV1>> = HashMap::new();

    for reg in registrations {
        let Some(parsed) = parse_json_registration(reg) else {
            continue;
        };
        let Ok(pubkey) = BlsPublicKey::deserialize(&parsed.message.pubkey) else {
            continue;
        };
        let (_, relays, _) = state.mux_config_and_relays(&pubkey);
        for relay in relays {
            let key = relay.id.to_string();
            // Only forward if this relay actually has a WS client spawned.
            if ws_clients.contains_key(&key) {
                by_relay.entry(key).or_default().push(parsed.clone());
            }
        }
    }

    for (relay_id, batch) in by_relay {
        if let Some(client) = ws_clients.get(&relay_id) {
            client.send_registration_batch(batch);
        }
    }
}

// ---------------------------------------------------------------------------
// JSON parsing
// ---------------------------------------------------------------------------

/// Parse a builder-specs `SignedValidatorRegistrationV1` JSON value into
/// the ws-wire specs-layout struct. Returns None on malformed input so the
/// forwarder can skip bad entries without failing the whole batch. REST
/// path still handles validation.
fn parse_json_registration(reg: &serde_json::Value) -> Option<SignedValidatorRegistrationV1> {
    let msg = reg.get("message")?;
    let signature = reg.get("signature").and_then(|s| s.as_str())?;

    let fee_recipient_str = msg.get("fee_recipient").and_then(|v| v.as_str())?;
    let pubkey_str = msg.get("pubkey").and_then(|v| v.as_str())?;

    // gas_limit and timestamp may appear as quoted-string or number in
    // builder-specs JSON (the spec technically mandates quoted-string).
    let gas_limit = parse_u64_field(msg.get("gas_limit"))?;
    let timestamp = parse_u64_field(msg.get("timestamp"))?;

    let fee_recipient = hex_to_fixed_bytes::<20>(fee_recipient_str);
    let pubkey = hex_to_fixed_bytes::<48>(pubkey_str);
    let signature_bytes = hex_to_fixed_bytes::<96>(signature);

    Some(SignedValidatorRegistrationV1 {
        message: SubscriptionRequest { fee_recipient, gas_limit, timestamp, pubkey },
        signature: signature_bytes,
    })
}

fn parse_u64_field(v: Option<&serde_json::Value>) -> Option<u64> {
    let v = v?;
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        return s.parse::<u64>().ok();
    }
    None
}

fn hex_to_fixed_bytes<const N: usize>(s: &str) -> [u8; N] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut arr = [0u8; N];
    for (i, byte) in arr.iter_mut().enumerate() {
        let byte_start = i * 2;
        if byte_start + 2 > s.len() {
            break;
        }
        if let Ok(b) = u8::from_str_radix(&s[byte_start..byte_start + 2], 16) {
            *byte = b;
        }
    }
    arr
}

// ---------------------------------------------------------------------------
// REST path (unchanged)
// ---------------------------------------------------------------------------

async fn send_register_validator_with_timeout(
    n_regs: usize,
    body: Bytes,
    relay: RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
    retry_limit: u32,
) -> Result<(), PbsError> {
    let url = relay.register_validator_url()?;
    let mut remaining_timeout_ms = timeout_ms;
    let mut retry = 0;
    let mut backoff = Duration::from_millis(250);

    loop {
        let start_request = Instant::now();
        match send_register_validator(
            url.clone(),
            n_regs,
            body.clone(),
            &relay,
            headers.clone(),
            remaining_timeout_ms,
            retry,
        )
        .await
        {
            Ok(_) => return Ok(()),

            Err(err) if err.should_retry() => {
                retry += 1;
                if retry >= retry_limit {
                    error!(
                        relay_id = relay.id.as_str(),
                        retry, "reached retry limit for validator registration"
                    );
                    return Err(err);
                }
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
    }
}

async fn send_register_validator(
    url: Url,
    n_regs: usize,
    body: Bytes,
    relay: &RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
    retry: u32,
) -> Result<(), PbsError> {
    let start_request = Instant::now();
    let res = match relay
        .client
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers)
        .body(body.0)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            RELAY_STATUS_CODE
                .with_label_values(&[
                    TIMEOUT_ERROR_CODE_STR,
                    REGISTER_VALIDATOR_ENDPOINT_TAG,
                    &relay.id,
                ])
                .inc();
            return Err(err.into());
        }
    };
    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[REGISTER_VALIDATOR_ENDPOINT_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());

    let code = res.status();
    RELAY_STATUS_CODE
        .with_label_values(&[code.as_str(), REGISTER_VALIDATOR_ENDPOINT_TAG, &relay.id])
        .inc();

    safe_read_http_response(res, MAX_SIZE_DEFAULT).await.inspect_err(|err| {
        error!(relay_id = relay.id.as_ref(), retry, %err, "failed registration");
    })?;

    debug!(
        relay_id = relay.id.as_ref(),
        retry,
        ?code,
        latency = ?request_latency,
        num_registrations = n_regs,
        "registration successful"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json(pubkey_hex: &str) -> serde_json::Value {
        serde_json::json!({
            "message": {
                "fee_recipient": "0x00000000000000000000000000000000000000aa",
                "gas_limit": "30000000",
                "timestamp": "1700000000",
                "pubkey": pubkey_hex,
            },
            "signature": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        })
    }

    #[test]
    fn parse_json_registration_quoted_string_numbers() {
        let pubkey = "0xaa".repeat(24);
        let pubkey = format!("{pubkey}");
        let pubkey = pubkey.replacen("0xaa0x", "0xaa", 1);
        let reg = sample_json(&pubkey);
        let parsed = parse_json_registration(&reg).expect("valid input");
        assert_eq!(parsed.message.gas_limit, 30_000_000);
        assert_eq!(parsed.message.timestamp, 1_700_000_000);
        assert_eq!(parsed.message.pubkey[0], 0xaa);
    }

    #[test]
    fn parse_json_registration_raw_numbers() {
        let pubkey = format!("0x{}", "bb".repeat(48));
        let reg = serde_json::json!({
            "message": {
                "fee_recipient": "0x00000000000000000000000000000000000000ff",
                "gas_limit": 30_000_000u64,
                "timestamp": 1_700_000_000u64,
                "pubkey": pubkey,
            },
            "signature": format!("0x{}", "cc".repeat(96)),
        });
        let parsed = parse_json_registration(&reg).expect("valid input");
        assert_eq!(parsed.message.gas_limit, 30_000_000);
        assert_eq!(parsed.message.pubkey[0], 0xbb);
        assert_eq!(parsed.signature[0], 0xcc);
    }

    #[test]
    fn parse_json_registration_missing_fields_returns_none() {
        let reg = serde_json::json!({ "message": {} });
        assert!(parse_json_registration(&reg).is_none());
    }

    #[test]
    fn parse_u64_field_handles_both_forms() {
        assert_eq!(parse_u64_field(Some(&serde_json::json!(42u64))), Some(42));
        assert_eq!(parse_u64_field(Some(&serde_json::json!("42"))), Some(42));
        assert_eq!(parse_u64_field(Some(&serde_json::json!("not a number"))), None);
        assert_eq!(parse_u64_field(None), None);
    }

    #[test]
    fn hex_to_fixed_bytes_roundtrip() {
        let h = "0xaabbccdd";
        let b = hex_to_fixed_bytes::<4>(h);
        assert_eq!(b, [0xaa, 0xbb, 0xcc, 0xdd]);
        // Short input pads with zeros.
        let b = hex_to_fixed_bytes::<6>(h);
        assert_eq!(b, [0xaa, 0xbb, 0xcc, 0xdd, 0, 0]);
    }
}
