use std::{
    fmt,
    net::Ipv4Addr,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::U256,
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use axum::{
    extract::{FromRequest, Request},
    http::HeaderValue,
    response::{IntoResponse, Response},
};
use blst::min_pk::{PublicKey, Signature};
use bytes::Bytes;
use mediatype::{names, MediaType, MediaTypeList};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::{
    header::{HeaderMap, ACCEPT, CONTENT_TYPE},
    StatusCode,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use ssz::{Decode, Encode};
use tracing::Level;
use tracing_appender::{non_blocking::WorkerGuard, rolling::Rotation};
use tracing_subscriber::{fmt::Layer, prelude::*, EnvFilter};

use crate::{
    config::{load_optional_env_var, LogsSettings, PBS_MODULE_NAME},
    pbs::HEADER_VERSION_VALUE,
    types::Chain,
};

const MILLIS_PER_SECOND: u64 = 1_000;
pub const CONSENSUS_VERSION_HEADER: &str = "Eth-Consensus-Version";

pub fn timestamp_of_slot_start_sec(slot: u64, chain: Chain) -> u64 {
    chain.genesis_time_sec() + slot * chain.slot_time_sec()
}
pub fn timestamp_of_slot_start_millis(slot: u64, chain: Chain) -> u64 {
    timestamp_of_slot_start_sec(slot, chain) * MILLIS_PER_SECOND
}
pub fn ms_into_slot(slot: u64, chain: Chain) -> u64 {
    let slot_start_ms = timestamp_of_slot_start_millis(slot, chain);
    utcnow_ms().saturating_sub(slot_start_ms)
}

/// Seconds
pub fn utcnow_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
/// Millis
pub fn utcnow_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}
/// Micros
pub fn utcnow_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}
/// Nanos
pub fn utcnow_ns() -> u64 {
    // safe until ~2554
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

pub const WEI_PER_ETH: u64 = 1_000_000_000_000_000_000;
pub fn eth_to_wei(eth: f64) -> U256 {
    U256::from((eth * WEI_PER_ETH as f64).floor())
}

// Serde
/// Test that the encoding and decoding works, returns the decoded struct
pub fn test_encode_decode<T: Serialize + DeserializeOwned>(d: &str) -> T {
    let decoded = serde_json::from_str::<T>(d).expect("deserialize");

    // re-encode to make sure that different formats are ignored
    let encoded = serde_json::to_string(&decoded).unwrap();
    let original_v: Value = serde_json::from_str(d).unwrap();
    let encoded_v: Value = serde_json::from_str(&encoded).unwrap();

    if original_v != encoded_v {
        println!("ORIGINAL: {original_v}");
        println!("ENCODED: {encoded_v}");
        panic!("encode mismatch");
    }

    decoded
}

pub fn test_encode_decode_ssz<T: Encode + Decode>(d: &[u8]) -> T {
    let decoded = T::from_ssz_bytes(d).expect("deserialize");
    let encoded = T::as_ssz_bytes(&decoded);

    assert_eq!(encoded, d);

    decoded
}

pub mod as_str {
    use std::{fmt::Display, str::FromStr};

    use serde::Deserialize;

    pub fn serialize<S, T: Display>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&data.to_string())
    }

    pub fn deserialize<'de, D, T, E>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: FromStr<Err = E>,
        E: Display,
    {
        let s = String::deserialize(deserializer)?;
        T::from_str(&s).map_err(serde::de::Error::custom)
    }
}

pub mod as_eth_str {
    use alloy::primitives::{
        utils::{format_ether, parse_ether},
        U256,
    };
    use serde::Deserialize;

    use super::eth_to_wei;

    pub fn serialize<S>(data: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = format_ether(*data);
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrF64 {
            Str(String),
            F64(f64),
        }

        let value = StringOrF64::deserialize(deserializer)?;
        let wei = match value {
            StringOrF64::Str(s) => {
                parse_ether(&s).map_err(|_| serde::de::Error::custom("invalid eth amount"))?
            }
            StringOrF64::F64(f) => eth_to_wei(f),
        };

        Ok(wei)
    }
}

pub const fn default_u64<const U: u64>() -> u64 {
    U
}

pub const fn default_u16<const U: u16>() -> u16 {
    U
}

pub const fn default_bool<const U: bool>() -> bool {
    U
}

pub const fn default_host() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}

pub const fn default_u256() -> U256 {
    U256::ZERO
}

// LOGGING
pub fn initialize_tracing_log(module_id: &str) -> eyre::Result<WorkerGuard> {
    let settings = LogsSettings::from_env_config()?;

    // Use file logs only if setting is set
    let use_file_logs = settings.is_some();
    let settings = settings.unwrap_or_default();

    // Log level for stdout

    let stdout_log_level = if let Some(log_level) = load_optional_env_var("RUST_LOG") {
        log_level.parse::<Level>().expect("invalid RUST_LOG value")
    } else {
        settings.log_level.parse::<Level>().expect("invalid log_level value in settings")
    };

    let stdout_filter = format_crates_filter(Level::INFO.as_str(), stdout_log_level.as_str());

    if use_file_logs {
        // Log all events to a rolling log file.
        let mut builder =
            tracing_appender::rolling::Builder::new().filename_prefix(module_id.to_lowercase());
        if let Some(value) = settings.max_log_files {
            builder = builder.max_log_files(value);
        }
        let file_appender = builder
            .rotation(Rotation::DAILY)
            .build(settings.log_dir_path)
            .expect("failed building rolling file appender");

        let (writer, guard) = tracing_appender::non_blocking(file_appender);

        // at least debug for file logs
        let file_log_level = stdout_log_level.max(Level::DEBUG);
        let file_log_filter = format_crates_filter(Level::INFO.as_str(), file_log_level.as_str());

        let stdout_layer =
            tracing_subscriber::fmt::layer().with_target(false).with_filter(stdout_filter);

        let file_layer = Layer::new()
            .json()
            .with_current_span(false)
            .with_span_list(true)
            .with_writer(writer)
            .with_filter(file_log_filter);

        tracing_subscriber::registry().with(stdout_layer.and_then(file_layer)).init();
        Ok(guard)
    } else {
        let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
        let stdout_layer = tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_writer(writer)
            .with_filter(stdout_filter);
        tracing_subscriber::registry().with(stdout_layer).init();
        Ok(guard)
    }
}

pub fn initialize_pbs_tracing_log() -> eyre::Result<WorkerGuard> {
    initialize_tracing_log(PBS_MODULE_NAME)
}

// all commit boost crates
// TODO: this can probably done without unwrap
fn format_crates_filter(default_level: &str, crates_level: &str) -> EnvFilter {
    let s = format!(
        "{default_level},cb_signer={crates_level},cb_pbs={crates_level},cb_common={crates_level},cb_metrics={crates_level}",
    );
    s.parse().unwrap()
}

pub fn print_logo() {
    println!(
        r#"   ______                          _ __     ____                   __ 
  / ____/___  ____ ___  ____ ___  (_) /_   / __ )____  ____  _____/ /_
 / /   / __ \/ __ `__ \/ __ `__ \/ / __/  / __  / __ \/ __ \/ ___/ __/
/ /___/ /_/ / / / / / / / / / / / / /_   / /_/ / /_/ / /_/ (__  ) /_  
\____/\____/_/ /_/ /_/_/ /_/ /_/_/\__/  /_____/\____/\____/____/\__/  
                                                                      "#
    )
}

// Crypto conversions

pub fn alloy_pubkey_to_blst(pubkey: &BlsPublicKey) -> Result<PublicKey, blst::BLST_ERROR> {
    PublicKey::key_validate(&pubkey.0)
}

pub fn alloy_sig_to_blst(signature: &BlsSignature) -> Result<Signature, blst::BLST_ERROR> {
    Signature::from_bytes(&signature.0)
}

pub fn blst_pubkey_to_alloy(pubkey: &PublicKey) -> BlsPublicKey {
    BlsPublicKey::from_slice(&pubkey.to_bytes())
}

/// Generates a random string
pub fn random_jwt() -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect()
}

/// Returns the user agent from the request headers or an empty string if not
/// present
pub fn get_user_agent(req_headers: &HeaderMap) -> String {
    req_headers
        .get(reqwest::header::USER_AGENT)
        .and_then(|ua| ua.to_str().ok().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Adds the commit boost version to the existing user agent
pub fn get_user_agent_with_version(req_headers: &HeaderMap) -> eyre::Result<HeaderValue> {
    let ua = get_user_agent(req_headers);
    Ok(HeaderValue::from_str(&format!("commit-boost/{HEADER_VERSION_VALUE} {}", ua))?)
}

/// Parse ACCEPT header, default to JSON if missing or mal-formatted
pub fn get_accept_header(req_headers: &HeaderMap) -> Accept {
    Accept::from_str(
        req_headers.get(ACCEPT).and_then(|value| value.to_str().ok()).unwrap_or("application/json"),
    )
    .unwrap_or(Accept::Json)
}

/// Parse CONTENT TYPE header, default to JSON if missing or mal-formatted
pub fn get_content_type_header(req_headers: &HeaderMap) -> ContentType {
    ContentType::from_str(
        req_headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/json"),
    )
    .unwrap_or(ContentType::Json)
}

/// Parse CONSENSUS_VERSION header
pub fn get_consensus_version_header(req_headers: &HeaderMap) -> Option<ForkName> {
    ForkName::from_str(
        req_headers
            .get(CONSENSUS_VERSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or(""),
    )
    .ok()
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ForkName {
    Deneb,
    Electra,
}

impl std::fmt::Display for ForkName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForkName::Deneb => write!(f, "deneb"),
            ForkName::Electra => write!(f, "electra"),
        }
    }
}

impl FromStr for ForkName {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "deneb" => Ok(ForkName::Deneb),
            "electra" => Ok(ForkName::Electra),
            _ => Err(format!("Invalid fork name {}", value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContentType {
    Json,
    Ssz,
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentType::Json => write!(f, "application/json"),
            ContentType::Ssz => write!(f, "application/octet-stream"),
        }
    }
}

impl FromStr for ContentType {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "application/json" => Ok(ContentType::Json),
            "application/octet-stream" => Ok(ContentType::Ssz),
            _ => Ok(ContentType::Json),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Accept {
    Json,
    Ssz,
    Any,
}

impl fmt::Display for Accept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Accept::Ssz => write!(f, "application/octet-stream"),
            Accept::Json => write!(f, "application/json"),
            Accept::Any => write!(f, "*/*"),
        }
    }
}

impl FromStr for Accept {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let media_type_list = MediaTypeList::new(s);

        // [q-factor weighting]: https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.2
        // find the highest q-factor supported accept type
        let mut highest_q = 0_u16;
        let mut accept_type = None;

        const APPLICATION: &str = names::APPLICATION.as_str();
        const OCTET_STREAM: &str = names::OCTET_STREAM.as_str();
        const JSON: &str = names::JSON.as_str();
        const STAR: &str = names::_STAR.as_str();
        const Q: &str = names::Q.as_str();

        media_type_list.into_iter().for_each(|item| {
            if let Ok(MediaType { ty, subty, suffix: _, params }) = item {
                let q_accept = match (ty.as_str(), subty.as_str()) {
                    (APPLICATION, OCTET_STREAM) => Some(Accept::Ssz),
                    (APPLICATION, JSON) => Some(Accept::Json),
                    (STAR, STAR) => Some(Accept::Any),
                    _ => None,
                }
                .map(|item_accept_type| {
                    let q_val = params
                        .iter()
                        .find_map(|(n, v)| match n.as_str() {
                            Q => {
                                Some((v.as_str().parse::<f32>().unwrap_or(0_f32) * 1000_f32) as u16)
                            }
                            _ => None,
                        })
                        .or(Some(1000_u16));

                    (q_val.unwrap(), item_accept_type)
                });

                match q_accept {
                    Some((q, accept)) if q > highest_q => {
                        highest_q = q;
                        accept_type = Some(accept);
                    }
                    _ => (),
                }
            }
        });
        accept_type.ok_or_else(|| "accept header is not supported".to_string())
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonOrSsz<T>(pub T);

impl<T, S> FromRequest<S> for JsonOrSsz<T>
where
    T: serde::de::DeserializeOwned + ssz::Decode + 'static,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let headers = req.headers().clone();
        let content_type = headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok());

        let bytes = Bytes::from_request(req, _state).await.map_err(IntoResponse::into_response)?;

        if let Some(content_type) = content_type {
            if content_type.starts_with(&ContentType::Json.to_string()) {
                let payload: T = serde_json::from_slice(&bytes)
                    .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
                return Ok(Self(payload));
            }

            if content_type.starts_with(&ContentType::Ssz.to_string()) {
                let payload = T::from_ssz_bytes(&bytes)
                    .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
                return Ok(Self(payload));
            }
        }

        Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response())
    }
}

#[cfg(unix)]
pub async fn wait_for_signal() -> eyre::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }

    Ok(())
}

#[cfg(windows)]
pub async fn wait_for_signal() -> eyre::Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}
