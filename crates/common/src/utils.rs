use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
    primitives::U256,
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use axum::http::HeaderValue;
use blst::min_pk::{PublicKey, Signature};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::header::HeaderMap;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use tracing::Level;
use tracing_appender::{non_blocking::WorkerGuard, rolling::Rotation};
use tracing_subscriber::{fmt::Layer, prelude::*, EnvFilter};

use crate::{
    config::{LogsSettings, LOGS_DIR_DEFAULT, PBS_MODULE_NAME},
    pbs::HEADER_VERSION_VALUE,
    types::Chain,
};

const SECONDS_PER_SLOT: u64 = 12;
const MILLIS_PER_SECOND: u64 = 1_000;

pub fn timestamp_of_slot_start_millis(slot: u64, chain: Chain) -> u64 {
    let seconds_since_genesis = chain.genesis_time_sec() + slot * SECONDS_PER_SLOT;
    seconds_since_genesis * MILLIS_PER_SECOND
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

// Formatting
const WEI_PER_ETH: u64 = 1_000_000_000_000_000_000;
pub fn wei_to_eth(wei: &U256) -> f64 {
    wei.to_string().parse::<f64>().unwrap_or_default() / WEI_PER_ETH as f64
}
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
    assert_eq!(original_v, encoded_v, "encode mismatch");

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
    use alloy::primitives::U256;
    use serde::Deserialize;

    use super::{eth_to_wei, wei_to_eth};

    pub fn serialize<S>(data: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = wei_to_eth(data).to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = f64::deserialize(deserializer)?;
        Ok(eth_to_wei(s))
    }
}

pub const fn default_u64<const U: u64>() -> u64 {
    U
}

pub const fn default_bool<const U: bool>() -> bool {
    U
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
    let stdout_log_level = match settings.log_level.parse::<Level>() {
        Ok(f) => f,
        Err(_) => {
            eprintln!("Invalid RUST_LOG value {}, defaulting to info", settings.log_level);
            Level::INFO
        }
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
            .build(LOGS_DIR_DEFAULT)
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
