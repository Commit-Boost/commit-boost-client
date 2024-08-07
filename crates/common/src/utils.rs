use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::U256,
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use axum::http::HeaderValue;
use blst::min_pk::{PublicKey, Signature};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::header::HeaderMap;
use tracing::Level;
use tracing_appender::{non_blocking::WorkerGuard, rolling::Rotation};
use tracing_subscriber::{fmt::Layer, prelude::*, EnvFilter};

use crate::{
    config::{default_log_level, RollingDuration, CB_BASE_LOG_PATH},
    pbs::HEAVER_VERSION_VALUE,
    types::Chain,
};

const SECONDS_PER_SLOT: u64 = 12;
const MILLIS_PER_SECOND: u64 = 1_000;

pub const ROLLING_DURATION_ENV: &str = "ROLLING_DURATION";

pub const MAX_LOG_FILES_ENV: &str = "MAX_LOG_FILES";

pub const RUST_LOG_ENV: &str = "RUST_LOG";

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
pub fn initialize_tracing_log(module_id: &str) -> WorkerGuard {
    // Log all events to a rolling log file.
    let mut builder =
        tracing_appender::rolling::Builder::new().filename_prefix(module_id.to_lowercase());
    if let Ok(value) = env::var(MAX_LOG_FILES_ENV) {
        builder =
            builder.max_log_files(value.parse().expect("MAX_LOG_FILES is not a valid usize value"));
    }

    let rotation = match env::var(ROLLING_DURATION_ENV)
        .unwrap_or(RollingDuration::default().to_string())
        .as_str()
    {
        "hourly" => Rotation::HOURLY,
        "daily" => Rotation::DAILY,
        "never" => Rotation::NEVER,
        _ => panic!("unknown rotation value"),
    };

    let log_file = builder
        .rotation(rotation)
        .build(CB_BASE_LOG_PATH)
        .expect("failed building rolling file appender");

    let level_env = std::env::var(RUST_LOG_ENV).unwrap_or(default_log_level());

    // Log level for stdout
    let stdout_log_level = match level_env.parse::<Level>() {
        Ok(f) => f,
        Err(_) => {
            eprintln!("Invalid RUST_LOG value {}, defaulting to info", level_env);
            Level::INFO
        }
    };

    // at least debug for file logs
    let file_log_level = stdout_log_level.max(Level::DEBUG);

    let stdout_log_filter = format_crates_filter(Level::INFO.as_str(), stdout_log_level.as_str());
    let file_log_filter = format_crates_filter(Level::INFO.as_str(), file_log_level.as_str());

    let stdout_log =
        tracing_subscriber::fmt::layer().with_target(false).with_filter(stdout_log_filter);
    let (default_writer, guard) = tracing_appender::non_blocking(log_file);
    let file_log = Layer::new()
        .json()
        .with_current_span(false)
        .with_span_list(true)
        .with_writer(default_writer)
        .with_filter(file_log_filter);

    tracing_subscriber::registry().with(stdout_log.and_then(file_log)).init();

    guard
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
    Ok(HeaderValue::from_str(&format!("commit-boost/{HEAVER_VERSION_VALUE} {}", ua))?)
}
