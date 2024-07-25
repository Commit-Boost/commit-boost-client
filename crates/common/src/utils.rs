use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
    primitives::U256,
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use blst::min_pk::{PublicKey, Signature};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::header::HeaderMap;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::types::Chain;

const SECONDS_PER_SLOT: u64 = 12;
const MILLIS_PER_SECOND: u64 = 1_000;

pub fn timestamp_of_slot_start_millis(slot: u64, chain: Chain) -> u64 {
    let seconds_since_genesis = chain.genesis_time_sec() + slot * SECONDS_PER_SLOT;

    seconds_since_genesis * MILLIS_PER_SECOND
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

// LOGGING
// TODO: more customized logging + logging guard
pub fn initialize_tracing_log() {
    let level_env = std::env::var("RUST_LOG").unwrap_or("info".to_owned());

    let filter = match level_env.parse::<EnvFilter>() {
        Ok(f) => f,
        Err(_) => {
            eprintln!("Invalid RUST_LOG value {}, defaulting to info", level_env);
            EnvFilter::new("info")
        }
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false))
        .try_init()
        .unwrap();
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

/// Extracts the user agent from the request headers
pub fn get_user_agent(req_headers: &HeaderMap) -> Option<String> {
    req_headers
        .get(reqwest::header::USER_AGENT)
        .and_then(|ua| ua.to_str().ok().map(|s| s.to_string()))
}
