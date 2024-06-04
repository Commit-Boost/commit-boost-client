use std::net::SocketAddr;

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

use super::utils::as_eth_str;
use crate::{pbs::RelayEntry, types::Chain};

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitBoostConfig {
    pub chain: Chain,
    pub pbs: BuilderConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BuilderConfig {
    /// Which port to open listen
    pub address: SocketAddr,
    /// Which relay to register/subscribe
    pub relays: Vec<RelayEntry>,
    /// Whether to forward getStatus to relays or skip it
    pub relay_check: bool,
    #[serde(default = "default_u64::<950>")]
    pub timeout_get_header_ms: u64,
    #[serde(default = "default_u64::<4000>")]
    pub timeout_get_payload_ms: u64,
    #[serde(default = "default_u64::<3000>")]
    pub timeout_register_validator_ms: u64,
    // TODO: add custom headers
    /// Whether to skip the relay signature verification
    #[serde(default = "default_bool::<false>")]
    pub skip_sigverify: bool,
    #[serde(rename = "min_bid_eth", with = "as_eth_str", default = "default_u256")]
    pub min_bid_wei: U256,
}

const fn default_u64<const U: u64>() -> u64 {
    U
}

const fn default_bool<const U: bool>() -> bool {
    U
}

const fn default_u256() -> U256 {
    U256::ZERO
}
