//! Configuration for the PBS module

use std::collections::HashMap;

use alloy::primitives::U256;
use serde::{Deserialize, Serialize};

use super::{
    constants::{DefaultTimeout, LATE_IN_SLOT_TIME_MS},
    RelayEntry,
};
use crate::utils::{as_eth_str, default_bool, default_u256, default_u64};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RelayConfig {
    /// Relay ID, if missing will default to the URL hostname from the entry
    pub id: Option<String>,
    /// Relay in the form of pubkey@url
    #[serde(rename = "url")]
    pub entry: RelayEntry,
    /// Optional headers to send with each request
    pub headers: Option<HashMap<String, String>>,
    /// Whether to enable timing games
    pub enable_timing_games: bool,
    /// Delay in ms to wait before sending the first get_header
    pub wait_first_header_ms: Option<u64>,
    /// Frequency in ms to send get_header requests
    pub frequency_get_header_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PbsConfig {
    /// Port to receive BuilderAPI calls from beacon node
    pub port: u16,
    /// Whether to forward `get_status`` to relays or skip it
    pub relay_check: bool,
    /// Timeout for get_header request in milliseconds
    #[serde(default = "default_u64::<{ DefaultTimeout::GET_HEADER_MS }>")]
    pub timeout_get_header_ms: u64,
    /// Timeout for get_payload request in milliseconds
    #[serde(default = "default_u64::<{ DefaultTimeout::GET_PAYLOAD_MS }>")]
    pub timeout_get_payload_ms: u64,
    /// Timeout for register_validator request in milliseconds
    #[serde(default = "default_u64::<{ DefaultTimeout::REGISTER_VALIDATOR_MS }>")]
    pub timeout_register_validator_ms: u64,
    /// Whether to skip the relay signature verification
    #[serde(default = "default_bool::<false>")]
    pub skip_sigverify: bool,
    /// Minimum bid that will be accepted from get_header
    #[serde(rename = "min_bid_eth", with = "as_eth_str", default = "default_u256")]
    pub min_bid_wei: U256,
    /// How late in the slot we consider to be "late"
    #[serde(default = "default_u64::<LATE_IN_SLOT_TIME_MS>")]
    pub late_in_slot_time_ms: u64,
    /// If it's too late in the slot, skip get header and force local build
    #[serde(default = "default_bool::<false>")]
    pub skip_header_late_in_slot: bool,
}
