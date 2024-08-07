pub const BULDER_API_PATH: &str = "/eth/v1/builder";

pub const GET_HEADER_PATH: &str = "/header/:slot/:parent_hash/:pubkey";
pub const GET_STATUS_PATH: &str = "/status";
pub const REGISTER_VALIDATOR_PATH: &str = "/validators";
pub const SUBMIT_BLOCK_PATH: &str = "/blinded_blocks";

// https://ethereum.github.io/builder-specs/#/Builder

pub const HEADER_SLOT_UUID_KEY: &str = "X-MEVBoost-SlotID";
pub const HEADER_VERSION_KEY: &str = "X-CommitBoost-Version";
pub const HEAVER_VERSION_VALUE: &str = env!("CARGO_PKG_VERSION");
pub const HEADER_START_TIME_UNIX_MS: &str = "X-MEVBoost-StartTimeUnixMS";

pub const BUILDER_EVENTS_PATH: &str = "/builder_events";
pub const DEFAULT_PBS_JWT_KEY: &str = "DEFAULT_PBS";

#[non_exhaustive]
pub struct DefaultTimeout;
impl DefaultTimeout {
    pub const GET_HEADER_MS: u64 = 950;
    pub const GET_PAYLOAD_MS: u64 = 4000;
    pub const REGISTER_VALIDATOR_MS: u64 = 3000;
}

pub const LATE_IN_SLOT_TIME_MS: u64 = 2000;
