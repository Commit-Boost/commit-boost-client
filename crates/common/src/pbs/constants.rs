use crate::constants::COMMIT_BOOST_VERSION;

pub const BUILDER_API_PATH: &str = "/eth/v1/builder";

pub const GET_HEADER_PATH: &str = "/header/{slot}/{parent_hash}/{pubkey}";
pub const GET_STATUS_PATH: &str = "/status";
pub const REGISTER_VALIDATOR_PATH: &str = "/validators";
pub const SUBMIT_BLOCK_PATH: &str = "/blinded_blocks";
pub const RELOAD_PATH: &str = "/reload";

// https://ethereum.github.io/builder-specs/#/Builder

// Currently unused to enable a stateless default PBS module
// const HEADER_SLOT_UUID_KEY: &str = "X-MEVBoost-SlotID";
pub const HEADER_VERSION_KEY: &str = "X-CommitBoost-Version";
pub const HEADER_VERSION_VALUE: &str = COMMIT_BOOST_VERSION;
pub const HEADER_START_TIME_UNIX_MS: &str = "Date-Milliseconds";

pub const BUILDER_EVENTS_PATH: &str = "/builder_events";
pub const DEFAULT_PBS_JWT_KEY: &str = "DEFAULT_PBS";

pub const DEFAULT_PBS_PORT: u16 = 18550;

#[non_exhaustive]
pub struct DefaultTimeout;
impl DefaultTimeout {
    pub const GET_HEADER_MS: u64 = 950;
    pub const GET_PAYLOAD_MS: u64 = 4000;
    pub const REGISTER_VALIDATOR_MS: u64 = 3000;
}

pub const LATE_IN_SLOT_TIME_MS: u64 = 2000;

// Maximum number of retries for validator registration request per relay
pub const REGISTER_VALIDATOR_RETRY_LIMIT: u32 = 3;
