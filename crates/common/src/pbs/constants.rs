pub const BULDER_API_PATH: &str = "/eth/v1/builder";

pub const GET_HEADER_PATH: &str = "/header/:slot/:parent_hash/:pubkey";
pub const GET_STATUS_PATH: &str = "/status";
pub const REGISTER_VALIDATOR_PATH: &str = "/validators";
pub const SUBMIT_BLOCK_PATH: &str = "/blinded_blocks";

// https://ethereum.github.io/builder-specs/#/Builder

pub const HEADER_SLOT_UUID_KEY: &str = "X-MEVBoost-SlotID";
pub const HEADER_VERSION_KEY: &str = "X-CommitBoost-Version";
pub const HEAVER_VERSION_VALUE: &str = "0.1.0";
pub const HEADER_START_TIME_UNIX_MS: &str = "X-MEVBoost-StartTimeUnixMS";

pub const BUILDER_EVENTS_PATH: &str = "/events";
pub const DEFAULT_PBS_JWT_KEY: &str = "DEFAULT_PBS";
