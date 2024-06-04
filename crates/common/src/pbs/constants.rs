pub const BULDER_API_PATH: &str = "/eth/v1/builder";

pub const GET_HEADER_PATH: &str = "/header/:slot/:parent_hash/:pubkey";
pub const GET_STATUS_PATH: &str = "/status";
pub const REGISTER_VALIDATOR_PATH: &str = "/validators";
pub const SUBMIT_BLOCK_PATH: &str = "/blinded_blocks";

// https://ethereum.github.io/builder-specs/#/Builder

pub const HEADER_KEY_SLOT_UUID: &str = "X-MEVBoost-SlotID";
pub const HEADER_KEY_VERSION: &str = "X-MEVBoost-Version"; // do we need to use this
pub const HEADER_START_TIME_UNIX_MS: &str = "X-MEVBoost-StartTimeUnixMS";
