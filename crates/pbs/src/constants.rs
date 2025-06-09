pub const STATUS_ENDPOINT_TAG: &str = "status";
pub const REGISTER_VALIDATOR_ENDPOINT_TAG: &str = "register_validator";
pub const SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG: &str = "submit_blinded_block";
pub const GET_HEADER_ENDPOINT_TAG: &str = "get_header";
pub const RELOAD_ENDPOINT_TAG: &str = "reload";

/// For metrics recorded when a request times out
pub const TIMEOUT_ERROR_CODE: u16 = 555;
pub const TIMEOUT_ERROR_CODE_STR: &str = "555";

/// 20 MiB to cover edge cases for heavy blocks and also add a bit of slack for
/// any Ethereum upgrades in the near future
pub const MAX_SIZE_SUBMIT_BLOCK_RESPONSE: usize = 20 * 1024 * 1024;

/// 20 MiB, enough to process ~45000 registrations in one request
pub const MAX_SIZE_REGISTER_VALIDATOR_REQUEST: usize = 20 * 1024 * 1024;

/// 5 MiB, to account for max execution requests / commitments
pub const MAX_SIZE_GET_HEADER_RESPONSE: usize = 5 * 1024 * 1024;

pub const MAX_SIZE_DEFAULT: usize = 1024;
