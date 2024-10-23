pub(crate) const STATUS_ENDPOINT_TAG: &str = "status";
pub(crate) const REGISTER_VALIDATOR_ENDPOINT_TAG: &str = "register_validator";
pub(crate) const SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG: &str = "submit_blinded_block";
pub(crate) const GET_HEADER_ENDPOINT_TAG: &str = "get_header";

/// For metrics recorded when a request times out
pub(crate) const TIMEOUT_ERROR_CODE: u16 = 555;
pub(crate) const TIMEOUT_ERROR_CODE_STR: &str = "555";

/// 20 MiB to cover edge cases for heavy blocks and also add a bit of slack for
/// any Ethereum upgrades in the near future
pub(crate) const MAX_SIZE_SUBMIT_BLOCK: usize = 20 * 1024 * 1024;

/// 1 KiB, headers are around 700 bytes + some buffer
pub(crate) const MAX_SIZE_GET_HEADER: usize = 1024;

pub(crate) const MAX_SIZE_DEFAULT: usize = 1024;
