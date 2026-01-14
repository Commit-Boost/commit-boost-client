mod get_header;
mod register_validator;
mod reload;
mod status;
mod submit_block;

use alloy::primitives::U256;
use cb_common::{pbs::GetHeaderResponse, utils::EncodingType};
pub use get_header::get_header;
use lh_types::ForkName;
pub use register_validator::register_validator;
pub use reload::reload;
pub use status::get_status;
pub use submit_block::submit_block;

/// Enum that handles different response types based on the level of validation
/// required
pub enum CompoundGetHeaderResponse {
    /// Standard response type, fully parsing the response from a relay into a
    /// complete response struct
    Full(Box<GetHeaderResponse>),

    /// Light response type, only extracting the fork and value from the builder
    /// bid with the entire (undecoded) payload for forwarding
    Light(LightGetHeaderResponse),
}

/// Core details of a GetHeaderResponse, used for light processing when
/// validation mode is set to none.
#[derive(Clone)]
pub struct LightGetHeaderResponse {
    /// The fork name for the bid
    pub version: ForkName,

    /// The bid value in wei
    pub value: U256,

    /// The raw bytes of the response, for forwarding to the caller
    pub raw_bytes: Vec<u8>,

    /// The format the response bytes are encoded with
    pub encoding_type: EncodingType,
}
