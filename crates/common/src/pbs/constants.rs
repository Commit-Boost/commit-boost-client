use crate::constants::COMMIT_BOOST_VERSION;

pub const BUILDER_V1_API_PATH: &str = "/eth/v1/builder";
pub const BUILDER_V2_API_PATH: &str = "/eth/v2/builder";

pub const GET_HEADER_PATH: &str = "/header/{slot}/{parent_hash}/{pubkey}";

pub const GET_HEADER_STREAM_PATH: &str = "/header_stream";
pub const GET_STATUS_PATH: &str = "/status";
pub const REGISTER_VALIDATOR_PATH: &str = "/validators";
pub const SUBMIT_BLOCK_PATH: &str = "/blinded_blocks";
pub const RELOAD_PATH: &str = "/reload";

pub const GET_EXECUTION_PAYLOAD_BID_PATH: &str =
    "/execution_payload_bid/{slot}/{parent_hash}/{parent_root}/{proposer_pubkey}";
pub const SUBMIT_BUILDER_PREFERENCES_PATH: &str = "/builder_preferences/{proposer_pubkey}";
pub const SUBMIT_SIGNED_BEACON_BLOCK_PATH: &str = "/beacon_blocks";

// https://ethereum.github.io/builder-specs/#/Builder

// Currently unused to enable a stateless default PBS module
// const HEADER_SLOT_UUID_KEY: &str = "X-MEVBoost-SlotID";
pub const HEADER_VERSION_KEY: &str = "X-CommitBoost-Version";
pub const HEADER_VERSION_VALUE: &str = COMMIT_BOOST_VERSION;
pub const HEADER_START_TIME_UNIX_MS: &str = "Date-Milliseconds";
pub const HEADER_TIMEOUT_MS: &str = "X-Timeout-Ms";
pub const HEADER_API_KEY: &str = "X-Api-Key";
pub const HEADER_CONSENSUS_VERSION: &str = "Eth-Consensus-Version";

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

/// How long each ePBS bid poll may take before the next one supersedes it. Set
/// generously: a proposer far from its builders needs more than the poll
/// cadence to land any bid at all, and a value below the round trip would time
/// out every poll. The final poll ignores this and holds until the deadline.
pub const DEFAULT_BID_POLL_TIMEOUT_MS: u64 = 500;

// Maximum number of retries for validator registration request per relay
pub const REGISTER_VALIDATOR_RETRY_LIMIT: u32 = 3;

pub const DEFAULT_REGISTRY_REFRESH_SECONDS: u64 = 12 * 32; // One epoch
