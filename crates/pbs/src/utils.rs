use cb_common::{
    pbs::error::PbsError,
    utils::{read_chunked_body_with_max as read_chunked_body_with_max_impl, ResponseReadError},
};
use reqwest::Response;

pub async fn read_chunked_body_with_max(
    res: Response,
    max_size: usize,
) -> Result<Vec<u8>, PbsError> {
    let result = read_chunked_body_with_max_impl(res, max_size).await;
    match result {
        Ok(bytes) => Ok(bytes),
        Err(ResponseReadError::PayloadTooLarge { max, raw }) => {
            Err(PbsError::PayloadTooLarge { max, raw })
        }
        Err(ResponseReadError::ChunkError { inner }) => Err(PbsError::Reqwest(inner)),
    }
}

const GAS_LIMIT_ADJUSTMENT_FACTOR: u64 = 1024;
const GAS_LIMIT_MINIMUM: u64 = 5_000;

/// Validates the gas limit against the parent gas limit, according to the
/// execution spec https://github.com/ethereum/execution-specs/blob/98d6ddaaa709a2b7d0cd642f4cfcdadc8c0808e1/src/ethereum/cancun/fork.py#L1118-L1154
pub fn check_gas_limit(gas_limit: u64, parent_gas_limit: u64) -> bool {
    let max_adjustment_delta = parent_gas_limit / GAS_LIMIT_ADJUSTMENT_FACTOR;
    if gas_limit >= parent_gas_limit + max_adjustment_delta {
        return false;
    }

    if gas_limit <= parent_gas_limit - max_adjustment_delta {
        return false;
    }

    if gas_limit < GAS_LIMIT_MINIMUM {
        return false;
    }

    true
}
