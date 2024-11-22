use cb_common::pbs::error::PbsError;
use futures::StreamExt;
use reqwest::Response;

pub async fn read_chunked_body_with_max(
    res: Response,
    max_size: usize,
) -> Result<Vec<u8>, PbsError> {
    let mut stream = res.bytes_stream();
    let mut response_bytes = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if response_bytes.len() + chunk.len() > max_size {
            // avoid spamming logs if the message is too large
            response_bytes.truncate(1024);
            return Err(PbsError::PayloadTooLarge {
                max: max_size,
                raw: String::from_utf8_lossy(&response_bytes).into_owned(),
            });
        }

        response_bytes.extend_from_slice(&chunk);
    }

    Ok(response_bytes)
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
