use alloy_rpc_types_beacon::BlsPublicKey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("unknown consensus signer: {0}")]
    UnknownConsensusSigner(BlsPublicKey),

    #[error("unknown proxy signer: {0}")]
    UnknownProxySigner(BlsPublicKey),
}
