use std::ops::Deref;

use alloy::{
    primitives::{Bytes, B256, U256},
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use cb_common::pbs::{SignedExecutionPayloadHeader, VersionedResponse};
use serde::{Deserialize, Serialize};

/// Extra config loaded from the config file
/// You should add an `inc_amount` field to the config file in the `pbs`
/// section. Be sure also to change the `pbs.docker_image` field,
/// `test_status_api` in this case (from scripts/build_local_modules.sh).
#[derive(Debug, Deserialize)]
pub struct ExtraConfig {
    pub inc_amount: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct GetHeaderParams {
    pub slot: u64,
    pub parent_hash: B256,
    pub pubkey: BlsPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConstraints {
    pub message: ConstraintsMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintsMessage {
    pub validator_index: u64,
    pub slot: u64,
    pub top: bool,
    pub transactions: Vec<Bytes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDelegation {
    pub message: DelegationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationMessage {
    pub validator_index: u64,
    pub pubkey: BlsPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRevocation {
    pub message: RevocationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationMessage {
    pub validator_index: u64,
    pub pubkey: BlsPublicKey,
}

pub type GetHeaderWithProofsResponse = VersionedResponse<SignedExecutionPayloadHeaderWithProofs>;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedExecutionPayloadHeaderWithProofs {
    #[serde(flatten)]
    pub header: SignedExecutionPayloadHeader,
    pub proofs: (),
}

impl Deref for SignedExecutionPayloadHeaderWithProofs {
    type Target = SignedExecutionPayloadHeader;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}
