use alloy::primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

use super::spec::EthSpec;
use crate::types::{BlsPublicKey, BlsSignature};

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ExecutionRequests<T: EthSpec> {
    pub deposits: VariableList<DepositRequest, T::MaxDepositRequestsPerPayload>,
    pub withdrawals: VariableList<WithdrawalRequest, T::MaxWithdrawalRequestsPerPayload>,
    pub consolidations: VariableList<ConsolidationRequest, T::MaxConsolidationRequestsPerPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct DepositRequest {
    pub pubkey: BlsPublicKey,
    pub withdrawal_credentials: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: BlsSignature,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct WithdrawalRequest {
    pub source_address: Address,
    pub validator_pubkey: BlsPublicKey,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: BlsPublicKey,
    pub target_pubkey: BlsPublicKey,
}
