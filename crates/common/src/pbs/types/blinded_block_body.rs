use alloy::{
    primitives::{Address, B256},
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use serde::{Deserialize, Serialize};
use ssz_types::{typenum, BitList, BitVector, FixedVector, VariableList};

use super::{
    execution_payload::ExecutionPayloadHeader, kzg::KzgCommitments, spec::EthSpec, utils::*,
};
use crate::utils::as_str;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BlindedBeaconBlockBody<T: EthSpec> {
    pub randao_reveal: BlsSignature,
    pub eth1_data: Eth1Data,
    pub graffiti: B256,
    pub proposer_slashings: VariableList<ProposerSlashing, T::MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashing<T>, T::MaxAttesterSlashings>,
    pub attestations: VariableList<Attestation<T>, T::MaxAttestations>,
    pub deposits: VariableList<Deposit, T::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, T::MaxVoluntaryExits>,
    pub sync_aggregate: SyncAggregate<T>,
    pub execution_payload_header: ExecutionPayloadHeader<T>,
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, T::MaxBlsToExecutionChanges>,
    pub blob_kzg_commitments: KzgCommitments<T>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Eth1Data {
    pub deposit_root: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_count: u64,
    pub block_hash: B256,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BlsToExecutionChange {
    #[serde(with = "as_str")]
    pub validator_index: u64,
    pub from_bls_pubkey: BlsPublicKey,
    pub to_execution_address: Address,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedBlsToExecutionChange {
    pub message: BlsToExecutionChange,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttesterSlashing<T: EthSpec> {
    pub attestation_1: IndexedAttestation<T>,
    pub attestation_2: IndexedAttestation<T>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct IndexedAttestation<T: EthSpec> {
    /// Lists validator registry indices, not committee indices.
    #[serde(with = "quoted_variable_list_u64")]
    pub attesting_indices: VariableList<u64, T::MaxValidatorsPerCommitteeWithSlot>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttestationData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    // LMD GHOST vote
    pub beacon_block_root: B256,
    // FFG Vote
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
    pub root: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct Attestation<T: EthSpec> {
    pub aggregation_bits: BitList<T::MaxValidatorsPerCommitteeWithSlot>,
    pub data: AttestationData,
    pub signature: BlsSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committee_bits: Option<BitVector<T::MaxCommitteesPerSlot>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Deposit {
    pub proof: FixedVector<B256, typenum::U33>, // put this in EthSpec?
    pub data: DepositData,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DepositData {
    pub pubkey: BlsPublicKey,
    pub withdrawal_credentials: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed.
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct SyncAggregate<T: EthSpec> {
    pub sync_committee_bits: BitVector<T::SyncCommitteeSize>,
    pub sync_committee_signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct ExecutionRequests<T: EthSpec> {
    pub deposits: VariableList<DepositRequest, T::MaxDepositRequestsPerPayload>,
    pub withdrawals: VariableList<WithdrawalRequest, T::MaxWithdrawalRequestsPerPayload>,
    pub consolidations: VariableList<ConsolidationRequest, T::MaxConsolidationRequestsPerPayload>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DepositRequest {
    pub pubkey: BlsPublicKey,
    pub withdrawal_credentials: B256,
    pub amount: u64,
    pub signature: BlsSignature,
    pub index: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub source_address: Address,
    pub validator_pubkey: BlsPublicKey,
    pub amount: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: BlsPublicKey,
    pub target_pubkey: BlsPublicKey,
}