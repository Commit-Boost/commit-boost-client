use alloy::{
    primitives::{Address, B256},
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, BitList, BitVector, FixedVector, VariableList};

use super::{
    execution_payload::ExecutionPayloadHeader, execution_requests::ExecutionRequests,
    kzg::KzgCommitments, spec::EthSpec, utils::*,
};

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct BlindedBeaconBlockBodyElectra<T: EthSpec> {
    pub randao_reveal: BlsSignature,
    pub eth1_data: Eth1Data,
    pub graffiti: B256,
    pub proposer_slashings: VariableList<ProposerSlashing, T::MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashingElectra<T>, T::MaxAttesterSlashings>,
    pub attestations: VariableList<AttestationElectra<T>, T::MaxAttestations>,
    pub deposits: VariableList<Deposit, T::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, T::MaxVoluntaryExits>,
    pub sync_aggregate: SyncAggregate<T>,
    pub execution_payload_header: ExecutionPayloadHeader<T>,
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, T::MaxBlsToExecutionChanges>,
    pub blob_kzg_commitments: KzgCommitments<T>,
    pub execution_requests: ExecutionRequests<T>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Eth1Data {
    pub deposit_root: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_count: u64,
    pub block_hash: B256,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct BeaconBlockHeader {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct BlsToExecutionChange {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub from_bls_pubkey: BlsPublicKey,
    pub to_execution_address: Address,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedBlsToExecutionChange {
    pub message: BlsToExecutionChange,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AttesterSlashingElectra<T: EthSpec> {
    pub attestation_1: IndexedAttestationElectra<T>,
    pub attestation_2: IndexedAttestationElectra<T>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
#[serde(bound = "T: EthSpec")]
pub struct IndexedAttestationElectra<T: EthSpec> {
    /// Lists validator registry indices, not committee indices.
    #[serde(with = "quoted_variable_list_u64")]
    pub attesting_indices: VariableList<u64, T::MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
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

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Checkpoint {
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
    pub root: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
#[serde(bound = "T: EthSpec")]
pub struct AttestationElectra<T: EthSpec> {
    pub aggregation_bits: BitList<T::MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: BlsSignature,
    pub committee_bits: BitVector<T::MaxCommitteesPerSlot>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Deposit {
    pub proof: FixedVector<B256, typenum::U33>, // put this in EthSpec?
    pub data: DepositData,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct DepositData {
    pub pubkey: BlsPublicKey,
    pub withdrawal_credentials: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed.
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
#[serde(bound = "T: EthSpec")]
pub struct SyncAggregate<T: EthSpec> {
    pub sync_committee_bits: BitVector<T::SyncCommitteeSize>,
    pub sync_committee_signature: BlsSignature,
}
