use serde::{Deserialize, Serialize};
use ssz_types::typenum::{
    Unsigned, U0, U1, U1048576, U1073741824, U128, U131072, U134217728, U16, U2, U2048, U256,
    U262144, U32, U4096, U512, U6, U64, U8, U8192, U9,
};
use std::fmt::Debug;

pub trait EthSpec: 'static + Default + Clone + Debug + Send + Sync + Serialize {
    type MaxProposerSlashings: Unsigned + Clone + Debug + Send + Sync;
    type MaxValidatorsPerCommittee: Unsigned + Clone + Debug + Send + Sync;
    type MaxAttesterSlashings: Unsigned + Clone + Debug + Send + Sync;
    type MaxAttestations: Unsigned + Clone + Debug + Send + Sync;
    type MaxDeposits: Unsigned + Clone + Debug + Send + Sync;
    type MaxVoluntaryExits: Unsigned + Clone + Debug + Send + Sync;
    type SyncCommitteeSize: Unsigned + Clone + Debug + Send + Sync;
    type BytesPerLogsBloom: Unsigned + Clone + Debug + Send + Sync;
    type MaxExtraDataBytes: Unsigned + Clone + Debug + Send + Sync;
    type MaxBlsToExecutionChanges: Unsigned + Clone + Debug + Send + Sync;
    type MaxBlobCommitmentsPerBlock: Unsigned + Clone + Debug + Send + Sync;
    type MaxWithdrawalsPerPayload: Unsigned + Clone + Debug + Send + Sync;
    type MaxBytesPerTransaction: Unsigned + Clone + Debug + Send + Sync;
    type MaxTransactionsPerPayload: Unsigned + Clone + Debug + Send + Sync;
    type BytesPerBlob: Unsigned + Clone + Debug + Send + Sync;
    type MaxBlobsPerBlock: Unsigned + Clone + Debug + Send + Sync;
    type MaxCommitteesPerSlot: Unsigned + Clone + Debug + Send + Sync;
    // New in Electra
    type PendingBalanceDepositsLimit: Unsigned + Clone + Debug + Send + Sync;
    type PendingPartialWithdrawalsLimit: Unsigned + Clone + Debug + Send + Sync;
    type PendingConsolidationsLimit: Unsigned + Clone + Debug + Send + Sync;
    type MaxConsolidationRequestsPerPayload: Unsigned + Clone + Debug + Send + Sync;
    type MaxDepositRequestsPerPayload: Unsigned + Clone + Debug + Send + Sync;
    type MaxWithdrawalRequestsPerPayload: Unsigned + Clone + Debug + Send + Sync;

    // used across multiple specs
    type MaxValidatorsPerCommitteeWithSlot: Unsigned + Clone + Debug + Send + Sync;
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DenebSpec;

impl EthSpec for DenebSpec {
    type MaxValidatorsPerCommittee = U2048;
    type MaxProposerSlashings = U16;
    type MaxAttesterSlashings = U2;
    type MaxAttestations = U128;
    type MaxDeposits = U16;
    type MaxVoluntaryExits = U16;
    type SyncCommitteeSize = U512;
    type MaxExtraDataBytes = U32;
    type MaxBlobCommitmentsPerBlock = U4096;
    type BytesPerLogsBloom = U256;
    type MaxBlsToExecutionChanges = U16;
    type MaxWithdrawalsPerPayload = U16;
    type MaxBytesPerTransaction = U1073741824;
    type MaxTransactionsPerPayload = U1048576;
    type BytesPerBlob = U131072;
    type MaxBlobsPerBlock = U6;
    type MaxCommitteesPerSlot = U64;

    // Ignore Electra fields
    type PendingBalanceDepositsLimit = U0;
    type PendingPartialWithdrawalsLimit = U0;
    type PendingConsolidationsLimit = U0;
    type MaxConsolidationRequestsPerPayload = U0;
    type MaxDepositRequestsPerPayload = U0;
    type MaxWithdrawalRequestsPerPayload = U0;

    // MAX_VALIDATORS_PER_COMMITTEE
    type MaxValidatorsPerCommitteeWithSlot = U2048;
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ElectraSpec;

impl EthSpec for ElectraSpec {
    type MaxValidatorsPerCommittee = U2048;
    type MaxProposerSlashings = U16;
    type MaxAttesterSlashings = U1; // Updated in Electra
    type MaxAttestations = U8; // Updated in Electra
    type MaxDeposits = U16;
    type MaxVoluntaryExits = U16;
    type SyncCommitteeSize = U512;
    type MaxExtraDataBytes = U32;
    type MaxBlobCommitmentsPerBlock = U4096;
    type BytesPerLogsBloom = U256;
    type MaxBlsToExecutionChanges = U16;
    type MaxWithdrawalsPerPayload = U16;
    type MaxBytesPerTransaction = U1073741824;
    type MaxTransactionsPerPayload = U1048576;
    type BytesPerBlob = U131072;
    type MaxBlobsPerBlock = U9; // New in Electra:EIP7691
    type MaxCommitteesPerSlot = U64;

    // New Electra fields
    type PendingBalanceDepositsLimit = U134217728;
    type PendingPartialWithdrawalsLimit = U134217728;
    type PendingConsolidationsLimit = U262144;
    type MaxConsolidationRequestsPerPayload = U2;
    type MaxDepositRequestsPerPayload = U8192;
    type MaxWithdrawalRequestsPerPayload = U16;

    // MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT
    type MaxValidatorsPerCommitteeWithSlot = U131072;
}
