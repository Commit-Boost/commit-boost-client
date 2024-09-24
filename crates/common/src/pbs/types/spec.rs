use serde::{Deserialize, Serialize};
use ssz_types::typenum;

pub trait EthSpec {
    type MaxProposerSlashings: typenum::Unsigned + std::fmt::Debug;
    type MaxValidatorsPerCommittee: typenum::Unsigned + std::fmt::Debug;
    type MaxAttesterSlashings: typenum::Unsigned + std::fmt::Debug;
    type MaxAttestations: typenum::Unsigned + std::fmt::Debug;
    type MaxDeposits: typenum::Unsigned + std::fmt::Debug;
    type MaxVoluntaryExits: typenum::Unsigned + std::fmt::Debug;
    type SyncCommitteeSize: typenum::Unsigned + std::fmt::Debug;
    type BytesPerLogsBloom: typenum::Unsigned + std::fmt::Debug;
    type MaxExtraDataBytes: typenum::Unsigned + std::fmt::Debug;
    type MaxBlsToExecutionChanges: typenum::Unsigned + std::fmt::Debug;
    type MaxBlobCommitmentsPerBlock: typenum::Unsigned + std::fmt::Debug;
    type MaxWithdrawalsPerPayload: typenum::Unsigned + std::fmt::Debug;
    type MaxBytesPerTransaction: typenum::Unsigned + std::fmt::Debug;
    type MaxTransactionsPerPayload: typenum::Unsigned + std::fmt::Debug;
    type BytesPerBlob: typenum::Unsigned + std::fmt::Debug;
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DenebSpec;

impl EthSpec for DenebSpec {
    type MaxValidatorsPerCommittee = typenum::U2048;
    type MaxProposerSlashings = typenum::U16;
    type MaxAttesterSlashings = typenum::U2;
    type MaxAttestations = typenum::U128;
    type MaxDeposits = typenum::U16;
    type MaxVoluntaryExits = typenum::U16;
    type SyncCommitteeSize = typenum::U512;
    type MaxExtraDataBytes = typenum::U32;
    type MaxBlobCommitmentsPerBlock = typenum::U4096;
    type BytesPerLogsBloom = typenum::U256;
    type MaxBlsToExecutionChanges = typenum::U16;
    type MaxWithdrawalsPerPayload = typenum::U16;
    type MaxBytesPerTransaction = typenum::U1073741824;
    type MaxTransactionsPerPayload = typenum::U1048576;
    type BytesPerBlob = typenum::U131072;
}
