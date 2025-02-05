use serde::{Deserialize, Serialize};
use ssz_derive::Encode;
use ssz_types::{FixedVector, VariableList};

use super::{
    kzg::{KzgCommitments, KzgProofs},
    spec::EthSpec,
};

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode)]
#[serde(bound = "T: EthSpec")]
pub struct BlobsBundle<T: EthSpec> {
    pub commitments: KzgCommitments<T>,
    pub proofs: KzgProofs<T>,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub blobs: VariableList<Blob<T>, <T as EthSpec>::MaxBlobCommitmentsPerBlock>,
}

pub type Blob<T> = FixedVector<u8, <T as EthSpec>::BytesPerBlob>;
