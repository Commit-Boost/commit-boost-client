use std::usize;

use alloy::primitives::{Address, B256, U256};
use cb_common::utils::as_str;
use ethereum_types::{Address as EAddress, U256 as EU256};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use tree_hash_derive::TreeHash;

use super::{spec::EthSpec, utils::*};

pub const EMPTY_TX_ROOT_HASH: [u8; 32] = [
    127, 254, 36, 30, 166, 1, 135, 253, 176, 24, 123, 250, 34, 222, 53, 209, 249, 190, 215, 171, 6,
    29, 148, 1, 253, 71, 227, 74, 84, 251, 237, 225,
];

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct ExecutionPayload<T: EthSpec> {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    pub prev_randao: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    #[serde(with = "as_str")]
    pub base_fee_per_gas: U256,
    pub block_hash: B256,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Transactions<T>,
    pub withdrawals: VariableList<Withdrawal, T::MaxWithdrawalsPerPayload>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub blob_gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub excess_blob_gas: u64,
}

pub type Transactions<T> = VariableList<
    Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
    <T as EthSpec>::MaxTransactionsPerPayload,
>;
pub type Transaction<N> = VariableList<u8, N>;

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Withdrawal {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ExecutionPayloadHeader<T: EthSpec> {
    pub parent_hash: B256,
    pub fee_recipient: EAddress,
    pub state_root: B256,
    pub receipts_root: B256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    pub prev_randao: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    #[serde(with = "as_dec_str")]
    base_fee_per_gas: EU256,
    pub block_hash: B256,
    pub transactions_root: B256,
    pub withdrawals_root: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub blob_gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub excess_blob_gas: u64,
}

#[cfg(test)]
mod tests {
    use ssz_types::VariableList;
    use tree_hash::TreeHash;

    use super::Transactions;
    use crate::types::{execution_payload::EMPTY_TX_ROOT_HASH, spec::DenebSpec};

    #[test]
    fn test_empty_tx_root_hash() {
        let txs: Transactions<DenebSpec> = VariableList::empty();
        let txs_root = txs.tree_hash_root();

        assert_eq!(txs_root.0, EMPTY_TX_ROOT_HASH);
        assert_eq!(
            format!("{txs_root:?}"),
            "0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1"
        );
    }
}
