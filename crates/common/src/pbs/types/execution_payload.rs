use alloy::primitives::{b256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use tree_hash_derive::TreeHash;

use super::spec::EthSpec;
use crate::utils::as_str;

pub const EMPTY_TX_ROOT_HASH: B256 =
    b256!("7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1");

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
    #[serde(with = "serde_utils::quoted_u256")]
    pub base_fee_per_gas: U256,
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
    use alloy::primitives::b256;
    use ssz_types::VariableList;
    use tree_hash::TreeHash;

    use super::*;
    use crate::{
        pbs::types::{execution_payload::Transactions, spec::DenebSpec},
        utils::test_encode_decode,
    };

    #[test]
    fn test_empty_tx_root_hash() {
        let txs: Transactions<DenebSpec> = VariableList::empty();
        let txs_root = txs.tree_hash_root();

        assert_eq!(txs_root, EMPTY_TX_ROOT_HASH);
    }

    #[test]
    fn test_execution_payload_header() {
        let data = r#"{
            "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
            "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
            "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
            "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
            "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
            "block_number": "1",
            "gas_limit": "1",
            "gas_used": "1",
            "timestamp": "1",
            "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
            "base_fee_per_gas": "150",
            "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
            "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
            "withdrawals_root": "0x2daccf0e476ca3e2644afbd13b2621d55b4d515b813a3b867cdacea24bb352d1",
            "blob_gas_used": "786432",
            "excess_blob_gas": "95158272"
        }"#;

        let parsed = test_encode_decode::<ExecutionPayloadHeader<DenebSpec>>(&data);

        assert_eq!(
            parsed.parent_hash,
            b256!("cf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2")
        );
        assert_eq!(parsed.base_fee_per_gas, U256::from(150));
    }
}
