use alloy::primitives::{B256, U256};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use super::{
    execution_payload::ExecutionPayloadHeader, execution_requests::ExecutionRequests,
    kzg::KzgCommitments, spec::ElectraSpec, utils::VersionedResponse,
};
use crate::types::{BlsPublicKey, BlsSignature};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetHeaderParams {
    /// The slot to request the header for
    pub slot: u64,
    /// The parent hash of the block to request the header for
    pub parent_hash: B256,
    /// The pubkey of the validator that is requesting the header
    pub pubkey: BlsPublicKey,
}

/// Returned by relay in get_header
pub type GetHeaderResponse =
    VersionedResponse<SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageElectra>>;

impl GetHeaderResponse {
    pub fn block_number(&self) -> u64 {
        match self {
            VersionedResponse::Electra(data) => data.message.header.block_number,
        }
    }

    pub fn block_hash(&self) -> B256 {
        match self {
            VersionedResponse::Electra(data) => data.message.header.block_hash,
        }
    }

    pub fn gas_limit(&self) -> u64 {
        match self {
            VersionedResponse::Electra(data) => data.message.header.gas_limit,
        }
    }

    pub fn pubkey(&self) -> &BlsPublicKey {
        match self {
            VersionedResponse::Electra(data) => &data.message.pubkey,
        }
    }

    pub fn value(&self) -> U256 {
        match self {
            VersionedResponse::Electra(data) => data.message.value,
        }
    }

    pub fn transactions_root(&self) -> B256 {
        match self {
            GetHeaderResponse::Electra(data) => data.message.header.transactions_root,
        }
    }

    pub fn parent_hash(&self) -> B256 {
        match self {
            GetHeaderResponse::Electra(data) => data.message.header.parent_hash,
        }
    }

    pub fn signautre(&self) -> &BlsSignature {
        match self {
            GetHeaderResponse::Electra(data) => &data.signature,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedExecutionPayloadHeader<T: Encode + Decode> {
    pub message: T,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ExecutionPayloadHeaderMessageElectra {
    pub header: ExecutionPayloadHeader<ElectraSpec>,
    pub blob_kzg_commitments: KzgCommitments<ElectraSpec>,
    pub execution_requests: ExecutionRequests<ElectraSpec>,
    #[serde(with = "serde_utils::quoted_u256")]
    pub value: U256,
    pub pubkey: BlsPublicKey,
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{aliases::B32, U256};

    use super::*;
    use crate::{
        constants::APPLICATION_BUILDER_DOMAIN,
        pbs::VersionedResponse,
        signature::verify_signed_message,
        types::Chain,
        utils::{test_encode_decode, test_encode_decode_ssz},
    };

    #[test]
    // from the builder api spec, with signature fixed to the correct pubkey
    fn test_get_header_electra() {
        let data = r#"{
            "version": "electra",
            "data": {
                "message": {
                    "header": {
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
                        "base_fee_per_gas": "1",
                        "blob_gas_used": "1",
                        "excess_blob_gas": "1",
                        "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "withdrawals_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                    },
                    "blob_kzg_commitments": [
                        "0xa94170080872584e54a1cf092d845703b13907f2e6b3b1c0ad573b910530499e3bcd48c6378846b80d2bfa58c81cf3d5"
                    ],
                    "execution_requests": {
                        "deposits": [
                            {
                                "pubkey": "0x911f24ad11078aad2b28ff9dcb4651a0b686e3972b2b4190273f35d416bf057dbd95553d7a0edb107b1a5e1b211da8c4",
                                "withdrawal_credentials": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                                "amount": "1",
                                "signature": "0xb4f92cd90de8e4b67debeb0379f08d0e6d3046e67e824e6ed63cd841abc9999c8b123a780e34a480d4ef13466b6241e30000b047d27de43fcf475fc4e69da2d26929cec97742892346f53e78f973bbe8095285f05a8ea60b118cdd1e6a704c94",
                                "index": "1"
                            }
                        ],
                        "withdrawals": [
                            {
                                "source_address": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                                "validator_pubkey": "0x911f24ad11078aad2b28ff9dcb4651a0b686e3972b2b4190273f35d416bf057dbd95553d7a0edb107b1a5e1b211da8c4",
                                "amount": "1"
                            }
                        ],
                        "consolidations": [
                            {
                                "source_address": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                                "source_pubkey": "0x911f24ad11078aad2b28ff9dcb4651a0b686e3972b2b4190273f35d416bf057dbd95553d7a0edb107b1a5e1b211da8c4",
                                "target_pubkey": "0x911f24ad11078aad2b28ff9dcb4651a0b686e3972b2b4190273f35d416bf057dbd95553d7a0edb107b1a5e1b211da8c4"
                            }
                        ]
                    },
                    "value": "1",
                    "pubkey": "0xac0a230bd98a766b8e4156f0626ee679dd280dee5b0eedc2b9455ca3dacc4c7618da5010b9db609450a712f095c9f7a5"
                },
                "signature": "0x8aeb4642fb2982039a43fd6a6d9cc0ebf7598dbf02343c4617d9a68d799393c162492add63f31099a25eacc2782ba27a190e977a8c58760b6636dccb503d528b3be9e885c93d5b79699e68fcca870b0c790cdb00d67604d8b4a3025ae75efa2f"
            }
        }"#;

        let parsed = test_encode_decode::<GetHeaderResponse>(data);
        let VersionedResponse::Electra(parsed) = parsed;

        assert_eq!(parsed.message.value, U256::from(1));

        assert!(verify_signed_message(
            Chain::Holesky,
            &parsed.message.pubkey,
            &parsed.message,
            &parsed.signature,
            None,
            &B32::from(APPLICATION_BUILDER_DOMAIN),
        ))
    }

    #[test]
    // this is dummy data generated with https://github.com/attestantio/go-builder-client
    fn test_signed_execution_payload_header_ssz() {
        let data_json = include_str!("testdata/get-header-response.json");
        let block_json = test_encode_decode::<
            SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageElectra>,
        >(data_json);

        let data_ssz = include_bytes!("testdata/get-header-response.ssz");
        test_encode_decode_ssz::<SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageElectra>>(
            data_ssz,
        );

        assert_eq!(block_json.as_ssz_bytes(), data_ssz);
    }
}
