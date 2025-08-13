use alloy::{
    primitives::{B256, U256},
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use super::{
    execution_payload::ExecutionPayloadHeader, execution_requests::ExecutionRequests,
    kzg::KzgCommitments, spec::ElectraSpec, utils::VersionedResponse,
};

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
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

    pub fn pubkey(&self) -> BlsPublicKey {
        match self {
            VersionedResponse::Electra(data) => data.message.pubkey,
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

    pub fn signautre(&self) -> BlsSignature {
        match self {
            GetHeaderResponse::Electra(data) => data.signature,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedExecutionPayloadHeader<T: Encode + Decode> {
    pub message: T,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
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
    // from the builder api spec, the signature is a dummy so it's not checked
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
                                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                                "withdrawal_credentials": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                                "amount": "1",
                                "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
                                "index": "1"
                            }
                        ],
                        "withdrawals": [
                            {
                                "source_address": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                                "validator_pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                                "amount": "1"
                            }
                        ],
                        "consolidations": [
                            {
                                "source_address": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                                "source_pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                                "target_pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
                            }
                        ]
                    },
                    "value": "1",
                    "pubkey": "0x86b1cea87eed94cad99244356abcd83995947670f0553a1d3fe83c4a9e8116f4891fb1c51db232e736be1cb3327164bc"
                },
                "signature": "0x8addecd35e0ffe27b74e41aff2836527e6fea0efdb46dbb0f7436f5087d0cd5665bd16d924f640fc928cdba0173971e400dc603dbd6310bfb6f249c1554b044fe06ae4cf5d5f452f3ff19d9d130809b34d3d3abdca3d192c839ba2ac91129c15"
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
            &B32::from(APPLICATION_BUILDER_DOMAIN)
        )
        .is_ok())
    }

    #[test]
    // this is dummy data generated with https://github.com/attestantio/go-builder-client
    fn test_signed_execution_payload_header_ssz() {
        let data_json = include_str!("testdata/get-header-response.json");
        let block_json = test_encode_decode::<
            SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageElectra>,
        >(data_json);

        let data_ssz = include_bytes!("testdata/get-header-response.ssz");
        let data_ssz = alloy::primitives::hex::decode(data_ssz).unwrap();
        test_encode_decode_ssz::<SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageElectra>>(
            &data_ssz,
        );

        assert_eq!(block_json.as_ssz_bytes(), data_ssz);
    }
}
