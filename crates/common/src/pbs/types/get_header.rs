use alloy::{
    primitives::{B256, U256},
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use super::{
    execution_payload::ExecutionPayloadHeader,
    execution_requests::ExecutionRequests,
    kzg::KzgCommitments,
    spec::{DenebSpec, ElectraSpec},
    utils::VersionedResponse,
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
pub type GetHeaderResponse = VersionedResponse<
    SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageDeneb>,
    SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageElectra>,
>;

impl GetHeaderResponse {
    pub fn block_number(&self) -> u64 {
        match self {
            VersionedResponse::Deneb(data) => data.message.header.block_number,
            VersionedResponse::Electra(data) => data.message.header.block_number,
        }
    }

    pub fn block_hash(&self) -> B256 {
        match self {
            VersionedResponse::Deneb(data) => data.message.header.block_hash,
            VersionedResponse::Electra(data) => data.message.header.block_hash,
        }
    }

    pub fn gas_limit(&self) -> u64 {
        match self {
            VersionedResponse::Deneb(data) => data.message.header.gas_limit,
            VersionedResponse::Electra(data) => data.message.header.gas_limit,
        }
    }

    pub fn pubkey(&self) -> BlsPublicKey {
        match self {
            VersionedResponse::Deneb(data) => data.message.pubkey,
            VersionedResponse::Electra(data) => data.message.pubkey,
        }
    }

    pub fn value(&self) -> U256 {
        match self {
            VersionedResponse::Deneb(data) => data.message.value,
            VersionedResponse::Electra(data) => data.message.value,
        }
    }

    pub fn transactions_root(&self) -> B256 {
        match self {
            GetHeaderResponse::Deneb(data) => data.message.header.transactions_root,
            GetHeaderResponse::Electra(data) => data.message.header.transactions_root,
        }
    }

    pub fn parent_hash(&self) -> B256 {
        match self {
            GetHeaderResponse::Deneb(data) => data.message.header.parent_hash,
            GetHeaderResponse::Electra(data) => data.message.header.parent_hash,
        }
    }

    pub fn signautre(&self) -> BlsSignature {
        match self {
            GetHeaderResponse::Deneb(data) => data.signature,
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
pub struct ExecutionPayloadHeaderMessageDeneb {
    pub header: ExecutionPayloadHeader<DenebSpec>,
    pub blob_kzg_commitments: KzgCommitments<DenebSpec>,
    #[serde(with = "serde_utils::quoted_u256")]
    pub value: U256,
    pub pubkey: BlsPublicKey,
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
    use alloy::primitives::U256;

    use super::*;
    use crate::{
        constants::APPLICATION_BUILDER_DOMAIN,
        pbs::VersionedResponse,
        signature::verify_signed_message,
        types::Chain,
        utils::{test_encode_decode, test_encode_decode_ssz},
    };

    #[test]
    fn test_get_header_deneb() {
        let data = r#"{
            "version": "deneb",
            "data": {
                "message": {
                    "header": {
                        "parent_hash": "0x114d1897fefa402a01a653c21a7f1f1db049d1373a5e73a2d25d7a8045dc02a1",
                        "fee_recipient": "0x1268ad189526ac0b386faf06effc46779c340ee6",
                        "state_root": "0x53ffe6d7d4bbcc5ef71429ce82b3d7bbfffddaed89d53979bf4dca7af0dbe94c",
                        "receipts_root": "0x3d67a1bb141379c352c95126c4dd06a4fe086efdc00b6e919b050c84d79f4df2",
                        "logs_bloom": "0x05440404082f80182749948b189406732c7da48ce83013f11c02562c0d10cc714002025f21c1c64b21293e4c40c5b58e5404aed7922104002008019258ad7020097424e0b01d41eb474dc0cd26c0c9298c640692260452e27104ac808a050a0dc47187f40386108058b301007229b82f0d30bb082c72410043005e32a42c841841184260c0d744a4a9a190840048a4590011e00084ca62a8ce3a030d640350214fbedf09f041823266c491b128800802a200eb1048341000fa810323c4825804643b68ca2301c559881c0e944334c843016e0874010c81009100348a1900e0546014239b02e956940d1408c1824847516850d8de4a110495f3d9a4d8c00808a0",
                        "prev_randao": "0x0fde820be6404bcb71d7bbeee140c16cd28b1940a40fa8a4e2c493114a08b38a",
                        "block_number": "1598034",
                        "gas_limit": "30000000",
                        "gas_used": "21186389",
                        "timestamp": "1716481836",
                        "extra_data": "0x546974616e2028746974616e6275696c6465722e78797a29",
                        "base_fee_per_gas": "1266581747",
                        "block_hash": "0xef2ebdec55b9fa68137c0a3133c0010963bfe1dfbb45139c7d2def06f0591c6b",
                        "transactions_root": "0x6b2db9b2be28599e0bf11b31c9a91c238c190f49072421b3fdb0734117e97b45",
                        "withdrawals_root": "0x2daccf0e476ca3e2644afbd13b2621d55b4d515b813a3b867cdacea24bb352d1",
                        "blob_gas_used": "786432",
                        "excess_blob_gas": "95158272"
                    },
                    "blob_kzg_commitments": [
                        "0xa20c71d1985996098aa63e8b5dc7b7fedb70de31478fe309dad3ac0e9b6d28d82be8e5e543021a0203dc785742e94b2f",
                        "0x94f367b25711d95dda009bdd4b055b8f433dc61a426e5f1ec70688b4c5fdd01c632c7fa4c71688161166f5ec6d90f9c9",
                        "0xb0d6874218fd27607effcd790eeb873d7114b9909942b9e7ccbbb78f02ddcb6f627c7cdfb91b0eb7e3982ba0d0024a2a",
                        "0x9576d096bb8bf8a6184afa070eac8ed92f2209be20b5ea46e2360653a9556d614e5f0779dbd9cedbc8e2933f74433c0c",
                        "0xa20c71d1985996098aa63e8b5dc7b7fedb70de31478fe309dad3ac0e9b6d28d82be8e5e543021a0203dc785742e94b2f",
                        "0xa20c71d1985996098aa63e8b5dc7b7fedb70de31478fe309dad3ac0e9b6d28d82be8e5e543021a0203dc785742e94b2f"
                    ],
                    "value": "4293912964927787",
                    "pubkey": "0xaa58208899c6105603b74396734a6263cc7d947f444f396a90f7b7d3e65d102aec7e5e5291b27e08d02c50a050825c2f"
                },
                "signature": "0x8468517fd5ae1807d6b13a2c91e4d1d12b7249db0c63861095e054dfd801968c61b86ac270ac0dafcf84b486ee628d8e145cba65dcf126000f225d9adfe3e252a59d6e91b7fea9df6b7e6dfbb030567d4405e4522349c8f6eddf0f37afa2619e"
            }
        }"#;

        let parsed = test_encode_decode::<GetHeaderResponse>(&data);
        let VersionedResponse::Deneb(parsed) = parsed else {
            panic!("parsed is not a Deneb response");
        };

        assert_eq!(parsed.message.value, U256::from(4293912964927787u64));

        assert!(verify_signed_message(
            Chain::Holesky,
            &parsed.message.pubkey.into(),
            &parsed.message,
            &parsed.signature,
            APPLICATION_BUILDER_DOMAIN
        )
        .is_ok())
    }

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
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
                },
                "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
            }
        }"#;

        let parsed = test_encode_decode::<GetHeaderResponse>(&data);
        let VersionedResponse::Electra(parsed) = parsed else {
            panic!("parsed is not a Deneb response");
        };

        assert_eq!(parsed.message.value, U256::from(1));
    }

    #[test]
    // this is dummy data generated with https://github.com/attestantio/go-builder-client
    fn test_signed_execution_payload_header_ssz() {
        let data_json = include_str!("testdata/get-header-response.json");
        let block_json = test_encode_decode::<
            SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageElectra>,
        >(&data_json);

        let data_ssz = include_bytes!("testdata/get-header-response.ssz");
        let data_ssz = alloy::primitives::hex::decode(data_ssz).unwrap();
        test_encode_decode_ssz::<SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageElectra>>(
            &data_ssz,
        );

        assert_eq!(block_json.as_ssz_bytes(), data_ssz);
    }
}
