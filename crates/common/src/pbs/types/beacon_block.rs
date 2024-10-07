use alloy::{primitives::B256, rpc::types::beacon::BlsSignature};
use serde::{Deserialize, Serialize};

use super::{
    blinded_block_body::BlindedBeaconBlockBody, blobs_bundle::BlobsBundle,
    execution_payload::ExecutionPayload, spec::DenebSpec, utils::VersionedResponse,
};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
/// Sent to relays in submit_block
pub struct SignedBlindedBeaconBlock {
    pub message: BlindedBeaconBlock,
    pub signature: BlsSignature,
}

impl SignedBlindedBeaconBlock {
    pub fn block_hash(&self) -> B256 {
        self.message.body.execution_payload_header.block_hash
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BlindedBeaconBlock {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body: BlindedBeaconBlockBody<DenebSpec>,
}

/// Returned by relay in submit_block
pub type SubmitBlindedBlockResponse = VersionedResponse<PayloadAndBlobs>;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PayloadAndBlobs {
    pub execution_payload: ExecutionPayload<DenebSpec>,
    pub blobs_bundle: Option<BlobsBundle<DenebSpec>>,
}

impl SubmitBlindedBlockResponse {
    pub fn block_hash(&self) -> B256 {
        self.data.execution_payload.block_hash
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{SignedBlindedBeaconBlock, SubmitBlindedBlockResponse};
    use crate::utils::test_encode_decode;

    #[test]
    // this is from the builder api spec, but with sync_committee_bits fixed to
    // deserialize correctly
    fn test_signed_blinded_block() {
        let data = r#"{
        "message": {
          "slot": "1",
          "proposer_index": "1",
          "parent_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
          "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
          "body": {
            "randao_reveal": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
            "eth1_data": {
              "deposit_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "deposit_count": "1",
              "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
            },
            "graffiti": "0xdeadbeefc0ffeedeadbeefc0ffeedeadbeefc0ffeedeadbeefc0ffeedeadbeef",
            "proposer_slashings": [
              {
                "signed_header_1": {
                  "message": {
                    "slot": "1",
                    "proposer_index": "1",
                    "parent_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "body_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                  },
                  "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
                },
                "signed_header_2": {
                  "message": {
                    "slot": "1",
                    "proposer_index": "1",
                    "parent_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "body_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                  },
                  "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
                }
              }
            ],
            "attester_slashings": [
              {
                "attestation_1": {
                  "attesting_indices": [
                    "1"
                  ],
                  "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
                  "data": {
                    "slot": "1",
                    "index": "1",
                    "beacon_block_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "source": {
                      "epoch": "1",
                      "root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                    },
                    "target": {
                      "epoch": "1",
                      "root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                    }
                  }
                },
                "attestation_2": {
                  "attesting_indices": [
                    "1"
                  ],
                  "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
                  "data": {
                    "slot": "1",
                    "index": "1",
                    "beacon_block_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "source": {
                      "epoch": "1",
                      "root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                    },
                    "target": {
                      "epoch": "1",
                      "root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                    }
                  }
                }
              }
            ],
            "attestations": [
              {
                "aggregation_bits": "0x01",
                "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
                "data": {
                  "slot": "1",
                  "index": "1",
                  "beacon_block_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                  "source": {
                    "epoch": "1",
                    "root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                  },
                  "target": {
                    "epoch": "1",
                    "root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                  }
                }
              }
            ],
            "deposits": [
              {
                "proof": [
                  "0xeeffb6c21a01d3abf09cd6c56e5d48f5ea0fc3bb0de906e3beea3e73776329cb",
                  "0x601c3b24a99d023224d50811bed19449890febb719a31d09ac414c4632f3c0ba",
                  "0xbb5e485e0a366e16510de33731d71204ad2fe0f7c600861fc2ac4685212c34e3",
                  "0x0006964745296a3e6ebf3954a1541e73205f1eefaddfc48ca9dc856bf159bca2",
                  "0x2c6020f1f9712b89f59550aec05b7c23cb1b113762399c0ca5b8fdd2fa85ce57",
                  "0x1c15634783e1d9d2cb969da66fd72cafca5026191d911b83211318d183c5ea59",
                  "0xdfbdf99a1fde57899df1545be1f91bc8a8a9f46c4bac619e28e92aff276de41f",
                  "0xfe9b0f0c05fde6bd26ce63d394058844ad4451f70b6d2547f49c5c2a5c7891a1",
                  "0x165f84ee467d18dbafdb07275dc42fb988ab696b0a7ad94c52f4d7a27144b994",
                  "0x506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1",
                  "0xecdbe5e5056b968aa726a08f1aa33f5d41540eed42f59ace020431cf38a5144e",
                  "0xc4498c5eb1feeb0b225a3f332bdf523dbc013a5b336a851fce1c055b4019a457",
                  "0xb7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f",
                  "0x8a9b66ad79116c9fc6eed14bde76e8f486669e59b0b5bb0c60a6b3caea38b83d",
                  "0x267c5455e4806b5d0ad5573552d0162e0983595bac25dacd9078174a2766643a",
                  "0x27e0c6357985de4d6026d6da14f31e8bfe14524056fec69dc06d6f8a239344af",
                  "0xf8455aebc24849bea870fbcef1235e2d27c8fd27db24e26d30d0173f3b207874",
                  "0xaba01bf7fe57be4373f47ff8ea6adc4348fab087b69b2518ce630820f95f4150",
                  "0xd47152335d9460f2b6fb7aba05ced32a52e9f46659ccd3daa2059661d75a6308",
                  "0xf893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f",
                  "0xcddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa",
                  "0x8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c",
                  "0xfeb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167",
                  "0xe71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7",
                  "0x31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0",
                  "0x21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544",
                  "0x619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765",
                  "0x7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4",
                  "0x848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1",
                  "0x8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636",
                  "0xb5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c",
                  "0x985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7",
                  "0xf7ed070000000000000000000000000000000000000000000000000000000000"
                ],
                "data": {
                  "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                  "withdrawal_credentials": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                  "amount": "1",
                  "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
                }
              }
            ],
            "voluntary_exits": [
              {
                "message": {
                  "epoch": "1",
                  "validator_index": "1"
                },
                "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
              }
            ],
            "sync_aggregate": {
              "sync_committee_bits": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
              "sync_committee_signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
            },
            "execution_payload_header": {
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
            "bls_to_execution_changes": [
              {
                "message": {
                  "validator_index": "1",
                  "from_bls_pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                  "to_execution_address": "0xabcf8e0d4e9587369b2301d0790347320302cc09"
                },
                "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
              }
            ],
            "blob_kzg_commitments": [
              "0xa94170080872584e54a1cf092d845703b13907f2e6b3b1c0ad573b910530499e3bcd48c6378846b80d2bfa58c81cf3d5"
            ]
          }
        },
        "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
      }"#;

        test_encode_decode::<SignedBlindedBeaconBlock>(&data);
    }

    #[test]
    // this is from mev-boost test data
    fn test_signed_blinded_block_fb() {
        let data = r#"{
          "message": {
            "slot": "348241",
            "proposer_index": "35822",
            "parent_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
            "state_root": "0x4f6e0857501da4ab1d72f0c122869e1c084e16daa96613b64914aada28d0dc28",
            "body": {
              "randao_reveal": "0xb2b7d2e89bb4a4aa6a377972651bb9041cb59af8eedd19568d699fc0866189d3fd78cc93c0e63877b7e2bd6d34d1597c0afd4508aa99b6e882c2cb1ac6f424adba29afd46d1737124300ad72177715fcce8584dd25a06c45bfe9a8ccabd6175d",
              "eth1_data": {
                "deposit_root": "0x704964a5ad034a440f4f29ff1875986db66adbca45dc0014e439349c7e10194f",
                "deposit_count": "4933",
                "block_hash": "0x9c69de2814a7c3e3751654511372937627dacc3187bf457892789f3f5533c794"
              },
              "graffiti": "0x74656b752d626573750000000000000000000000000000000000000000000000",
              "proposer_slashings": [],
              "attester_slashings": [],
              "attestations": [
                {
                  "aggregation_bits": "0xffffffffffffffffffffffffffffff5fff",
                  "data": {
                    "slot": "348240",
                    "index": "7",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0x92da7bf78eb364219f85af2388d7ac7ddbea1934786d75875486ec9fceb310eee131dcfea131bdf4593d3c431b31b2900bb48ebb7ab02e17524d86a4e132883246df8ce427e935dd9e20c422cdf8eb135b3cc45b86fe4c2f592fb4899eb22f7c"
                },
                {
                  "aggregation_bits": "0xffdffffffffffff5fffffffffffffffffd",
                  "data": {
                    "slot": "348240",
                    "index": "3",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0x88cce1f9fbf651e52a6ab71dea2f4025702021744aac90fb2997f82bac6c192e295ae39b2a430546cb102bf8b68f687e0f40a5179bc293e1424e37d694ef1ad6b3b8de72a0e7fbbe97aeafe6f47e949d415381fbbb090e3135224d5b324eefcb"
                },
                {
                  "aggregation_bits": "0xffffffffffefffffffffbfffff7fffdfff",
                  "data": {
                    "slot": "348240",
                    "index": "11",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0x82186d946dfde2ab3b5fcf5bd858fadeec7fa9729f28527e209d16a1d9b4d635558cad6f8de8cee12caa2a4fc5459fb911ca17cbbecfd22e83c82e244ad7a8c8c849a1e03ee88bf0d338c633c2acfefd142574897cd78f9076b69f6e370e3751"
                },
                {
                  "aggregation_bits": "0xfffdffffffffffffffffffffffffffffff",
                  "data": {
                    "slot": "348240",
                    "index": "4",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0xb9c5ee50f800fe2619d1d0fe46a2fb00a64bcf2613e46a40b579ce6a39c4f6cd71a46790757ccc3df8f5f82e34c77c8d084f525ea8a4bd5bd10190496644be0740ace3d217e43af15229a8023d58e583cfec849fab10169225444f4f4ecc66a8"
                },
                {
                  "aggregation_bits": "0xffffffffeffffffffffffdffffffffffff",
                  "data": {
                    "slot": "348240",
                    "index": "12",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0x91e4ee5c0d6bb54d6856cee653c6859f635cebf9c51bef524d6f439cf6d1c69bea5fcb3e4c067c178cfa4518a76baba909b18189a864f38020f44b2cd5223a11e42d58aaedfa2f004710a72a704357874850842a1493017eca6e473d01395932"
                },
                {
                  "aggregation_bits": "0xffffffffffffffffffffffffffffffffff",
                  "data": {
                    "slot": "348240",
                    "index": "13",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0x8c376c5bb5ada745ba8cb8ce2aae103f4e3f85549ceaacaf312b1fa8e6d2ee5232149a926dcfd58ffa1f50f710eb4edc10943bbd40a601f2fb4d53104a59c0663a397744b59f1fa0744bba49f22afc3bab47045ebb42e61dac41ad44c6bf28f4"
                },
                {
                  "aggregation_bits": "0xfffffffffffffffffffffffffffeffffff",
                  "data": {
                    "slot": "348240",
                    "index": "1",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0xaf11c64ce957f2a1686d12b07d0fbc170d89e48490e326cd73ef761ba042bddc01e48e5fc39953c6113df0a989d75e750d5b9d75155259508c2bbdd53903967f893e24f2f7f751f4a05b0fb1cb2b9084ce8543690a8a623599308d6c190fca4a"
                },
                {
                  "aggregation_bits": "0xfffffff5fffffffffdfffbbffffff7ffff",
                  "data": {
                    "slot": "348240",
                    "index": "6",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0x91075da401796a4341ab9a850ff330c9b0d996ca12b9970ec15a4b40fee652edd043e0c9f9d81529621b3a7970e676f619d7a39af67bf193af4441b5447f199f02d75a26c32181569cddc0a237b7064971539f80811fe40e9362d4d9242404ed"
                },
                {
                  "aggregation_bits": "0xfffffffdfffffffffffffdfffffeffffff",
                  "data": {
                    "slot": "348240",
                    "index": "0",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0xad9aa5aa9b9c022036fbb81a0aca626b19a2ccd7c7ee6efa5b2a454f5ffb5d75d00e5563b31319b3a0ad1e0ef6f512be00fb8c39243004a1133610344473953dfcf06c3bd53f00255de6983927acd8624b0131fe9d8a085062747d70972b4713"
                },
                {
                  "aggregation_bits": "0xffffffffffff7fdfffffffffffffffffff",
                  "data": {
                    "slot": "348240",
                    "index": "2",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0x89dde857bc31a4cc5e71d6cc440c00b2b1ee85b758722aadc5c4da0a939523de7532aabcfef4e80f84094924bb69d80d0a3d702b85859c5fce0433b6d0f7bc302af866ef7a9234a75be7bbd91b32256126808ffdf65ac0ce07a33afbaa16c575"
                },
                {
                  "aggregation_bits": "0xffffffffffffffffffffffffffffffffff",
                  "data": {
                    "slot": "348240",
                    "index": "8",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0x891fbba500eee2cf2f5734d3bf8445e8684376e47469692d44e87fc8a295616d9f29410afc2d6ff2bc649618b33b417e13de4e152099aac054f4d35df4cd79234b6df1edcf2393b7ebc0f2ecf61f4604232b96830e0dbff9311408dad4479667"
                },
                {
                  "aggregation_bits": "0xfffffffffffbffffffffefffffffff5fff",
                  "data": {
                    "slot": "348240",
                    "index": "14",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0xb9ab0354d0d61eb6b5f2184dc3bd0c8416cca74f2c913c6aaca653a87dd2c4b8ba2471aa450e0fa170573637c49dc8920eb84970fea4230d7b3c3c8c8152c782e912b29bc19a6de05dc36c1b44db2f649f31673b4751e1b22f17021833ca9cc8"
                },
                {
                  "aggregation_bits": "0xfffffebffffbf7ffeffffbffffffffffff",
                  "data": {
                    "slot": "348240",
                    "index": "5",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0x8e17aa835e6343f708e73e432b7268741f60565f5bb6ef62b5fba892438ca5474a14c0382609e14624058f3fab120e8902ad3f667cf14418836ce120f3bbf50ea3c15923c881e599227cc3a2758ef9a2cd08bd3b862bd711a875e27477ac347c"
                },
                {
                  "aggregation_bits": "0xfffffffffffefffffffffffeffffffffff",
                  "data": {
                    "slot": "348240",
                    "index": "10",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0xa0909f67a7745300cee6278605e3cb79e5a9564cd6e81ac379b285e0eb6e1849537326b546079d7bf676c8e33a166cad00ab74a396f12c9f4851fb64612f6aeb911db550e0aeae88e1b90831a5a858ae64f9262f67403327d85fcb345df9fca4"
                },
                {
                  "aggregation_bits": "0xffffffffffffffffffffffffffffffffff",
                  "data": {
                    "slot": "348240",
                    "index": "9",
                    "beacon_block_root": "0x15bd2273ad32344e34f842fc77ad8acb2a2eaedafa6e5328ef799babfe81113d",
                    "source": {
                      "epoch": "10881",
                      "root": "0x12a21e7bb91e09dac76d5d3f170db6358785032f10b9130a1e92e6f4409f2ecf"
                    },
                    "target": {
                      "epoch": "10882",
                      "root": "0x1c8a9a3a0d4c9d72a93b9ff2ea442a986f4d6dfde52953e48a146206393e7708"
                    }
                  },
                  "signature": "0x886d038ddd7598cfda720dfe1caf83e030e24b207bbc0c97d012fbf5accbaa2f63366f32fe643aa1fdf6c8282480cd51165710bb786d77ecfb72ef7cc9d55e342c94fb57f5a75d50a0d486ecdf014bb08e0195f24202911c86efb5b46b2167ab"
                }
              ],
              "deposits": [],
              "voluntary_exits": [],
              "sync_aggregate": {
                "sync_committee_bits": "0xffffffffffffffffffff7edfffffffff7ffffffffffffffffffffffffffff7ffdf7ffffffff7fffffefffffffffffffbfffffffffdffffffffffffffffffffff",
                "sync_committee_signature": "0x877de19f5fff89de5af36954d4c7f7f5c2ccf6f8dc39fe7e3eb87c3357fca26f0af747dffd0f992c8844a20763e9f8a51858d0be70ce610055c6421d340160adec0ddcb706a7d7a5c45edff7b5f9b9a039fce093cea41c7a5699834f9de48b94"
              },
              "execution_payload_header": {
                "parent_hash": "0xa330251430b91a6fb5342f30a1f527dc76499c03a411464235951dbd51b94d9f",
                "fee_recipient": "0xf97e180c050e5ab072211ad2c213eb5aee4df134",
                "state_root": "0x079f2cc22a29388fd4fc20f451cbaa3ff39845d68b2c368ff7be314617418e38",
                "receipts_root": "0xed980a4cf6df8ba330c14ed9fe0597ec20515f44e5a9adfd2f7b72aa14890996",
                "logs_bloom": "0x0000000400000008000008000040000000000000000000001000104880000200000004000000400000000204000020002000000000000000000000000022000800000004000000000002000c000000000000000000000100000000000000000000000000000000000000000000000040000000000040000001000014000000010002104000000000000000000000000000000000000000000000000000000080020000000000000000002400000000000001000000000002000200102000000040100002000000000000000000000000000000000000000800000000000000000010000000000000000000000000000000000400002000000000000000200000",
                "prev_randao": "0x86cc02ef030b0c147321a7f94158c1b33cb730f8baac3c59955b983fda3ae39b",
                "block_number": "330714",
                "gas_limit": "30000000",
                "gas_used": "369098",
                "timestamp": "1679442492",
                "extra_data": "0x",
                "base_fee_per_gas": "7",
                "block_hash": "0x4ab1ced57222819bf6a6b6c1456715011585599a1cef18b060eb364811bbb14e",
                "transactions_root": "0x6d47bae3b4963cbde00ec39bbd6442540afe26f8005e73722489904836008bfc",
                "withdrawals_root": "0x5dc5f3ff8bade8e1dd04e5cf56292b2a194a2829e1c8e8b4a627d95e08296ba3",
                "blob_gas_used": "4438756708366371443",
                "excess_blob_gas": "12504111653614393862"
              },
              "bls_to_execution_changes": [],
              "blob_kzg_commitments": [
                "0x95cc5099bbd8420d8ebade383c00a2346dace60a7604f768cd71501757b4d72eeb7d5474a6b615af10379d69aa9f478f",
                "0xae9f2d2217013ef61f995f9074faead9ec24e8048440164ec3d6029b87d43686dd0c97c2df9554fc997d0d66c3a78929"
              ]
            }
          },
          "signature": "0x8c3095fd9d3a18e43ceeb7648281e16bb03044839dffea796432c4e5a1372bef22c11a98a31e0c1c5389b98cc6d45917170a0f1634bcf152d896f360dc599fabba2ec4de77898b5dff080fa1628482bdbad5b37d2e64fea3d8721095186cfe50"
        }"#;

        test_encode_decode::<SignedBlindedBeaconBlock>(&data);
    }

    #[test]
    // this is from the builder api spec, but with blobs fixed to deserialize
    // correctly
    fn test_submit_blinded_block_response() {
        let blob = alloy::primitives::hex::encode_prefixed([1; 131072]);

        let data = json!({
          "version": "deneb",
          "data": {
            "execution_payload": {
              "parent_hash":
        "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
              "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "receipts_root":
        "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "logs_bloom":
        "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ,       "prev_randao":
        "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "block_number": "1",
              "gas_limit": "1",
              "gas_used": "1",
              "timestamp": "1",
              "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "base_fee_per_gas": "1",
              "blob_gas_used": "1",
              "excess_blob_gas": "1",
              "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "transactions": [
                "0x02f878831469668303f51d843b9ac9f9843b9aca0082520894c93269b73096998db66be0441e836d873535cb9c8894a19041886f000080c001a031cc29234036afbf9a1fb9476b463367cb1f957ac0b919b69bbc798436e604aaa018c4e9c3914eb27aadd0b91e10b18655739fcf8c1fc398763a9f1beecb8ddc86"
              ],
              "withdrawals": [
                {
                  "index": "1",
                  "validator_index": "1",
                  "address": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                  "amount": "32000000000"
                }
              ]
            },
            "blobs_bundle": {
              "commitments": [
                "0x8dab030c51e16e84be9caab84ee3d0b8bbec1db4a0e4de76439da8424d9b957370a10a78851f97e4b54d2ce1ab0d686f"
              ],
              "proofs": [
                "0xb4021b0de10f743893d4f71e1bf830c019e832958efd6795baf2f83b8699a9eccc5dc99015d8d4d8ec370d0cc333c06a"
              ],
              "blobs": [
                blob
              ]
            }
          }
        }).to_string();

        test_encode_decode::<SubmitBlindedBlockResponse>(&data);
    }
}
