use alloy::{primitives::B256, rpc::types::beacon::BlsSignature};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

use super::{
    blinded_block_body::{BlindedBeaconBlockBodyDeneb, BlindedBeaconBlockBodyElectra},
    blobs_bundle::BlobsBundle,
    execution_payload::ExecutionPayload,
    spec::{DenebSpec, ElectraSpec},
    utils::VersionedResponse,
};

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
/// Sent to relays in submit_block
pub struct SignedBlindedBeaconBlock {
    pub message: BlindedBeaconBlock,
    pub signature: BlsSignature,
}

impl SignedBlindedBeaconBlock {
    pub fn block_hash(&self) -> B256 {
        match &self.message {
            BlindedBeaconBlock::Electra(b) => b.body.execution_payload_header.block_hash,
            BlindedBeaconBlock::Deneb(b) => b.body.execution_payload_header.block_hash,
        }
    }

    pub fn parent_hash(&self) -> B256 {
        match &self.message {
            BlindedBeaconBlock::Electra(b) => b.parent_root,
            BlindedBeaconBlock::Deneb(b) => b.parent_root,
        }
    }

    pub fn slot(&self) -> u64 {
        match &self.message {
            BlindedBeaconBlock::Electra(b) => b.slot,
            BlindedBeaconBlock::Deneb(b) => b.slot,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
pub enum BlindedBeaconBlock {
    Deneb(BlindedBeaconBlockDeneb),
    Electra(BlindedBeaconBlockElectra),
}

impl Default for BlindedBeaconBlock {
    fn default() -> Self {
        Self::Deneb(BlindedBeaconBlockDeneb::default())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct BlindedBeaconBlockDeneb {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body: BlindedBeaconBlockBodyDeneb<DenebSpec>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct BlindedBeaconBlockElectra {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body: BlindedBeaconBlockBodyElectra<ElectraSpec>,
}

/// Returned by relay in submit_block
pub type SubmitBlindedBlockResponse =
    VersionedResponse<PayloadAndBlobsDeneb, PayloadAndBlobsElectra>;

impl SubmitBlindedBlockResponse {
    pub fn block_hash(&self) -> B256 {
        match self {
            VersionedResponse::Deneb(d) => d.block_hash(),
            VersionedResponse::Electra(d) => d.block_hash(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PayloadAndBlobsDeneb {
    pub execution_payload: ExecutionPayload<DenebSpec>,
    pub blobs_bundle: BlobsBundle<DenebSpec>,
}

impl PayloadAndBlobsDeneb {
    pub fn block_hash(&self) -> B256 {
        self.execution_payload.block_hash
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PayloadAndBlobsElectra {
    pub execution_payload: ExecutionPayload<ElectraSpec>,
    pub blobs_bundle: BlobsBundle<ElectraSpec>,
}

impl PayloadAndBlobsElectra {
    pub fn block_hash(&self) -> B256 {
        self.execution_payload.block_hash
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ssz::Encode;

    use super::*;
    use crate::utils::{test_encode_decode, test_encode_decode_ssz};

    #[test]
    // this is from the builder api spec, but with sync_committee_bits fixed to
    // deserialize correctly
    fn test_signed_blinded_block_deneb() {
        let data = include_str!("testdata/signed-blinded-beacon-block-deneb-2.json");
        let block = test_encode_decode::<SignedBlindedBeaconBlock>(&data);
        assert!(matches!(block.message, BlindedBeaconBlock::Deneb(_)));
    }

    #[test]
    // this is from mev-boost test data
    fn test_signed_blinded_block_fb_deneb() {
        let data = include_str!("testdata/signed-blinded-beacon-block-deneb.json");
        let block = test_encode_decode::<SignedBlindedBeaconBlock>(&data);
        assert!(matches!(block.message, BlindedBeaconBlock::Deneb(_)));
    }

    #[test]
    // this is from mev-boost test data
    fn test_signed_blinded_block_fb_electra() {
        let data = include_str!("testdata/signed-blinded-beacon-block-electra.json");
        let block = test_encode_decode::<SignedBlindedBeaconBlock>(&data);
        assert!(matches!(block.message, BlindedBeaconBlock::Electra(_)));
    }

    #[test]
    // this is from the builder api spec, but with blobs fixed to deserialize
    // correctly
    fn test_submit_blinded_block_response_deneb() {
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

        let block = test_encode_decode::<SubmitBlindedBlockResponse>(&data);
        assert!(matches!(block, SubmitBlindedBlockResponse::Deneb(_)));
    }

    #[test]
    // this is dummy data generated with https://github.com/attestantio/go-eth2-client
    fn test_signed_blinded_block_ssz() {
        let data_json = include_str!("testdata/signed-blinded-beacon-block-electra-2.json");
        let block_json = test_encode_decode::<SignedBlindedBeaconBlock>(&data_json);
        assert!(matches!(block_json.message, BlindedBeaconBlock::Electra(_)));

        let data_ssz = include_bytes!("testdata/signed-blinded-beacon-block-electra-2.ssz");
        let data_ssz = alloy::primitives::hex::decode(data_ssz).unwrap();
        let block_ssz = test_encode_decode_ssz::<SignedBlindedBeaconBlock>(&data_ssz);
        assert!(matches!(block_ssz.message, BlindedBeaconBlock::Electra(_)));

        assert_eq!(block_json.as_ssz_bytes(), data_ssz);
    }

    #[test]
    // this is dummy data generated with https://github.com/attestantio/go-builder-client
    fn test_execution_payload_block_ssz() {
        let data_json = include_str!("testdata/execution-payload-deneb.json");
        let block_json = test_encode_decode::<PayloadAndBlobsDeneb>(&data_json);

        let data_ssz = include_bytes!("testdata/execution-payload-deneb.ssz");
        let data_ssz = alloy::primitives::hex::decode(data_ssz).unwrap();
        test_encode_decode_ssz::<PayloadAndBlobsDeneb>(&data_ssz);

        assert_eq!(block_json.as_ssz_bytes(), data_ssz);

        // electra and deneb have the same execution payload

        let data_json = include_str!("testdata/execution-payload-deneb.json");
        let block_json = test_encode_decode::<PayloadAndBlobsElectra>(&data_json);

        let data_ssz = include_bytes!("testdata/execution-payload-deneb.ssz");
        let data_ssz = alloy::primitives::hex::decode(data_ssz).unwrap();
        test_encode_decode_ssz::<PayloadAndBlobsElectra>(&data_ssz);

        assert_eq!(block_json.as_ssz_bytes(), data_ssz);
    }
}
