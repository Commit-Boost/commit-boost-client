use alloy::primitives::{Address, B256, U256, b256};
pub use lh_eth2::ForkVersionedResponse;
pub use lh_types::ForkName;
use lh_types::{BlindedPayload, ExecPayload, MainnetEthSpec, Slot};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

use crate::types::{BlsPublicKey, BlsSignature};

pub const EMPTY_TX_ROOT_HASH: B256 =
    b256!("7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1");

pub type ExecutionRequests = lh_types::ExecutionRequests<MainnetEthSpec>;

/// Request object of POST `/eth/v1/builder/blinded_blocks`
pub type SignedBlindedBeaconBlock = lh_types::SignedBlindedBeaconBlock<MainnetEthSpec>;
/// Request object of POST `/eth/v1/builder/beacon_blocks` (Gloas onwards)
pub type SignedBeaconBlock = lh_types::SignedBeaconBlock<MainnetEthSpec>;
pub type BlindedBeaconBlock<'a> =
    lh_types::BeaconBlockRef<'a, MainnetEthSpec, BlindedPayload<MainnetEthSpec>>;
pub type BlindedBeaconBlockElectra =
    lh_types::BeaconBlockElectra<MainnetEthSpec, BlindedPayload<MainnetEthSpec>>;
pub type BlindedBeaconBlockFulu =
    lh_types::BeaconBlockFulu<MainnetEthSpec, BlindedPayload<MainnetEthSpec>>;

pub type BlobsBundle = lh_eth2::types::BlobsBundle<MainnetEthSpec>;
pub type PayloadAndBlobs = lh_eth2::types::ExecutionPayloadAndBlobs<MainnetEthSpec>;
/// Response object of POST `/eth/v1/builder/blinded_blocks`
pub type SubmitBlindedBlockResponse = ForkVersionedResponse<PayloadAndBlobs>;

pub type ExecutionPayloadHeader = lh_types::ExecutionPayloadHeader<MainnetEthSpec>;
pub type ExecutionPayloadHeaderBellatrix =
    lh_types::ExecutionPayloadHeaderBellatrix<MainnetEthSpec>;
pub type ExecutionPayloadHeaderCapella = lh_types::ExecutionPayloadHeaderCapella<MainnetEthSpec>;
pub type ExecutionPayloadHeaderDeneb = lh_types::ExecutionPayloadHeaderDeneb<MainnetEthSpec>;
pub type ExecutionPayloadHeaderElectra = lh_types::ExecutionPayloadHeaderElectra<MainnetEthSpec>;
pub type ExecutionPayloadHeaderFulu = lh_types::ExecutionPayloadHeaderFulu<MainnetEthSpec>;
pub type ExecutionPayloadHeaderRef<'a> = lh_types::ExecutionPayloadHeaderRef<'a, MainnetEthSpec>;
pub type ExecutionPayload = lh_types::ExecutionPayload<MainnetEthSpec>;
pub type ExecutionPayloadElectra = lh_types::ExecutionPayloadElectra<MainnetEthSpec>;
pub type ExecutionPayloadFulu = lh_types::ExecutionPayloadFulu<MainnetEthSpec>;
pub type SignedBuilderBid = lh_types::SignedBuilderBid<MainnetEthSpec>;
pub type BuilderBid = lh_types::BuilderBid<MainnetEthSpec>;
pub type BuilderBidBellatrix = lh_types::BuilderBidBellatrix<MainnetEthSpec>;
pub type BuilderBidCapella = lh_types::BuilderBidCapella<MainnetEthSpec>;
pub type BuilderBidDeneb = lh_types::BuilderBidDeneb<MainnetEthSpec>;
pub type BuilderBidElectra = lh_types::BuilderBidElectra<MainnetEthSpec>;
pub type BuilderBidFulu = lh_types::BuilderBidFulu<MainnetEthSpec>;

/// Response object of GET
/// `/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}`
pub type GetHeaderResponse = ForkVersionedResponse<SignedBuilderBid>;

pub type KzgCommitments = lh_types::KzgCommitments<MainnetEthSpec>;

/// Response params of GET
/// `/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}`
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetHeaderParams {
    /// The slot to request the header for
    pub slot: u64,
    /// The parent hash of the block to request the header for
    pub parent_hash: B256,
    /// The pubkey of the validator that is requesting the header
    pub pubkey: BlsPublicKey,
}

pub type ExecutionPayloadBid = lh_types::ExecutionPayloadBid<MainnetEthSpec>;
pub type SignedExecutionPayloadBid = lh_types::SignedExecutionPayloadBid<MainnetEthSpec>;

/// Whether `block` is a Gloas block. The submit endpoint is Gloas-only per
/// spec.
pub fn is_gloas(block: &SignedBeaconBlock) -> bool {
    matches!(block, lh_types::SignedBeaconBlock::Gloas(_))
}

/// Response object of POST
/// `/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash}/{parent_root}/
/// {proposer_pubkey}`
pub type GetExecutionPayloadBidResponse = ForkVersionedResponse<SignedExecutionPayloadBid>;

pub trait GetExecutionPayloadBidInfo {
    fn block_hash(&self) -> B256;
    fn parent_hash(&self) -> B256;
    fn parent_root(&self) -> B256;
    fn value(&self) -> u64;
    fn execution_payment(&self) -> u64;
    fn fee_recipient(&self) -> Address;
    fn builder_index(&self) -> u64;
    fn slot(&self) -> u64;
    fn gas_limit(&self) -> u64;
}

impl GetExecutionPayloadBidInfo for GetExecutionPayloadBidResponse {
    fn block_hash(&self) -> B256 {
        self.data.message.block_hash.0
    }

    fn parent_hash(&self) -> B256 {
        self.data.message.parent_block_hash.0
    }

    fn parent_root(&self) -> B256 {
        self.data.message.parent_block_root
    }

    fn value(&self) -> u64 {
        self.data.message.value
    }

    fn execution_payment(&self) -> u64 {
        self.data.message.execution_payment
    }

    fn fee_recipient(&self) -> Address {
        self.data.message.fee_recipient
    }

    fn builder_index(&self) -> u64 {
        self.data.message.builder_index
    }

    fn slot(&self) -> u64 {
        self.data.message.slot.as_u64()
    }

    fn gas_limit(&self) -> u64 {
        self.data.message.gas_limit
    }
}

/// Path params of POST
/// `/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash}/{parent_root}/
/// {proposer_pubkey}`
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetExecutionPayloadBidParams {
    /// The slot for which the block should be proposed.
    pub slot: u64,
    /// The hash of the execution layer block the proposer will build on.
    pub parent_hash: B256,
    /// The root of the beacon block the proposer will build on.
    pub parent_root: B256,
    /// The public key of the proposer
    pub proposer_pubkey: BlsPublicKey,
}

pub trait GetHeaderInfo {
    fn block_hash(&self) -> B256;
    fn value(&self) -> &U256;
    fn block_number(&self) -> u64;
    fn gas_limit(&self) -> u64;
}

impl GetHeaderInfo for GetHeaderResponse {
    fn block_hash(&self) -> B256 {
        self.data.message.header().block_hash().0
    }

    fn value(&self) -> &U256 {
        self.data.message.value()
    }

    fn block_number(&self) -> u64 {
        self.data.message.header().block_number()
    }

    fn gas_limit(&self) -> u64 {
        self.data.message.header().gas_limit()
    }
}

pub trait GetPayloadInfo {
    fn block_hash(&self) -> B256;
    fn block_number(&self) -> u64;
    fn parent_hash(&self) -> B256;
}

impl GetPayloadInfo for SignedBlindedBeaconBlock {
    fn block_hash(&self) -> B256 {
        // Block hash is only missing for Base and Altair forks
        self.message().body().execution_payload().map(|r| r.block_hash().0).unwrap_or_default()
    }

    fn block_number(&self) -> u64 {
        self.message().body().execution_payload().map(|r| r.block_number()).unwrap_or_default()
    }

    fn parent_hash(&self) -> B256 {
        self.message().body().execution_payload().map(|r| r.parent_hash().0).unwrap_or_default()
    }
}

#[allow(non_camel_case_types)]
pub type MAX_DATA_SIZE = typenum::U4096;

// `RequestAuth` is used to authenticate requests to a builder. This is useful
// so that other builders do not DDOS or run replay attacks on the builder.
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone, TreeHash)]
pub struct RequestAuth {
    /// Opaque authentication data agreed with the builder out of band; hex
    /// string on the JSON wire
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub data: VariableList<u8, MAX_DATA_SIZE>,
    pub slot: Slot,
}

// `SignedRequestAuth`
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct SignedRequestAuth {
    pub message: RequestAuth,
    pub signature: BlsSignature,
}

/// Per-builder preferences a proposer submits ahead of the bid request.
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct BuilderPreferences {
    /// Maximum execution-layer payment, in Gwei, this proposer will accept from
    /// this builder; quoted string on the JSON wire
    #[serde(with = "serde_utils::quoted_u64")]
    pub max_execution_payment: u64,
}

/// The `submitBuilderPreferences` request body.
/// SSZ field order `(preferences, auth)` per builder-specs
/// `types/gloas/builder_preferences.yaml`.
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct BuilderPreferencesRequest {
    pub preferences: BuilderPreferences,
    pub auth: SignedRequestAuth,
}

/// Path params for `POST /eth/v1/builder/builder_preferences/{proposer_pubkey}`
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubmitBuilderPreferencesParams {
    /// The public key of the proposer expressing these preferences
    pub proposer_pubkey: BlsPublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `data` is an opaque hex STRING on the wire
    #[test]
    fn test_request_auth_data_serializes_as_hex() {
        let auth = SignedRequestAuth {
            message: RequestAuth {
                data: VariableList::new(vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef])
                    .unwrap(),
                slot: Slot::new(100),
            },
            signature: BlsSignature::empty(),
        };
        let json = serde_json::to_value(&auth).unwrap();
        assert_eq!(json["message"]["data"], "0x1234567890abcdef");
        assert_eq!(json["message"]["slot"], "100");
    }

    /// Round-trip the spec's wire shape back into the struct
    #[test]
    fn test_request_auth_deserializes_spec_json() {
        let json = r#"{
            "message": {
                "data": "0x1234567890abcdef",
                "slot": "100"
            },
            "signature": "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        }"#;
        let auth: SignedRequestAuth = serde_json::from_str(json).unwrap();
        assert_eq!(auth.message.data.to_vec(), vec![
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
        ]);
        assert_eq!(auth.message.slot, Slot::new(100));
    }

    /// Spec vector for the SSZ layout of `BuilderPreferencesRequest`:
    /// `(preferences, auth)` per builder-specs
    /// `types/gloas/builder_preferences.yaml`. The order-determining fixed
    /// part is cross-checked byte-for-byte against the canonical example
    /// `examples/gloas/builder_preferences_request.ssz`.
    #[test]
    fn test_builder_preferences_request_ssz_spec_vector() {
        use ssz::{Decode, Encode};

        // The infinity signature: 0xc0 followed by 95 zero bytes
        let mut infinity_sig = vec![0u8; 96];
        infinity_sig[0] = 0xc0;

        let auth = SignedRequestAuth {
            message: RequestAuth {
                data: VariableList::new(vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef])
                    .unwrap(),
                slot: Slot::new(1234),
            },
            signature: BlsSignature::deserialize(&infinity_sig).unwrap(),
        };
        let request = BuilderPreferencesRequest {
            preferences: BuilderPreferences { max_execution_payment: 1_000_000_000 },
            auth: auth.clone(),
        };

        // Outer container is `(preferences, auth)`: the 8-byte fixed
        // `max_execution_payment` LE, then a 4-byte offset to the variable-size
        // `auth` (12 = 8-byte fixed `preferences` + 4-byte offset), then `auth`.
        let auth_bytes = auth.as_ssz_bytes();
        let mut expected = Vec::new();
        expected.extend_from_slice(&1_000_000_000u64.to_le_bytes());
        expected.extend_from_slice(&12u32.to_le_bytes());
        expected.extend_from_slice(&auth_bytes);

        assert_eq!(request.as_ssz_bytes(), expected);

        // The fixed part matches the canonical spec example byte-for-byte:
        // `max_execution_payment` (1_000_000_000 Gwei LE) precedes the `auth`
        // offset (12). A `(auth, preferences)` layout would put the offset first.
        assert_eq!(&request.as_ssz_bytes()[..12], &[
            0x00, 0xca, 0x9a, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
        ]);

        let decoded = BuilderPreferencesRequest::from_ssz_bytes(&expected).unwrap();
        assert_eq!(decoded.preferences.max_execution_payment, 1_000_000_000);
        assert_eq!(decoded.auth.message.slot, Slot::new(1234));
        assert_eq!(decoded.auth.message.data.to_vec(), vec![
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
        ]);
        assert_eq!(decoded.auth.signature.serialize().to_vec(), infinity_sig);
    }
}
