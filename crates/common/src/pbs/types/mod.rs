use alloy::primitives::{B256, U256, b256};
use lh_types::{BlindedPayload, ExecPayload, MainnetEthSpec};
pub use lh_types::{ForkName, ForkVersionedResponse};
use serde::{Deserialize, Serialize};

use crate::types::BlsPublicKey;

pub const EMPTY_TX_ROOT_HASH: B256 =
    b256!("7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1");

pub type ExecutionRequests = lh_types::execution_requests::ExecutionRequests<MainnetEthSpec>;

/// Request object of POST `/eth/v1/builder/blinded_blocks`
pub type SignedBlindedBeaconBlock =
    lh_types::signed_beacon_block::SignedBlindedBeaconBlock<MainnetEthSpec>;
pub type BlindedBeaconBlock<'a> =
    lh_types::beacon_block::BeaconBlockRef<'a, MainnetEthSpec, BlindedPayload<MainnetEthSpec>>;
pub type BlindedBeaconBlockElectra =
    lh_types::beacon_block::BeaconBlockElectra<MainnetEthSpec, BlindedPayload<MainnetEthSpec>>;
pub type BlindedBeaconBlockFulu =
    lh_types::beacon_block::BeaconBlockFulu<MainnetEthSpec, BlindedPayload<MainnetEthSpec>>;

pub type BlobsBundle = lh_eth2::types::BlobsBundle<MainnetEthSpec>;
pub type PayloadAndBlobs = lh_eth2::types::ExecutionPayloadAndBlobs<MainnetEthSpec>;
/// Response object of POST `/eth/v1/builder/blinded_blocks`
pub type SubmitBlindedBlockResponse = lh_types::ForkVersionedResponse<PayloadAndBlobs>;

pub type ExecutionPayloadHeader = lh_types::ExecutionPayloadHeader<MainnetEthSpec>;
pub type ExecutionPayloadHeaderElectra = lh_types::ExecutionPayloadHeaderElectra<MainnetEthSpec>;
pub type ExecutionPayloadHeaderFulu = lh_types::ExecutionPayloadHeaderFulu<MainnetEthSpec>;
pub type ExecutionPayloadHeaderRef<'a> = lh_types::ExecutionPayloadHeaderRef<'a, MainnetEthSpec>;
pub type ExecutionPayload = lh_types::ExecutionPayload<MainnetEthSpec>;
pub type ExecutionPayloadElectra = lh_types::ExecutionPayloadElectra<MainnetEthSpec>;
pub type ExecutionPayloadFulu = lh_types::ExecutionPayloadFulu<MainnetEthSpec>;
pub type SignedBuilderBid = lh_types::builder_bid::SignedBuilderBid<MainnetEthSpec>;
pub type BuilderBid = lh_types::builder_bid::BuilderBid<MainnetEthSpec>;
pub type BuilderBidElectra = lh_types::builder_bid::BuilderBidElectra<MainnetEthSpec>;

/// Response object of GET
/// `/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}`
pub type GetHeaderResponse = lh_types::ForkVersionedResponse<SignedBuilderBid>;

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

pub trait GetPyloadInfo {
    fn block_hash(&self) -> B256;
    fn block_number(&self) -> u64;
    fn parent_hash(&self) -> B256;
}

impl GetPyloadInfo for SignedBlindedBeaconBlock {
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
