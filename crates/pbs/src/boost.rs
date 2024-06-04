use std::fmt::Debug;

use alloy_primitives::B256;
use alloy_rpc_types_beacon::relay::ValidatorRegistration;
use async_trait::async_trait;
use axum::Router;

use crate::{
    mev_boost,
    state::{BuilderApiState, BuilderState},
    GetHeaderParams, GetHeaderReponse, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse,
};

#[async_trait]
pub trait BuilderApi<S: BuilderApiState>: 'static {
    /// Use to extend the BuilderApi
    fn routes() -> Option<Router<BuilderState<S>>> {
        None
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/getHeader
    async fn get_header(
        params: GetHeaderParams,
        state: BuilderState<S>,
    ) -> eyre::Result<Option<GetHeaderReponse>> {
        mev_boost::get_header(state, params).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/status
    async fn get_status(state: BuilderState<S>) -> eyre::Result<()> {
        mev_boost::get_status(state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock
    async fn submit_block(
        signed_blinded_block: SignedBlindedBeaconBlock,
        state: BuilderState<S>,
    ) -> eyre::Result<SubmitBlindedBlockResponse> {
        mev_boost::submit_block(signed_blinded_block, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/registerValidator
    async fn register_validator(
        registrations: Vec<ValidatorRegistration>,
        state: BuilderState<S>,
    ) -> eyre::Result<()> {
        mev_boost::register_validator(registrations, state).await
    }
}

pub struct DefaultBuilderApi;
impl BuilderApi<()> for DefaultBuilderApi {}

#[derive(Debug, Clone)]
pub enum BuilderEvent {
    GetHeaderRequest(GetHeaderParams),
    GetHeaderResponse(Box<Option<GetHeaderReponse>>),
    GetStatusEvent,
    GetStatusResponse,
    SubmitBlockRequest(Box<SignedBlindedBeaconBlock>),
    SubmitBlockResponse(Box<SubmitBlindedBlockResponse>),
    MissedPayload { block_hash: B256, relays: String },
    RegisterValidatorRequest(Vec<ValidatorRegistration>),
    RegisterValidatorResponse,
}
