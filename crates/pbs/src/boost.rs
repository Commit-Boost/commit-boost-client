use std::fmt::Debug;

use alloy::{primitives::B256, rpc::types::beacon::relay::ValidatorRegistration};
use async_trait::async_trait;
use axum::{http::HeaderMap, Router};

use crate::{
    mev_boost,
    state::{BuilderApiState, PbsState},
    GetHeaderParams, GetHeaderReponse, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse,
};

#[async_trait]
pub trait BuilderApi<S: BuilderApiState>: 'static {
    /// Use to extend the BuilderApi
    fn extra_routes() -> Option<Router<PbsState<S>>> {
        None
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/getHeader
    async fn get_header(
        params: GetHeaderParams,
        req_headers: HeaderMap,
        state: PbsState<S>,
    ) -> eyre::Result<Option<GetHeaderReponse>> {
        mev_boost::get_header(params, req_headers, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/status
    async fn get_status(req_headers: HeaderMap, state: PbsState<S>) -> eyre::Result<()> {
        mev_boost::get_status(req_headers, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock
    async fn submit_block(
        signed_blinded_block: SignedBlindedBeaconBlock,
        req_headers: HeaderMap,
        state: PbsState<S>,
    ) -> eyre::Result<SubmitBlindedBlockResponse> {
        mev_boost::submit_block(signed_blinded_block, req_headers, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/registerValidator
    async fn register_validator(
        registrations: Vec<ValidatorRegistration>,
        req_headers: HeaderMap,
        state: PbsState<S>,
    ) -> eyre::Result<()> {
        mev_boost::register_validator(registrations, req_headers, state).await
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
