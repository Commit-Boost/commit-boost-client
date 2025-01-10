use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use async_trait::async_trait;
use axum::{http::HeaderMap, Router};
use cb_common::pbs::{
    GetHeaderParams, GetHeaderResponse, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse,
};

use crate::{
    mev_boost,
    state::{BuilderApiState, InnerPbsState, PbsState},
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
        state: InnerPbsState<S>,
    ) -> eyre::Result<Option<GetHeaderResponse>> {
        mev_boost::get_header(params, req_headers, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/status
    async fn get_status(req_headers: HeaderMap, state: InnerPbsState<S>) -> eyre::Result<()> {
        mev_boost::get_status(req_headers, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock
    async fn submit_block(
        signed_blinded_block: SignedBlindedBeaconBlock,
        req_headers: HeaderMap,
        state: InnerPbsState<S>,
    ) -> eyre::Result<SubmitBlindedBlockResponse> {
        mev_boost::submit_block(signed_blinded_block, req_headers, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/registerValidator
    async fn register_validator(
        registrations: Vec<ValidatorRegistration>,
        req_headers: HeaderMap,
        state: InnerPbsState<S>,
    ) -> eyre::Result<()> {
        mev_boost::register_validator(registrations, req_headers, state).await
    }
}

pub struct DefaultBuilderApi;
impl BuilderApi<()> for DefaultBuilderApi {}
