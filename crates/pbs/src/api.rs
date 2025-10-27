use std::sync::Arc;

use async_trait::async_trait;
use axum::{Router, http::HeaderMap};
use cb_common::pbs::{
    BuilderApiVersion, GetHeaderParams, GetHeaderResponse, SignedBlindedBeaconBlock,
    SubmitBlindedBlockResponse,
};

use crate::{
    mev_boost,
    state::{BuilderApiState, PbsState, PbsStateGuard},
};

#[async_trait]
pub trait BuilderApi<S: BuilderApiState>: 'static {
    /// Use to extend the BuilderApi
    fn extra_routes() -> Option<Router<PbsStateGuard<S>>> {
        None
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/getHeader
    async fn get_header(
        params: GetHeaderParams,
        req_headers: HeaderMap,
        state: PbsState<S>,
    ) -> eyre::Result<Option<GetHeaderResponse>> {
        mev_boost::get_header(params, req_headers, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/status
    async fn get_status(req_headers: HeaderMap, state: PbsState<S>) -> eyre::Result<()> {
        mev_boost::get_status(req_headers, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock and
    /// https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlockV2
    async fn submit_block(
        signed_blinded_block: Arc<SignedBlindedBeaconBlock>,
        req_headers: HeaderMap,
        state: PbsState<S>,
        api_version: BuilderApiVersion,
    ) -> eyre::Result<Option<SubmitBlindedBlockResponse>> {
        mev_boost::submit_block(signed_blinded_block, req_headers, state, api_version).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/registerValidator
    async fn register_validator(
        registrations: Vec<serde_json::Value>,
        req_headers: HeaderMap,
        state: PbsState<S>,
    ) -> eyre::Result<()> {
        mev_boost::register_validator(registrations, req_headers, state).await
    }

    async fn reload(state: PbsState<S>) -> eyre::Result<PbsState<S>> {
        mev_boost::reload(state).await
    }
}

pub struct DefaultBuilderApi;
impl BuilderApi<()> for DefaultBuilderApi {}
