use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use async_trait::async_trait;
use axum::{http::HeaderMap, Router};
use cb_common::pbs::{
    DenebSpec, ElectraSpec, EthSpec, GetHeaderParams, GetHeaderResponse, SignedBlindedBeaconBlock,
    SubmitBlindedBlockResponse,
};
use serde::Deserialize;

use crate::{
    mev_boost,
    state::{BuilderApiState, PbsState, PbsStateGuard},
};

#[async_trait]
pub trait BuilderApi<S: BuilderApiState, T: EthSpec>: 'static {
    /// Use to extend the BuilderApi
    fn extra_routes() -> Option<Router<PbsStateGuard<S>>> {
        None
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/getHeader
    async fn get_header(
        params: GetHeaderParams,
        req_headers: HeaderMap,
        state: PbsState<S>,
    ) -> eyre::Result<Option<GetHeaderResponse<T>>>
    where
        T: EthSpec + for<'de> Deserialize<'de>,
    {
        mev_boost::get_header(params, req_headers, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/status
    async fn get_status(req_headers: HeaderMap, state: PbsState<S>) -> eyre::Result<()> {
        mev_boost::get_status(req_headers, state).await
    }

    /// https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock
    async fn submit_block(
        signed_blinded_block: SignedBlindedBeaconBlock<T>,
        req_headers: HeaderMap,
        state: PbsState<S>,
    ) -> eyre::Result<SubmitBlindedBlockResponse<T>>
    where
        T: EthSpec + for<'de> Deserialize<'de>,
    {
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

    async fn reload(state: PbsState<S>) -> eyre::Result<PbsState<S>> {
        mev_boost::reload(state).await
    }
}

pub struct DefaultBuilderApi;
impl BuilderApi<(), DenebSpec> for DefaultBuilderApi {}
impl BuilderApi<(), ElectraSpec> for DefaultBuilderApi {}
