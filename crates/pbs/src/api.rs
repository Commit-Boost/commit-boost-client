use std::sync::Arc;

use async_trait::async_trait;
use axum::{Router, http::HeaderMap};
use cb_common::pbs::{
    BuilderApiVersion, GetHeaderParams, GetHeaderResponse, SignedBlindedBeaconBlock,
    SubmitBlindedBlockResponse, Uint256,
};
use lh_types::{ContextDeserialize, ForkName};
use serde::{Deserialize, Deserializer};

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

/// A very light version of a BuilderBid, used for get_header responses when
/// full validation is not required.
#[derive(PartialEq, Deserialize, Clone)]
pub struct LightBuilderBid {
    #[serde(with = "serde_utils::quoted_u256")]
    pub value: Uint256,
}

/// Custom deserialization needed by ForkVersionedResponse; ignores the fork
/// version because the value doesn't depend on the fork
impl<'de> ContextDeserialize<'de, ForkName> for LightBuilderBid {
    fn context_deserialize<D>(deserializer: D, _context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err =
            |e| serde::de::Error::custom(format!("BuilderBid failed to deserialize: {:?}", e));
        Ok(Deserialize::deserialize(deserializer).map_err(convert_err)?)
    }
}

/// Wrapper struct to match the ForkVersionedResponse structure for
/// LightBuilderBid
#[derive(PartialEq, Deserialize, Clone)]
pub struct LightBuilderBidWrapper {
    pub message: LightBuilderBid,
}

/// Custom deserialization needed by ForkVersionedResponse; ignores the fork
/// version because the value doesn't depend on the fork
impl<'de> ContextDeserialize<'de, ForkName> for LightBuilderBidWrapper {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            message: serde_json::Value,
        }

        let helper = Helper::deserialize(deserializer)?;

        // Deserialize `data` using ContextDeserialize
        let message = LightBuilderBid::context_deserialize(helper.message, context)
            .map_err(serde::de::Error::custom)?;

        Ok(LightBuilderBidWrapper { message })
    }
}

pub(crate) type LightHeaderResponse = lh_types::ForkVersionedResponse<LightBuilderBidWrapper>;
