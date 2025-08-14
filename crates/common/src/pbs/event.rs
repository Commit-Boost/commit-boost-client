use std::{net::SocketAddr, time::Duration};

use alloy::{primitives::B256, rpc::types::beacon::relay::ValidatorRegistration};
use async_trait::async_trait;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
    Json,
};
use eyre::{bail, Result};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{error, info, trace, warn};
use url::Url;

use super::{
    GetHeaderParams, GetHeaderResponse, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse,
};
use crate::{
    config::{load_optional_env_var, BUILDER_URLS_ENV, HTTP_TIMEOUT_SECONDS_DEFAULT},
    pbs::{BuilderApiVersion, BUILDER_EVENTS_PATH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BuilderEvent {
    GetHeaderRequest(GetHeaderParams),
    GetHeaderResponse(Box<Option<GetHeaderResponse>>),
    GetStatusEvent,
    GetStatusResponse,
    SubmitBlockRequest(Box<SignedBlindedBeaconBlock>, BuilderApiVersion),
    SubmitBlockResponseV1(Box<SubmitBlindedBlockResponse>),
    SubmitBlockResponseV2,
    MissedPayload {
        /// Hash for the block for which no payload was received
        block_hash: B256,
    },
    RegisterValidatorRequest(Vec<ValidatorRegistration>),
    RegisterValidatorResponse,
    ReloadEvent,
    ReloadResponse,
}

#[derive(Debug, Clone)]
pub struct BuilderEventPublisher {
    client: reqwest::Client,
    endpoints: Vec<Url>,
}

impl BuilderEventPublisher {
    pub fn new(endpoints: Vec<Url>, http_timeout: Duration) -> Result<Self> {
        for endpoint in &endpoints {
            if endpoint.scheme() != "https" {
                warn!("BuilderEventPublisher endpoint {endpoint} is insecure, consider using HTTPS if possible instead");
            }
        }
        Ok(Self { client: reqwest::ClientBuilder::new().timeout(http_timeout).build()?, endpoints })
    }

    pub fn new_from_env() -> Result<Option<Self>> {
        let http_timeout = Duration::from_secs(HTTP_TIMEOUT_SECONDS_DEFAULT);

        load_optional_env_var(BUILDER_URLS_ENV)
            .map(|joined| {
                let endpoints = joined
                    .trim()
                    .split(',')
                    .map(|base| {
                        let url = base.trim().parse::<Url>()?.join(BUILDER_EVENTS_PATH)?;
                        Ok(url)
                    })
                    .collect::<Result<Vec<_>>>()?;

                Self::new(endpoints, http_timeout)
            })
            .transpose()
    }

    pub fn publish(&self, event: BuilderEvent) {
        for endpoint in self.endpoints.clone() {
            let client = self.client.clone();
            let event = event.clone();

            tokio::spawn(async move {
                trace!("Sending events to {}", endpoint);
                if let Err(err) = client
                    .post(endpoint)
                    .json(&event)
                    .send()
                    .await
                    .and_then(|res| res.error_for_status())
                {
                    error!("Failed to publish event: {:?}", err)
                };
            });
        }
    }

    pub fn n_subscribers(&self) -> usize {
        self.endpoints.len()
    }
}

pub struct BuilderEventClient<T: OnBuilderApiEvent> {
    pub port: u16,
    pub processor: T,
}

impl<T: OnBuilderApiEvent + Clone + Send + Sync + 'static> BuilderEventClient<T> {
    pub fn new(port: u16, processor: T) -> Self {
        Self { port, processor }
    }

    pub async fn run(self) -> eyre::Result<()> {
        info!("Starting builder events server on port {}", self.port);

        let router = axum::Router::new()
            .route(BUILDER_EVENTS_PATH, post(handle_builder_event::<T>))
            .with_state(self.processor);
        let address = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(&address).await?;

        axum::serve(listener, router).await?;

        bail!("Builder events stopped")
    }
}

async fn handle_builder_event<T: OnBuilderApiEvent>(
    State(processor): State<T>,
    Json(event): Json<BuilderEvent>,
) -> Response {
    trace!("Handling builder event");
    processor.on_builder_api_event(event).await;
    StatusCode::OK.into_response()
}

#[async_trait]
/// This is what modules are expected to implement to process BuilderApi events
pub trait OnBuilderApiEvent {
    async fn on_builder_api_event(&self, event: BuilderEvent);
}
