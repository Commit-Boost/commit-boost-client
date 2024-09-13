use std::net::SocketAddr;

use alloy::{primitives::B256, rpc::types::beacon::relay::ValidatorRegistration};
use axum::{
    async_trait,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
    Json,
};
use eyre::bail;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{error, info, trace};
use url::Url;

use super::{
    GetHeaderParams, GetHeaderResponse, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse,
};
use crate::{
    config::{load_optional_env_var, BUILDER_URLS_ENV},
    pbs::BUILDER_EVENTS_PATH,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BuilderEvent {
    GetHeaderRequest(GetHeaderParams),
    GetHeaderResponse(Box<Option<GetHeaderResponse>>),
    GetStatusEvent,
    GetStatusResponse,
    SubmitBlockRequest(Box<SignedBlindedBeaconBlock>),
    SubmitBlockResponse(Box<SubmitBlindedBlockResponse>),
    MissedPayload { block_hash: B256, relays: String },
    RegisterValidatorRequest(Vec<ValidatorRegistration>),
    RegisterValidatorResponse,
}

#[derive(Debug, Clone)]
pub struct BuilderEventPublisher {
    client: reqwest::Client,
    endpoints: Vec<Url>,
}

impl BuilderEventPublisher {
    pub fn new(endpoints: Vec<Url>) -> Self {
        Self { client: reqwest::Client::new(), endpoints }
    }

    pub fn new_from_env() -> eyre::Result<Option<Self>> {
        load_optional_env_var(BUILDER_URLS_ENV)
            .map(|joined| {
                let endpoints = joined
                    .trim()
                    .split(',')
                    .map(|base| {
                        let url = base.trim().parse::<Url>()?.join(BUILDER_EVENTS_PATH)?;
                        Ok(url)
                    })
                    .collect::<eyre::Result<Vec<_>>>()?;

                Ok(Self::new(endpoints))
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
