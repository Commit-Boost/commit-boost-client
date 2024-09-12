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

use super::{
    GetHeaderParams, GetHeaderResponse, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse,
};
use crate::{
    config::{load_env_var, BUILDER_PORT_ENV},
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
    endpoints: Vec<String>,
}

impl BuilderEventPublisher {
    pub fn new(endpoints: Vec<String>) -> Self {
        Self { client: reqwest::Client::new(), endpoints }
    }

    pub fn new_from_env() -> Option<Self> {
        load_env_var(BUILDER_PORT_ENV)
            .map(|joined| {
                let endpoints = joined
                    .split(',')
                    .map(|s| format!("http://{}{}", s, BUILDER_EVENTS_PATH))
                    .collect();

                Self::new(endpoints)
            })
            .ok()
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
