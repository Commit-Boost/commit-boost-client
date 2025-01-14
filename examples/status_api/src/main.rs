use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use async_trait::async_trait;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use commit_boost::prelude::*;
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::IntCounter;
use reqwest::{header::HeaderMap, StatusCode};
use serde::Deserialize;
use tracing::info;

lazy_static! {
    pub static ref CHECK_RECEIVED_COUNTER: IntCounter =
        IntCounter::new("checks", "successful /check requests received").unwrap();
}

/// Extra config loaded from the config file
/// You should add an `inc_amount` field to the config file in the `pbs`
/// section. Be sure also to change the `pbs.docker_image` field,
/// `test_status_api` in this case (from scripts/build_local_modules.sh).
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    inc_amount: u64,
}

// Extra state available at runtime
#[derive(Clone)]
struct MyBuilderState {
    inc_amount: u64,
    counter: Arc<AtomicU64>,
}

impl BuilderApiState for MyBuilderState {}

impl MyBuilderState {
    fn from_config(extra: ExtraConfig) -> Self {
        Self { inc_amount: extra.inc_amount, counter: Arc::new(AtomicU64::new(0)) }
    }

    fn inc(&self) {
        self.counter.fetch_add(self.inc_amount, Ordering::Relaxed);
    }
    fn get(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

struct MyBuilderApi;

#[async_trait]
impl BuilderApi<MyBuilderState> for MyBuilderApi {
    async fn get_status(req_headers: HeaderMap, state: PbsState<MyBuilderState>) -> Result<()> {
        state.data.inc();
        info!("THIS IS A CUSTOM LOG");
        CHECK_RECEIVED_COUNTER.inc();
        get_status(req_headers, state).await
    }

    fn extra_routes() -> Option<Router<PbsState<MyBuilderState>>> {
        let mut router = Router::new();
        router = router.route("/check", get(handle_check));
        Some(router)
    }
}

async fn handle_check(State(state): State<PbsState<MyBuilderState>>) -> Response {
    (StatusCode::OK, format!("Received {count} status requests!", count = state.data.get()))
        .into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>().await?;
    let chain = pbs_config.chain;
    let _guard = initialize_pbs_tracing_log()?;

    let custom_state = MyBuilderState::from_config(extra);
    let state = PbsState::new(pbs_config).with_data(custom_state);

    PbsService::register_metric(Box::new(CHECK_RECEIVED_COUNTER.clone()));
    PbsService::init_metrics(chain)?;

    PbsService::run::<MyBuilderState, MyBuilderApi>(state).await
}
