use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use async_trait::async_trait;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use cb_common::{config::load_pbs_config, utils::initialize_tracing_log};
use cb_pbs::{BuilderApi, BuilderApiState, BuilderState, PbsService};
use tracing::info;

// You can provide extra state to the Pbs server by implementing the `BuilderApiState` trait
#[derive(Debug, Default, Clone)]
struct StatusCounter(Arc<AtomicU64>);

impl BuilderApiState for StatusCounter {}
impl StatusCounter {
    fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn log(&self) -> String {
        let count = self.0.load(Ordering::Relaxed);
        format!("Received {count} status requests!")
    }
}

// Any method that is not overriden will default to the normal MEV boost flow
struct MyBuilderApi;
#[async_trait]
impl BuilderApi<StatusCounter> for MyBuilderApi {
    async fn get_status(state: BuilderState<StatusCounter>) -> eyre::Result<()> {
        let count = state.data.0.load(Ordering::Relaxed);
        info!("THIS IS A CUSTOM LOG. Count: {count}");
        state.data.inc();
        Ok(())
    }

    fn routes() -> Option<Router<BuilderState<StatusCounter>>> {
        let router = Router::new().route("/custom/stats", get(handle_stats));
        Some(router)
    }
}
async fn handle_stats(State(state): State<BuilderState<StatusCounter>>) -> Response {
    (StatusCode::OK, state.data.log()).into_response()
}

#[tokio::main]
async fn main() {
    initialize_tracing_log();

    let (chain, config) = load_pbs_config();

    info!("Starting custom pbs module");

    // TODO: pass these via config
    let jwt = "my_jwt_token";
    let address = "0.0.0.0:18550".parse().unwrap();

    let state = BuilderState::new(chain, config, address, jwt);

    PbsService::run::<StatusCounter, MyBuilderApi>(state).await;
}
