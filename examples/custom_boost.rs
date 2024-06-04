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
use cb_cli::runner::Runner;
use cb_common::utils::initialize_tracing_log;
use cb_pbs::{BuilderApi, BuilderApiState, BuilderState};
use clap::Parser;

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

    let (chain, config) = cb_cli::Args::parse().to_config();

    let state = BuilderState::new(chain, config);
    let runner = Runner::<StatusCounter, MyBuilderApi>::new(state);

    if let Err(err) = runner.run().await {
        eprintln!("Error: {err}");
        std::process::exit(1)
    };
}
