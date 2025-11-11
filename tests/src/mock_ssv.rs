use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{Path, State},
    response::Response,
    routing::get,
};
use cb_common::{
    config::MUXER_HTTP_MAX_LENGTH,
    interop::ssv::types::{SSVPagination, SSVResponse, SSVValidator},
};
use tokio::{net::TcpListener, sync::RwLock, task::JoinHandle};
use tracing::info;

pub const TEST_HTTP_TIMEOUT: u64 = 2;

/// State for the mock server
#[derive(Clone)]
pub struct SsvMockState {
    /// List of pubkeys for the mock server to return
    pub validators: Arc<RwLock<Vec<SSVValidator>>>,

    /// Whether to force a timeout response to simulate a server error
    pub force_timeout: Arc<RwLock<bool>>,
}

/// Creates a simple mock server to simulate the SSV API endpoint under
/// various conditions for testing. Note this ignores
pub async fn create_mock_ssv_server(
    port: u16,
    state: Option<SsvMockState>,
) -> Result<JoinHandle<()>, axum::Error> {
    let data = include_str!("../../tests/data/ssv_valid.json");
    let response = serde_json::from_str::<SSVResponse>(data).expect("failed to parse test data");
    let state = state.unwrap_or(SsvMockState {
        validators: Arc::new(RwLock::new(response.validators)),
        force_timeout: Arc::new(RwLock::new(false)),
    });
    let router = axum::Router::new()
        .route(
            "/api/v4/{chain_name}/validators/in_operator/{node_operator_id}",
            get(handle_validators),
        )
        .route("/big_data", get(handle_big_data))
        .with_state(state)
        .into_make_service();

    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(address).await.map_err(axum::Error::new)?;
    let server = axum::serve(listener, router).with_graceful_shutdown(async {
        tokio::signal::ctrl_c().await.expect("Failed to listen for shutdown signal");
    });
    let result = Ok(tokio::spawn(async move {
        if let Err(e) = server.await {
            eprintln!("Server error: {e}");
        }
    }));
    info!("Mock server started on http://localhost:{port}/");
    result
}

/// Returns a valid SSV validators response, or a timeout if requested in
/// the server state
async fn handle_validators(
    State(state): State<SsvMockState>,
    Path((_, _)): Path<(String, u64)>,
) -> Response {
    // Time out if requested
    if *state.force_timeout.read().await {
        return handle_timeout().await;
    }

    // Generate the response based on the current validators
    let response: SSVResponse;
    {
        let validators = state.validators.read().await;
        let pagination = SSVPagination { total: validators.len() };
        response = SSVResponse { validators: validators.clone(), pagination };
    }

    // Create a valid response
    Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&response).unwrap().into())
        .unwrap()
}

/// Sends a response with a large body - larger than the maximum allowed.
/// Note that hyper overwrites the content-length header automatically, so
/// setting it here wouldn't actually change the value that ultimately
/// gets sent to the server.
async fn handle_big_data() -> Response {
    let body = "f".repeat(2 * MUXER_HTTP_MAX_LENGTH);
    Response::builder()
        .status(200)
        .header("Content-Type", "application/text")
        .body(body.into())
        .unwrap()
}

/// Simulates a timeout by sleeping for a long time
async fn handle_timeout() -> Response {
    // Sleep for a long time to simulate a timeout
    tokio::time::sleep(std::time::Duration::from_secs(2 * TEST_HTTP_TIMEOUT)).await;
    Response::builder()
        .status(200)
        .header("Content-Type", "application/text")
        .body("Timeout response".into())
        .unwrap()
}
