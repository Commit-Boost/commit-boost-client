use axum::{
    extract::Request,
    http::{Response, StatusCode},
    middleware::{map_request, map_response},
    routing::{get, post},
    Router,
};
use cb_common::pbs::{
    BULDER_API_PATH, GET_HEADER_PATH, GET_STATUS_PATH, REGISTER_VALIDATOR_PATH, SUBMIT_BLOCK_PATH,
};
use tracing::debug;

use super::{handle_get_header, handle_get_status, handle_register_validator, handle_submit_block};
use crate::{
    boost::BuilderApi,
    state::{BuilderApiState, BuilderState},
};

pub fn create_app_router<S: BuilderApiState, T: BuilderApi<S>>(state: BuilderState<S>) -> Router {
    let builder_routes = Router::new()
        .route(GET_HEADER_PATH, get(handle_get_header::<S, T>))
        .route(GET_STATUS_PATH, get(handle_get_status::<S, T>))
        .route(REGISTER_VALIDATOR_PATH, post(handle_register_validator::<S, T>))
        .route(SUBMIT_BLOCK_PATH, post(handle_submit_block::<S, T>));

    let builder_api = Router::new().nest(BULDER_API_PATH, builder_routes);

    let app = if let Some(extra_routes) = T::routes() {
        builder_api.merge(extra_routes)
    } else {
        builder_api
    };

    app.layer(map_request(log_all_requests))
        .layer(map_response(log_all_responses))
        .fallback(handle_404)
        .with_state(state)
}

async fn handle_404() -> StatusCode {
    StatusCode::NOT_FOUND
}

// TODO: remove
async fn log_all_responses<B: std::fmt::Debug>(response: Response<B>) -> Response<B> {
    debug!("SENDING RESPONSE: {response:?}");
    response
}

// TODO: remove
async fn log_all_requests<B: std::fmt::Debug>(request: Request<B>) -> Request<B> {
    debug!("RECEIVED REQUEST: {request:?}");
    request
}
