use axum::{
    routing::{get, post},
    Router,
};
use cb_common::pbs::{
    BUILDER_API_PATH, GET_HEADER_PATH, GET_STATUS_PATH, REGISTER_VALIDATOR_PATH, RELOAD_PATH,
    SUBMIT_BLOCK_PATH,
};

use super::{
    handle_get_header, handle_get_status, handle_register_validator, handle_submit_block,
    reload::handle_reload,
};
use crate::{
    api::BuilderApi,
    state::{BuilderApiState, PbsState},
};

pub fn create_app_router<S: BuilderApiState, A: BuilderApi<S>>(state: PbsState<S>) -> Router {
    let builder_routes = Router::new()
        .route(GET_HEADER_PATH, get(handle_get_header::<S, A>))
        .route(GET_STATUS_PATH, get(handle_get_status::<S, A>))
        .route(REGISTER_VALIDATOR_PATH, post(handle_register_validator::<S, A>))
        .route(SUBMIT_BLOCK_PATH, post(handle_submit_block::<S, A>))
        .route(RELOAD_PATH, post(handle_reload::<S, A>));

    let builder_api = Router::new().nest(BUILDER_API_PATH, builder_routes);

    let app = if let Some(extra_routes) = A::extra_routes() {
        builder_api.merge(extra_routes)
    } else {
        builder_api
    };

    app.with_state(state)
}
