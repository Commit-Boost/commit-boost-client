use axum::{
    routing::{get, post},
    Router,
};
use cb_common::pbs::{
    BULDER_API_PATH, GET_HEADER_PATH, GET_STATUS_PATH, REGISTER_VALIDATOR_PATH, SUBMIT_BLOCK_PATH,
};

use super::{handle_get_header, handle_get_status, handle_register_validator, handle_submit_block};
use crate::{
    api::BuilderApi,
    state::{BuilderApiState, PbsState},
};

pub fn create_app_router<
    U: Clone + Send + Sync + 'static,
    S: BuilderApiState,
    T: BuilderApi<U, S>,
>(
    state: PbsState<U, S>,
) -> Router {
    let builder_routes = Router::new()
        .route(GET_HEADER_PATH, get(handle_get_header::<U, S, T>))
        .route(GET_STATUS_PATH, get(handle_get_status::<U, S, T>))
        .route(REGISTER_VALIDATOR_PATH, post(handle_register_validator::<U, S, T>))
        .route(SUBMIT_BLOCK_PATH, post(handle_submit_block::<U, S, T>));

    let builder_api = Router::new().nest(BULDER_API_PATH, builder_routes);

    let app = if let Some(extra_routes) = T::extra_routes() {
        builder_api.merge(extra_routes)
    } else {
        builder_api
    };

    app.with_state(state)
}
