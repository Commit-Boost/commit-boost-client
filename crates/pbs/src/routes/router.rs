use axum::{
    extract::{DefaultBodyLimit, MatchedPath, Request},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use axum_extra::headers::{ContentType, HeaderMapExt, UserAgent};
use cb_common::pbs::{
    BUILDER_API_PATH, GET_HEADER_PATH, GET_STATUS_PATH, REGISTER_VALIDATOR_PATH, RELOAD_PATH,
    SUBMIT_BLOCK_PATH,
};
use tracing::trace;
use uuid::Uuid;

use super::{
    handle_get_header, handle_get_status, handle_register_validator, handle_submit_block,
    reload::handle_reload,
};
use crate::{
    api::BuilderApi,
    state::{BuilderApiState, PbsStateGuard},
    MAX_SIZE_REGISTER_VALIDATOR_REQUEST, MAX_SIZE_SUBMIT_BLOCK_RESPONSE,
};

pub fn create_app_router<S: BuilderApiState, A: BuilderApi<S>>(state: PbsStateGuard<S>) -> Router {
    // DefaultBodyLimit is 2Mib by default, so we only increase it for a few routes
    // thay may need more

    let builder_routes = Router::new()
        .route(GET_HEADER_PATH, get(handle_get_header::<S, A>))
        .route(GET_STATUS_PATH, get(handle_get_status::<S, A>))
        .route(
            REGISTER_VALIDATOR_PATH,
            post(handle_register_validator::<S, A>)
                .route_layer(DefaultBodyLimit::max(MAX_SIZE_REGISTER_VALIDATOR_REQUEST)),
        )
        .route(
            SUBMIT_BLOCK_PATH,
            post(handle_submit_block::<S, A>)
                .route_layer(DefaultBodyLimit::max(MAX_SIZE_SUBMIT_BLOCK_RESPONSE)),
        ); // header is smaller than the response but err on the safe side
    let reload_router = Router::new().route(RELOAD_PATH, post(handle_reload::<S, A>));
    let builder_api = Router::new().nest(BUILDER_API_PATH, builder_routes).merge(reload_router);

    let app = if let Some(extra_routes) = A::extra_routes() {
        builder_api.merge(extra_routes)
    } else {
        builder_api
    };

    app.layer(middleware::from_fn(tracing_middleware)).with_state(state)
}

#[tracing::instrument(
    name = "", 
    skip_all,
    fields(
        method = %req.extensions().get::<MatchedPath>().map(|m| m.as_str()).unwrap_or("unknown"),
        req_id = ?Uuid::new_v4(),
        slot = tracing::field::Empty,
        block_hash = tracing::field::Empty,
        block_number = tracing::field::Empty,
        parent_hash = tracing::field::Empty,
        validator = tracing::field::Empty,
    ),
)]
pub async fn tracing_middleware(req: Request, next: Next) -> Response {
    trace!(
        http.method = %req.method(),
        http.user_agent = req.headers().typed_get::<UserAgent>().map(|ua| ua.to_string()).unwrap_or_default(),
        http.content_type = req.headers().typed_get::<ContentType>().map(|ua| ua.to_string()).unwrap_or_default(),
    "start request");

    let response = next.run(req).await;

    let status = response.status();

    trace!(http.response.status_code = ?status, "end request");

    response
}
