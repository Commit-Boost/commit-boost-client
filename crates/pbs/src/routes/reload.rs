use axum::{extract::State, response::IntoResponse};
use cb_common::config::load_pbs_config;
use reqwest::StatusCode;
use uuid::Uuid;

use crate::{
    error::PbsClientError,
    state::{BuilderApiState, PbsState},
    InnerPbsState,
};

#[tracing::instrument(skip_all, name = "reload", fields(req_id = %Uuid::new_v4()))]
pub async fn handle_reload<S: BuilderApiState>(
    State(state): State<PbsState<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let pbs_config = load_pbs_config()
        .await
        .map_err(|err| PbsClientError::Internal(format!("Cannot parse new config: {err}")))?;
    let new_state = InnerPbsState::new(pbs_config).with_data(state.inner.read().await.data.clone());

    *state.inner.write().await = new_state;

    Ok(StatusCode::OK)
}
