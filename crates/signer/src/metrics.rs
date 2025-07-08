//! Metrics for Signer module

use axum::http::Uri;
use cb_common::commit::constants::{
    GENERATE_PROXY_KEY_PATH, GET_PUBKEYS_PATH, REQUEST_SIGNATURE_BLS_PATH,
    REQUEST_SIGNATURE_PROXY_BLS_PATH, REQUEST_SIGNATURE_PROXY_ECDSA_PATH,
};
use lazy_static::lazy_static;
use prometheus::{register_int_counter_vec_with_registry, IntCounterVec, Registry};

use crate::constants::{
    GENERATE_PROXY_KEY_ENDPOINT_TAG, GET_PUBKEYS_ENDPOINT_TAG, REQUEST_SIGNATURE_BLS_ENDPOINT_TAG,
    REQUEST_SIGNATURE_PROXY_BLS_ENDPOINT_TAG, REQUEST_SIGNATURE_PROXY_ECDSA_ENDPOINT_TAG,
};

lazy_static! {
    pub static ref SIGNER_METRICS_REGISTRY: Registry =
        Registry::new_custom(Some("cb_signer".to_string()), None).unwrap();

    /// Status code returned by endpoint
    pub static ref SIGNER_STATUS: IntCounterVec = register_int_counter_vec_with_registry!(
        "signer_status_code_total",
        "HTTP status code returned by signer",
        &["http_status_code", "endpoint"],
        SIGNER_METRICS_REGISTRY
    ).unwrap();
}

pub fn uri_to_tag(uri: &Uri) -> &str {
    match uri.path() {
        GET_PUBKEYS_PATH => GET_PUBKEYS_ENDPOINT_TAG,
        GENERATE_PROXY_KEY_PATH => GENERATE_PROXY_KEY_ENDPOINT_TAG,
        REQUEST_SIGNATURE_BLS_PATH => REQUEST_SIGNATURE_BLS_ENDPOINT_TAG,
        REQUEST_SIGNATURE_PROXY_BLS_PATH => REQUEST_SIGNATURE_PROXY_BLS_ENDPOINT_TAG,
        REQUEST_SIGNATURE_PROXY_ECDSA_PATH => REQUEST_SIGNATURE_PROXY_ECDSA_ENDPOINT_TAG,
        _ => "unknown endpoint",
    }
}
