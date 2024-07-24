//! Metrics for PBS module
//! We collect two types of metrics within the PBS module:
//! - what PBS receives from relays
//! - what PBS returns to the beacon node

use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry, HistogramVec,
    IntCounterVec, Registry,
};

lazy_static! {
    pub static ref PBS_METRICS_REGISTRY: Registry =
        Registry::new_custom(Some("cb_pbs".to_string()), None).unwrap();

    // FROM RELAYS
    /// Status code received by relay by endpoint
    pub static ref RELAY_STATUS_CODE: IntCounterVec = register_int_counter_vec_with_registry!(
        "relay_status_code",
        "HTTP status code received by relay",
        &["http_status_code", "endpoint", "relay_id"],
        PBS_METRICS_REGISTRY
    )
    .unwrap();

    /// Latency by relay by endpoint
    pub static ref RELAY_LATENCY: HistogramVec = register_histogram_vec_with_registry!(
        "relay_latency",
        "HTTP latency by relay",
        &["endpoint", "relay_id"],
        PBS_METRICS_REGISTRY
    )
    .unwrap();

    // TO BEACON NODE
    /// Status code returned to beacon node by endpoint
    pub static ref BEACON_NODE_STATUS: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_node_status_code",
        "HTTP status code returned to beacon node",
        &["http_status_code", "endpoint"],
        PBS_METRICS_REGISTRY
    ).unwrap();
}
