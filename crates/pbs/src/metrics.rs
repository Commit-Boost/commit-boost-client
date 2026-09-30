//! Metrics for PBS module
//! We collect two types of metrics within the PBS module:
//! - what PBS receives from relays
//! - what PBS returns to the beacon node

use lazy_static::lazy_static;
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};

lazy_static! {
    pub static ref PBS_METRICS_REGISTRY: Registry =
        Registry::new_custom(Some("cb_pbs".to_string()), None).unwrap();

    // FROM RELAYS
    /// Status code received by relay by endpoint
    pub static ref RELAY_STATUS_CODE: IntCounterVec = register_int_counter_vec_with_registry!(
        "relay_status_code_total",
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

    /// Latest slot for which relay delivered a header
    pub static ref RELAY_LAST_SLOT: IntGaugeVec = register_int_gauge_vec_with_registry!(
        "relay_last_slot",
        "Latest slot for which relay delivered a header",
        &["relay_id"],
        PBS_METRICS_REGISTRY
    )
    .unwrap();

    /// Latest slot for which relay delivered a header
    // Don't store slot number to avoid creating high cardinality, if needed can just aggregate for 12sec
    pub static ref RELAY_HEADER_VALUE: IntGaugeVec = register_int_gauge_vec_with_registry!(
        "relay_header_value",
        "Header value in gwei delivered by relay",
        &["relay_id"],
        PBS_METRICS_REGISTRY
    )
    .unwrap();


    // THE WEBSOCKET BID STREAM
    // Outcome and time-to-first-bid ride RELAY_STATUS_CODE / RELAY_LATENCY
    // under `get_header_stream`

    /// Websocket handshake latency by relay
    pub static ref RELAY_STREAM_CONNECT_LATENCY: HistogramVec = register_histogram_vec_with_registry!(
        "relay_stream_connect_latency",
        "Websocket handshake latency by relay",
        &["relay_id"],
        vec![0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.2, 0.3, 0.4, 0.5, 1.0],
        PBS_METRICS_REGISTRY
    )
    .unwrap();

    /// Bid updates received per stream window by relay
    pub static ref RELAY_STREAM_UPDATES: HistogramVec = register_histogram_vec_with_registry!(
        "relay_stream_updates",
        "Bid updates received per stream window by relay",
        &["relay_id"],
        vec![0.0, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 50.0, 100.0],
        PBS_METRICS_REGISTRY
    )
    .unwrap();

    /// Websocket frames that could not be parsed as a bid, by relay
    pub static ref RELAY_STREAM_INVALID_FRAMES: IntCounterVec = register_int_counter_vec_with_registry!(
        "relay_stream_invalid_frames_total",
        "Websocket frames that could not be parsed as a bid, by relay",
        &["relay_id"],
        PBS_METRICS_REGISTRY
    )
    .unwrap();

    /// Stream attempts that fell back to HTTP, by relay
    // Only a handshake failure with bid window left retries; one at the
    // deadline shows on the status series alone
    pub static ref RELAY_STREAM_FALLBACK: IntCounterVec = register_int_counter_vec_with_registry!(
        "relay_stream_fallback_total",
        "get_header stream attempts that fell back to HTTP, by relay",
        &["relay_id"],
        PBS_METRICS_REGISTRY
    )
    .unwrap();

    // TO BEACON NODE
    /// Status code returned to beacon node by endpoint
    pub static ref BEACON_NODE_STATUS: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_node_status_code_total",
        "HTTP status code returned to beacon node",
        &["http_status_code", "endpoint"],
        PBS_METRICS_REGISTRY
    ).unwrap();

    /// Count of v2 submit_block requests that could not be served because the
    /// relay returned 404 on the v2 endpoint. A non-zero value means the relay
    /// fleet has not been upgraded to support submitBlindedBlockV2 and those
    /// blocks were not submitted.
    pub static ref RELAY_V2_UNSUPPORTED: IntCounterVec = register_int_counter_vec_with_registry!(
        "pbs_submit_block_v2_unsupported_total",
        "Count of v2 submit_block requests a relay could not serve because it does not support v2",
        &["relay_id"],
        PBS_METRICS_REGISTRY
    ).unwrap();
}
