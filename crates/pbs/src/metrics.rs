use lazy_static::lazy_static;
use prometheus::{histogram_opts, opts, HistogramVec, IntCounterVec, Registry};

lazy_static! {
    pub static ref PBS_METRICS_REGISTRY: prometheus::Registry =
        Registry::new_custom(Some("cb_pbs".to_string()), None).unwrap();
    pub static ref REQUESTS_RECEIVED: IntCounterVec =
        IntCounterVec::new(opts!("requests_received", "Number of requests received"), &[
            "endpoint",
        ])
        .unwrap();
    pub static ref RELAY_RESPONSES: IntCounterVec =
        IntCounterVec::new(opts!("relay_response", "Number of requests received"), &[
            "code", "endpoint", "relay_id"
        ])
        .unwrap();
    pub static ref RELAY_RESPONSE_TIME: HistogramVec =
        HistogramVec::new(histogram_opts!("relay_response_time_ms", "Relay response times"), &[
            "endpoint", "relay_id"
        ])
        .unwrap();
    pub static ref RELAY_WINNING_BLOCK: IntCounterVec = IntCounterVec::new(
        opts!("relay_delivered_block", "Which relay delivered the winning block"),
        &["relay_id"]
    )
    .unwrap();
}

// TODO: this can be done with the macros, need to fix the types
pub fn register_default_metrics() {
    PBS_METRICS_REGISTRY.register(Box::new(REQUESTS_RECEIVED.clone())).expect("failed to register");

    PBS_METRICS_REGISTRY.register(Box::new(RELAY_RESPONSES.clone())).expect("failed to register");

    PBS_METRICS_REGISTRY
        .register(Box::new(RELAY_RESPONSE_TIME.clone()))
        .expect("failed to register");
}
