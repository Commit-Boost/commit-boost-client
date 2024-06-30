use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};

lazy_static! {
    pub static ref PBS_METRICS_REGISTRY: prometheus::Registry =
        Registry::new_custom(Some("cb_pbs".to_string()), None).unwrap();
    pub static ref GET_HEADER_COUNTER: IntCounter =
        IntCounter::new("get_header_requests", "number of get_headers").unwrap();
}

pub fn register_default_metrics() {
    PBS_METRICS_REGISTRY
        .register(Box::new(GET_HEADER_COUNTER.clone()))
        .expect("failed to register");
}
