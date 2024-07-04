# Set up metrics reporting in custom module
1. Add the following dependencies to your Cargo.toml
```[dependencies]
cb-metrics.workspace = true
prometheus.workspace = true
lazy_static.workspace = true```
2. Import the necessary dependencies:
```use cb_metrics::sdk::MetricsProvider;
use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};```
3. Lazy load the prometheus registry and custom metric (for example a counter):
```// You can define custom metrics and a custom registry for the business logic of your module. These
// will be automatically scaped by the Prometheus server
lazy_static! {
    pub static ref MY_CUSTOM_REGISTRY: prometheus::Registry =
        Registry::new_custom(Some("da_commit".to_string()), None).unwrap();
    pub static ref SIG_RECEIVED_COUNTER: IntCounter =
        IntCounter::new("signature_received", "successful signatures requests received").unwrap();
}```
4. Initialize the registry and run the Module's metrics reporting server in main:
```#[tokio::main]
async fn main() {
    ... rest of code
    // Remember to register all your metrics before starting the process
    MY_CUSTOM_REGISTRY.register(Box::new(SIG_RECEIVED_COUNTER.clone())).unwrap();
    // Spin up a server that exposes the /metrics endpoint to Prometheus
    MetricsProvider::load_and_run(MY_CUSTOM_REGISTRY.clone());
    ... rest of code
}```
To update the metric in your business logic simply run:
```    SIG_RECEIVED_COUNTER.inc();```
