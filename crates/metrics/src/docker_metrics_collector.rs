use std::{net::SocketAddr, sync::Arc};

use bollard::{container::StatsOptions, Docker};
use futures_util::stream::TryStreamExt;
use opentelemetry::{global, metrics::ObservableGauge, KeyValue};
use prometheus::{Encoder, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use tokio::task;
use warp::{Filter, Reply};

#[derive(Clone)]
pub struct DockerMetricsCollector {
    docker: Arc<Docker>,
    container_ids: Vec<String>,
    cpu_usage: ObservableGauge<f64>,
    memory_usage: ObservableGauge<u64>,
    registry: Registry,
    jwt_token: String,
}

#[derive(Deserialize, Serialize)]
struct RegisterMetricRequest {
    name: String,
    description: String,
}

#[derive(Deserialize, Serialize)]
struct UpdateMetricRequest {
    name: String,
    value: f64,
    labels: Vec<(String, String)>,
}

impl DockerMetricsCollector {
    pub async fn new(container_ids: Vec<String>, addr: SocketAddr, jwt_token: String) -> Arc<Self> {
        let docker = Docker::connect_with_local_defaults().expect("Failed to connect to Docker");
        let registry = Registry::new_custom(Some("docker_metrics".to_string()), None).unwrap();
        // Configure OpenTelemetry to use this registry
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .build()
            .expect("failed to build exporter");

        let provider =
            opentelemetry_sdk::metrics::SdkMeterProvider::builder().with_reader(exporter).build();

        // NOTE:
        //  This line is crucial, since below we are using global::meter() to create meters (on
        // custom meter registration)  The current approach here might not be optimal, some
        // deeper understanding of OpenTelemetry's philosophy is needed
        global::set_meter_provider(provider.clone());

        // let _exporter = exporter().with_registry(registry.clone()).init();
        let meter = global::meter("docker_metrics");
        let cpu_usage =
            meter.f64_observable_gauge("cpu_usage").with_description("CPU Usage").init();
        let memory_usage =
            meter.u64_observable_gauge("memory_usage").with_description("Memory Usage").init();

        let collector = Arc::new(Self {
            docker: Arc::new(docker),
            container_ids,
            cpu_usage,
            memory_usage,
            registry,
            jwt_token,
        });

        let collector_clone = collector.clone();
        let addr = addr.to_string(); // Clone the address to move into the async block
        task::spawn(async move {
            collector_clone.start_http_server(&addr).await;
        });

        let collector_clone_for_metrics = collector.clone();
        task::spawn(async move {
            collector_clone_for_metrics.collect_metrics().await;
        });

        collector
    }

    async fn collect_metrics(&self) {
        for container_id in &self.container_ids {
            self.collect_docker_metrics(container_id.clone()).await;
        }
    }

    async fn collect_docker_metrics(&self, container_id: String) {
        let docker = self.docker.clone();
        let cpu_usage = self.cpu_usage.clone();
        let memory_usage = self.memory_usage.clone();

        tokio::spawn(async move {
            let stats_stream = docker
                .stats(&container_id, Some(StatsOptions { stream: true, one_shot: false }))
                .map_ok(|stat| {
                    // //TODO:
                    // //  Those crash since they're really reliant on implicit proper sequence of
                    // initialization //  I've replaced them with a direct 0 to
                    // avoid craches, but we must investigate how proper calculations must happen
                    // here. let cpu_delta =
                    // stat.cpu_stats.cpu_usage.total_usage -
                    // stat.precpu_stats.cpu_usage.total_usage;
                    // let system_cpu_delta = stat.cpu_stats.system_cpu_usage.unwrap() -
                    // stat.precpu_stats.system_cpu_usage.unwrap_or_default();
                    // let number_cpus = stat.cpu_stats.online_cpus.unwrap();
                    let cpu_stats = 0f64; //(cpu_delta as f64 / system_cpu_delta as f64) * number_cpus as f64 * 100.0;
                    let used_memory = stat.memory_stats.usage.unwrap_or_default();

                    cpu_usage
                        .observe(cpu_stats, &[KeyValue::new("container_id", container_id.clone())]);
                    memory_usage.observe(used_memory, &[KeyValue::new(
                        "container_id",
                        container_id.clone(),
                    )]);
                })
                .try_collect::<Vec<_>>()
                .await;

            if let Err(e) = stats_stream {
                eprintln!("Error collecting stats for container {}: {:?}", container_id, e);
            }
        });
    }

    async fn start_http_server(self: Arc<Self>, addr: &str) {
        let metrics_route = warp::path("metrics").map({
            let self_clone = self.clone();
            move || {
                let encoder = TextEncoder::new();
                let metric_families = self_clone.registry.gather();
                let buffer = encoder.encode_to_string(&metric_families).unwrap();
                warp::http::Response::builder()
                    .header("Content-Type", encoder.format_type())
                    .body(buffer)
            }
        });

        let register_metric_route = warp::path("register_custom_metric")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::header("Authorization"))
            .and_then({
                let self_clone = self.clone();
                move |req: RegisterMetricRequest, auth: String| {
                    let self_clone = self_clone.clone();
                    async move { self_clone.handle_register_custom_metric(req, auth).await }
                }
            });

        let update_metric_route = warp::path("update_custom_metric")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::header("Authorization"))
            .and_then({
                let self_clone = self.clone();
                move |req: UpdateMetricRequest, auth: String| {
                    let self_clone = self_clone.clone();
                    async move { self_clone.handle_update_custom_metric(req, auth).await }
                }
            });

        let routes = metrics_route.or(register_metric_route).or(update_metric_route);

        let addr: SocketAddr = addr.parse().expect("Invalid address");
        warp::serve(routes).run(addr).await;
    }

    fn register_custom_gauge(&self, name: String, description: String) -> ObservableGauge<f64> {
        let meter = global::meter("custom_metrics");
        meter.f64_observable_gauge(name).with_description(description).init()
    }

    fn update_custom_gauge(&self, gauge: &ObservableGauge<f64>, value: f64, labels: &[KeyValue]) {
        gauge.observe(value, labels);
    }

    async fn handle_register_custom_metric(
        &self,
        req: RegisterMetricRequest,
        auth: String,
    ) -> Result<impl Reply, warp::Rejection> {
        if !self.validate_token(auth) {
            return Ok(warp::reply::with_status(
                "Unauthorized",
                warp::http::StatusCode::UNAUTHORIZED,
            ));
        }

        self.register_custom_gauge(req.name, req.description);
        Ok(warp::reply::with_status("Metric registered", warp::http::StatusCode::OK))
    }

    async fn handle_update_custom_metric(
        &self,
        req: UpdateMetricRequest,
        auth: String,
    ) -> Result<impl Reply, warp::Rejection> {
        if !self.validate_token(auth) {
            return Ok(warp::reply::with_status(
                "Unauthorized",
                warp::http::StatusCode::UNAUTHORIZED,
            ));
        }

        let gauge = self.register_custom_gauge(req.name, "".to_string()); // Assuming the gauge is already registered
        let labels = req
            .labels
            .iter()
            .map(|(k, v)| KeyValue::new(k.clone(), v.clone()))
            .collect::<Vec<KeyValue>>();
        self.update_custom_gauge(&gauge, req.value, &labels);
        Ok(warp::reply::with_status("Metric updated", warp::http::StatusCode::OK))
    }

    fn validate_token(&self, token: String) -> bool {
        // TODO: Parsing should probably not happen here (too late)
        token.trim().replace("Bearer ", "") == self.jwt_token.trim()
    }
}
