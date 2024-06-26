use async_trait::async_trait;
use bollard::{Docker, container::StatsOptions};
use futures_util::stream::TryStreamExt;
use opentelemetry::{global, Context, KeyValue};
use opentelemetry_prometheus::exporter;
use prometheus::{Encoder, TextEncoder, Registry};
use std::net::SocketAddr;
use std::sync::Arc;
use sysinfo::{Pid, ProcessExt, System, SystemExt};
use tokio::sync::RwLock;
use warp::Filter;

#[async_trait]
pub trait MetricsCollector: Send + Sync {
    async fn collect_metrics(&self);

    async fn serve_metrics(&self, addr: &str) {
        let registry = self.get_registry().clone();
        let routes = warp::path("metrics").map(move || {
            let encoder = TextEncoder::new();
            let metric_families = registry.gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            warp::http::Response::builder()
                .header("Content-Type", encoder.format_type())
                .body(String::from_utf8(buffer).unwrap())
        });

        let addr: SocketAddr = addr.parse().expect("Invalid address");
        warp::serve(routes).run(addr).await;
    }

    fn get_registry(&self) -> &Registry;
}

#[derive(Clone)]
pub struct DockerMetricsCollector {
    docker: Arc<Docker>,
    container_ids: Vec<String>,
    cpu_usage: opentelemetry::metrics::ObservableGauge<f64>,
    memory_usage: opentelemetry::metrics::ObservableGauge<u64>,
    registry: Registry,
}

#[async_trait]
impl MetricsCollector for DockerMetricsCollector {
    async fn collect_metrics(&self) {
        // Collect Docker metrics for each container
        for container_id in &self.container_ids {
            self.collect_docker_metrics(container_id.clone()).await;
        }
    }

    fn get_registry(&self) -> &Registry {
        &self.registry
    }
}

impl DockerMetricsCollector {
    pub async fn new(container_ids: Vec<String>) -> Self {
        // Initialize Docker client
        let docker = Docker::connect_with_local_defaults().expect("Failed to connect to Docker");

        // Create a new Prometheus registry
        let registry = Registry::new_custom(Some("docker_metrics".to_string()), None).unwrap();

        // Configure OpenTelemetry to use this registry
        let _exporter = exporter()
            .with_registry(registry.clone())
            .init();

        let meter = global::meter("docker_metrics");

        // Define example metrics
        let cpu_usage = meter.f64_observable_gauge("cpu_usage").init();
        let memory_usage = meter.u64_observable_gauge("memory_usage").init();

        DockerMetricsCollector {
            docker: Arc::new(docker),
            container_ids,
            cpu_usage,
            memory_usage,
            registry,
        }
    }

    async fn collect_docker_metrics(&self, container_id: String) {
        let docker = self.docker.clone();
        let cpu_usage = self.cpu_usage.clone();
        let memory_usage = self.memory_usage.clone();
        let cx = Context::current();

        tokio::spawn(async move {
            let stats_stream = docker
                .stats(&container_id, Some(StatsOptions { stream: true, one_shot: false }))
                .map_ok(|stat| {
                    let cpu_delta = stat.cpu_stats.cpu_usage.total_usage - stat.precpu_stats.cpu_usage.total_usage;
                    let system_cpu_delta = stat.cpu_stats.system_cpu_usage.unwrap() - stat.precpu_stats.system_cpu_usage.unwrap_or_default();
                    let number_cpus = stat.cpu_stats.online_cpus.unwrap();
                    let cpu_stats = (cpu_delta as f64 / system_cpu_delta as f64) * number_cpus as f64 * 100.0;

                    let used_memory = stat.memory_stats.usage.unwrap();

                    // Collect the docker stats into our OpenTelemetry metrics
                    cpu_usage.observe(&cx, cpu_stats, &[KeyValue::new("container_id", container_id.clone())]);
                    memory_usage.observe(&cx, used_memory, &[KeyValue::new("container_id", container_id.clone())]);
                })
                .try_collect::<Vec<_>>()
                .await;

            if let Err(e) = stats_stream {
                eprintln!("Error collecting stats for container {}: {:?}", container_id, e)
            }
        });
    }
}

#[derive(Clone)]
pub struct SysinfoMetricsCollector {
    system: Arc<RwLock<System>>,
    cpu_usage: opentelemetry::metrics::ObservableGauge<f64>,
    memory_usage: opentelemetry::metrics::ObservableGauge<u64>,
    registry: Registry,
    pid: Pid,
}

#[async_trait]
impl MetricsCollector for SysinfoMetricsCollector {
    async fn collect_metrics(&self) {
        let system = self.system.clone();
        let cpu_usage = self.cpu_usage.clone();
        let memory_usage = self.memory_usage.clone();
        let pid = self.pid;
        let cx = Context::current();

        tokio::spawn(async move {
            loop {
                let mut system = system.write().await;
                system.refresh_process(pid);

                if let Some(process) = system.process(pid) {
                    let cpu_stats = process.cpu_usage();
                    let used_memory = process.memory();

                    // Collect the process stats into our OpenTelemetry metrics
                    cpu_usage.observe(&cx, cpu_stats as f64, &[KeyValue::new("pid", pid.to_string())]);
                    memory_usage.observe(&cx, used_memory, &[KeyValue::new("pid", pid.to_string())]);
                } else {
                    eprintln!("Process with PID {} not found", pid);
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });
    }

    fn get_registry(&self) -> &Registry {
        &self.registry
    }
}

impl SysinfoMetricsCollector {
    pub async fn new(pid: Pid) -> Self {
        // Create a new Prometheus registry
        let registry = Registry::new_custom(Some("sysinfo_metrics".to_string()), None).unwrap();

        // Configure OpenTelemetry to use this registry
        let _exporter = exporter()
            .with_registry(registry.clone())
            .init();

        let meter = global::meter("sysinfo_metrics");

        // Define example metrics
        let cpu_usage = meter.f64_observable_gauge("cpu_usage").init();
        let memory_usage = meter.u64_observable_gauge("memory_usage").init();

        SysinfoMetricsCollector {
            system: Arc::new(RwLock::new(System::new_all())),
            cpu_usage,
            memory_usage,
            registry,
            pid,
        }
    }
}
