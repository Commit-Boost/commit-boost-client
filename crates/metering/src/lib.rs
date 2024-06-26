use serde::{Serialize, Deserialize};
use sysinfo::{System, SystemExt, DiskExt, ProcessorExt};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;
use prometheus::{Encoder, TextEncoder, Registry, Gauge, opts};
use hyper::{Body, Response, Server, Request, Method};
use hyper::service::{make_service_fn, service_fn};
use std::convert::Infallible;


#[derive(Serialize, Deserialize, Debug)]
pub struct SystemMetrics {
    pub cpu_usage: f32,
    pub ram_usage: u64,
    pub disk_usage: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CustomMetric {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Metrics {
    pub system_metrics: SystemMetrics,
    pub custom_metrics: Vec<CustomMetric>,
}

pub struct MetricsCollector {
    system: Arc<RwLock<System>>,
    custom_metrics: Arc<RwLock<HashMap<String, String>>>,
    cpu_usage_gauge: Gauge,
    ram_usage_gauge: Gauge,
    disk_usage_gauge: Gauge,
    registry: Registry,
}

impl MetricsCollector {
    pub fn new() -> Self {
        let registry = Registry::new();

        let cpu_usage_gauge = Gauge::with_opts(opts!("cpu_usage", "CPU usage percentage")).unwrap();
        let ram_usage_gauge = Gauge::with_opts(opts!("ram_usage", "RAM usage in bytes")).unwrap();
        let disk_usage_gauge = Gauge::with_opts(opts!("disk_usage", "Disk usage in bytes")).unwrap();

        registry.register(Box::new(cpu_usage_gauge.clone())).unwrap();
        registry.register(Box::new(ram_usage_gauge.clone())).unwrap();
        registry.register(Box::new(disk_usage_gauge.clone())).unwrap();

        Self {
            system: Arc::new(RwLock::new(System::new_all())),
            custom_metrics: Arc::new(RwLock::new(HashMap::new())),
            cpu_usage_gauge,
            ram_usage_gauge,
            disk_usage_gauge,
            registry,
        }
    }

    pub async fn gather_system_metrics(&self) {
        let mut system = self.system.write().await;
        system.refresh_all();

        let cpu_usage = system.global_processor_info().cpu_usage();
        let ram_usage = system.used_memory() as f64;
        let disk_usage: u64 = system.disks().iter().map(|d| d.total_space() - d.available_space()).sum();

        self.cpu_usage_gauge.set(cpu_usage.into());
        self.ram_usage_gauge.set(ram_usage);
        self.disk_usage_gauge.set(disk_usage as f64);
    }

    pub async fn report_custom_metric(&self, name: String, value: String) {
        let mut custom_metrics = self.custom_metrics.write().await;
        custom_metrics.insert(name.clone(), value.clone());
    }

    pub async fn export_metrics(&self, _req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let encoder = TextEncoder::new();

        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        let response = Response::builder()
            .header("Content-Type", encoder.format_type())
            .body(Body::from(buffer))
            .unwrap();

        Ok(response)
    }

    pub async fn serve_metrics(&self, addr: &str) {
        let make_svc = make_service_fn(|_conn| {
            let collector = self.clone();
            async {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let collector = collector.clone();
                    async move {
                        match (req.method(), req.uri().path()) {
                            (&Method::GET, "/metrics") => collector.export_metrics(req).await,
                            _ => Ok(Response::new(Body::from("Not Found"))),
                        }
                    }
                }))
            }
        });

        let addr = addr.parse().unwrap();
        let server = Server::bind(&addr).serve(make_svc);
        if let Err(e) = server.await {
            eprintln!("server error: {}", e);
        }
    }
}

impl Clone for MetricsCollector {
    fn clone(&self) -> Self {
        Self {
            system: self.system.clone(),
            custom_metrics: self.custom_metrics.clone(),
            cpu_usage_gauge: self.cpu_usage_gauge.clone(),
            ram_usage_gauge: self.ram_usage_gauge.clone(),
            disk_usage_gauge: self.disk_usage_gauge.clone(),
            registry: self.registry.clone(),
        }
    }
}
