use eyre::Result;
use time::OffsetDateTime;
use tracing::{Event, Level, Subscriber};
use tracing_appender::{non_blocking::WorkerGuard, rolling::Rotation};
use tracing_subscriber::{
    fmt::{self, FmtContext},
    registry::LookupSpan,
    Layer as SubscriberLayer,
    Registry,
    EnvFilter,
    prelude::*,
};

use crate::config::{load_optional_env_var, LogDest, LogFormat, LogsSettings, PBS_MODULE_NAME};

pub struct RawFormatter;

impl RawFormatter {
    pub fn new() -> Self {
        RawFormatter
    }
}

impl<S, N> fmt::FormatEvent<S, N> for RawFormatter 
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: fmt::format::Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        // Write timestamp
        let now = OffsetDateTime::now_utc();
        write!(writer, "timestamp={} ", now.format(&time::format_description::well_known::Rfc3339).unwrap())?;

        // Write log level
        write!(writer, "log_level={} ", event.metadata().level().to_string().to_uppercase())?;

        // Write target/method
        write!(writer, "method={} ", event.metadata().target())?;

        // Write span fields and event fields
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

pub struct JsonFormatter;

impl JsonFormatter {
    pub fn new() -> Self {
        JsonFormatter
    }
}

impl<S, N> fmt::FormatEvent<S, N> for JsonFormatter 
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: fmt::format::Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        use serde_json::json;

        let timestamp = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();

        // Start with base fields
        let mut output = json!({
            "timestamp": timestamp,
            "log_level": event.metadata().level().to_string().to_uppercase(),
            "method": event.metadata().target(),
        });

        // Add event fields directly to root
        if let serde_json::Value::Object(ref mut map) = output {
            let mut visitor = JsonVisitor(map);
            event.record(&mut visitor);
        }

        writeln!(writer, "{}", serde_json::to_string(&output).unwrap())
    }
}

struct JsonVisitor<'a>(&'a mut serde_json::Map<String, serde_json::Value>);

impl<'a> tracing::field::Visit for JsonVisitor<'a> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_string(), serde_json::Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_string(), serde_json::Value::String(format!("{:?}", value)));
    }
}

// Moved from utils.rs
pub fn initialize_tracing_log(module_id: &str) -> Result<WorkerGuard> {
    // Load settings from environment/config, use defaults if not configured
    let settings = LogsSettings::from_env_config()?.unwrap_or_default();

    // Get log level from RUST_LOG env var or settings
    let log_level = if let Some(log_level) = load_optional_env_var("RUST_LOG") {
        log_level.parse::<Level>().expect("invalid RUST_LOG value")
    } else {
        settings.log_level.parse::<Level>().expect("invalid log_level value in settings")
    };

    // Create filter for commit-boost crates with specified log level
    let filter = format_crates_filter(Level::INFO.as_str(), log_level.as_str());

    match settings.destination {
        // Stdout only - use specified LogFormat
        LogDest::Stdout => {
            let (_, guard) = tracing_appender::non_blocking(std::io::stdout());
            let layer = settings.create_format_layer();
            tracing_subscriber::registry()
                .with(layer.with_filter(filter))
                .init();
            Ok(guard)
        }

        // File output only - use specified LogFormat
        LogDest::File => {
            // Set up daily rotating log files
            let file_appender = tracing_appender::rolling::Builder::new()
                .filename_prefix(module_id.to_lowercase())
                .max_log_files(settings.max_log_files.unwrap_or_default())
                .rotation(Rotation::DAILY)
                .build(settings.log_dir_path.clone())
                .expect("failed building rolling file appender");

            let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
            
            // Create layer with configured format
            let layer: Box<dyn SubscriberLayer<Registry> + Send + Sync> = match settings.format {
                LogFormat::Json => Box::new(fmt::layer().event_format(JsonFormatter).with_writer(file_writer)),
                LogFormat::Raw => Box::new(fmt::layer().event_format(RawFormatter).with_writer(file_writer)),
                _ => Box::new(fmt::layer().with_writer(file_writer)),
            };

            tracing_subscriber::registry()
                .with(layer.with_filter(filter))
                .init();
            Ok(guard)
        }

        // Both outputs - use specified LogFormat for both
        LogDest::Both => {
            // Set up daily rotating log files
            let file_appender = tracing_appender::rolling::Builder::new()
                .filename_prefix(module_id.to_lowercase())
                .filename_suffix("log")
                .max_log_files(settings.max_log_files.unwrap_or_default())
                .rotation(Rotation::DAILY)
                .build(settings.log_dir_path.clone())
                .expect("failed building rolling file appender");

            let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
            let (stdout_writer, _) = tracing_appender::non_blocking(std::io::stdout());

            // Create layers with configured format for both outputs
            let file_layer: Box<dyn SubscriberLayer<Registry> + Send + Sync> = match settings.format {
                LogFormat::Json => Box::new(fmt::layer().json().with_writer(file_writer)),
                LogFormat::Raw => Box::new(fmt::layer().event_format(RawFormatter).with_writer(file_writer)),
                _ => Box::new(fmt::layer().with_writer(file_writer)),
            };
            let stdout_layer: Box<dyn SubscriberLayer<Registry> + Send + Sync> = match settings.format {
                LogFormat::Json => Box::new(fmt::layer().json().with_writer(stdout_writer)),
                LogFormat::Raw => Box::new(fmt::layer().event_format(RawFormatter).with_writer(stdout_writer)),
                _ => Box::new(fmt::layer().with_writer(stdout_writer)),
            };

            // Create separate filters to avoid cloning
            let file_filter = format_crates_filter(Level::INFO.as_str(), log_level.as_str());
            let stdout_filter = format_crates_filter(Level::INFO.as_str(), log_level.as_str());

            // Initialize registry with both layers
            tracing_subscriber::registry()
                .with(vec![
                    file_layer.with_filter(file_filter),
                    stdout_layer.with_filter(stdout_filter),
                ])
                .init();
            Ok(guard)
        }
    }
}

pub fn initialize_pbs_tracing_log() -> Result<WorkerGuard> {
    initialize_tracing_log(PBS_MODULE_NAME)
}

// all commit boost crates
fn format_crates_filter(default_level: &str, crates_level: &str) -> EnvFilter {
    let s = format!(
        "{default_level},cb_signer={crates_level},cb_pbs={crates_level},cb_common={crates_level},cb_metrics={crates_level}",
    );
    s.parse().unwrap()
}

#[cfg(test)]
mod tests {
    use crate::config::CommitBoostConfig;

    use super::*;
    use std::io::Write;
    use alloy::primitives::U256;
    use tempfile::tempdir;
    use tracing::info;
    use tracing_subscriber::fmt::writer::TestWriter;

    fn setup_test_config(dir: &tempfile::TempDir, settings: &LogsSettings) -> Result<()> {
        let config = CommitBoostConfig{
            chain: crate::types::Chain::Mainnet,
            relays: vec![],
            pbs: crate::config::StaticPbsConfig{
                pbs_config: crate::config::PbsConfig{
                    host: "0.0.0.0".parse().unwrap(),
                    port: 8080,
                    relay_check: true,
                    wait_all_registrations: true,
                    timeout_get_header_ms: 1000,
                    timeout_get_payload_ms: 1000,
                    timeout_register_validator_ms: 1000,
                    skip_sigverify: false,
                    min_bid_wei: U256::from(10000),
                    relay_monitors: vec![],
                    late_in_slot_time_ms: 1000,
                    extra_validation_enabled: false,
                    rpc_url: None,
                },
                docker_image: "".to_string(),
                with_signer: false,
            },
            logs: Some(settings.clone()),
            muxes: None,
            modules: None,
            signer: None,
            metrics: None,
        };
        let config = toml::to_string(&config)?;
        std::fs::write(dir.path().join("config.toml"), config)?;
        std::env::set_var("CB_CONFIG", dir.path().join("config.toml"));
        Ok(())
    }

    #[test]
    fn test_initialize_tracing_log_stdout() -> Result<()> {
        let dir = tempdir()?;
        std::env::set_var("RUST_LOG", "debug");
        
        let mut settings = LogsSettings::default();
        settings.destination = LogDest::Stdout;
        settings.format = LogFormat::Raw;
        settings.log_dir_path = dir.path().to_path_buf();

        setup_test_config(&dir, &settings)?;

        let _guard = initialize_tracing_log("test")?;
        info!("test message");
        Ok(())
    }

    #[test]
    fn test_initialize_tracing_log_file() -> Result<()> {
        let dir = tempdir()?;
        std::env::set_var("RUST_LOG", "debug");
        
        let mut settings = LogsSettings::default();
        settings.destination = LogDest::File;
        settings.format = LogFormat::Raw;
        settings.log_dir_path = dir.path().to_path_buf();

        setup_test_config(&dir, &settings)?;

        let _guard = initialize_tracing_log("test")?;

        // Verify log file was created - look for files starting with "test"
        let log_files = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let is_log = e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.starts_with("test"))
                    .unwrap_or(false);
                is_log
            })
            .count();
        assert_eq!(log_files, 1, "Expected 1 log file, found {}", log_files);
        Ok(())
    }

    #[test]
    fn test_initialize_tracing_log_both() -> Result<()> {
        let dir = tempdir()?;
        std::env::set_var("RUST_LOG", "debug");
        
        let mut settings = LogsSettings::default();
        settings.destination = LogDest::Both;
        settings.format = LogFormat::Raw;
        settings.log_dir_path = dir.path().to_path_buf();

        setup_test_config(&dir, &settings)?;

        let _guard = initialize_tracing_log("test")?;
        info!("test message");

        // Verify log file was created
        let log_files = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("log"))
            .count();
        assert_eq!(log_files, 1);
        Ok(())
    }

    #[test]
    fn test_file_logging_raw_format() -> Result<()> {
        let dir = tempdir()?;
        std::env::set_var("RUST_LOG", "debug");
        
        let mut settings = LogsSettings::default();
        settings.destination = LogDest::File;
        settings.format = LogFormat::Raw;
        settings.log_dir_path = dir.path().to_path_buf();

        setup_test_config(&dir, &settings)?;

        let _guard = initialize_tracing_log("test")?;
        info!(field = "value", "test message");

        // Give the non-blocking writer a moment to flush
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Find and read the log file
        let log_file = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .find(|e| {
                let is_log = e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.starts_with("test"))
                    .unwrap_or(false);
                is_log
            })
            .expect("Log file not found");

        let contents = std::fs::read_to_string(log_file.path())?;
        println!("File contents:\n{}", contents);

        assert!(contents.contains("log_level=INFO"), "Missing log level");
        assert!(contents.contains("\"value\""), "Missing value");
        assert!(contents.contains("test message"), "Missing message");
        assert!(contents.contains("method=cb_common::logging::tests"), "Missing method");

        Ok(())
    }

    #[test]
    fn test_file_logging_json_format() -> Result<()> {
        let dir = tempdir()?;
        std::env::set_var("RUST_LOG", "debug");
        
        let mut settings = LogsSettings::default();
        settings.destination = LogDest::File;
        settings.format = LogFormat::Json;
        settings.log_dir_path = dir.path().to_path_buf();

        setup_test_config(&dir, &settings)?;

        let _guard = initialize_tracing_log("test")?;
        info!(
            req_id = "test-123",
            relay_id = "test-relay",
            msg = "test message",
            latency = "100ms",
        );

        // Give the non-blocking writer a moment to flush
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Find and read the log file
        let log_file = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .find(|e| e.path()
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.starts_with("test"))
                .unwrap_or(false))
            .expect("Log file not found");

        let contents = std::fs::read_to_string(log_file.path())?;
        println!("File contents:\n{}", contents);

        let json: serde_json::Value = serde_json::from_str(&contents)?;
        assert_eq!(json["log_level"], "INFO", "Wrong log level");
        assert_eq!(json["method"], "cb_common::logging::tests", "Wrong method");
        assert_eq!(json["req_id"], "test-123", "Wrong req_id");
        assert_eq!(json["relay_id"], "test-relay", "Wrong relay_id");
        assert_eq!(json["msg"], "test message", "Wrong message");
        assert_eq!(json["latency"], "100ms", "Wrong latency");

        Ok(())
    }
} 