use chrono::{Utc, Duration as ChronoDuration};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use tokio::time::{sleep, Duration};
use std::process::{Command, Stdio};

/// Initializes logging with log file retention and periodic log collection.
/// 
/// # Arguments
/// * `log_file_name` - The name of the log file to manage.
/// * `retention_period_days` - The number of days logs should be retained.
/// * `log_collection_interval_secs` - Interval in seconds for collecting logs.
pub fn initialize_logging(log_file_name: String, retention_period_days: i64, log_collection_interval_secs: Option<u64>) {
    let retention_duration = ChronoDuration::days(retention_period_days);
    let collection_interval = log_collection_interval_secs.unwrap_or(30);

    // Task for log file retention
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(86400)).await; // Sleep for one day
            let cutoff = Utc::now() - retention_duration;
            if let Ok(metadata) = fs::metadata(&log_file_name) {
                if let Ok(modified) = metadata.modified() {
                    if modified < cutoff.into() {
                        let _ = fs::remove_file(&log_file_name);
                    }
                }
            }
        }
    });

    // Task for collecting and appending logs every specified interval
    tokio::spawn(async move {
        loop {
            let mut file = match OpenOptions::new().append(true).create(true).open(&log_file_name) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Failed to open log file: {}", e);
                    continue;
                }
            };

            let mut writer = BufWriter::new(file);

            let mut child = match Command::new("docker")
                .arg("logs")
                .arg("--since")
                .arg("30s") // Collect logs from the last 30 seconds
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn() {
                    Ok(child) => child,
                    Err(e) => {
                        eprintln!("Failed to start docker logs command: {}", e);
                        continue;
                    }
                };

            if let Some(mut stdout) = child.stdout.take() {
                if let Err(e) = std::io::copy(&mut stdout, &mut writer) {
                    eprintln!("Failed to write stdout to log file: {}", e);
                }
            }

            if let Some(mut stderr) = child.stderr.take() {
                if let Err(e) = std::io::copy(&mut stderr, &mut writer) {
                    eprintln!("Failed to write stderr to log file: {}", e);
                }
            }

            sleep(Duration::from_secs(collection_interval)).await;
        }
    });
}
