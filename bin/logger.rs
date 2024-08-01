use chrono::{Utc, Duration as ChronoDuration};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, copy};
use tokio::time::{sleep, Duration};
use std::process::{Command, Stdio};
use tokio::task;
use std::time::SystemTime;
use cb_common::config::load_logger_config;
use std::os::unix::fs::PermissionsExt;

#[tokio::main]
async fn main() {
    let logger_config = load_logger_config().expect("failed to load logger config");

    let retention_duration = ChronoDuration::days(logger_config.retention_period_days.try_into().unwrap());
    let collection_interval = Duration::from_secs(logger_config.log_collection_interval_secs);
    let log_dir = logger_config.log_dir.clone();

    // Ensure the log directory exists and has the correct permissions
    if let Err(e) = fs::create_dir_all(&log_dir) {
        eprintln!("Failed to create log directory: {}", e);
        return;
    }

    if let Err(e) = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o775)) {
        eprintln!("Failed to set permissions for log directory: {}", e);
        return;
    }

    // Clone log_dir for use in the retention task
    let log_dir_retention = log_dir.clone();
    let retention_handle = task::spawn(async move {
        loop {
            sleep(Duration::from_secs(86400)).await; // Sleep for one day
            let cutoff = Utc::now() - retention_duration;
            let cutoff_system_time = SystemTime::from(cutoff);
            
            if let Ok(entries) = fs::read_dir(&log_dir_retention) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        if let Ok(metadata) = entry.metadata() {
                            if let Ok(modified) = metadata.modified() {
                                if modified < cutoff_system_time {
                                    let _ = fs::remove_file(entry.path());
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // Clone log_dir for use in the collection task
    let log_dir_collection = log_dir.clone();
    let collection_handle = task::spawn(async move {
        let mut last_log_file_name = String::new();

        loop {
            let now = Utc::now();
            let log_file_name = format!("{}/log_{}.log", log_dir_collection, now.format("%Y-%m-%d"));

            // Check if the log file name needs to be updated
            if log_file_name != last_log_file_name {
                last_log_file_name = log_file_name.clone();
            }

            // Check if the directory exists and create if necessary
            if let Err(e) = fs::create_dir_all(&log_dir_collection) {
                eprintln!("Failed to create log directory: {}", e);
                continue;
            }

            let file = match OpenOptions::new().append(true).create(true).open(&log_file_name) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Failed to open log file: {}", e);
                    continue;
                }
            };

            let mut writer = BufWriter::new(file);
            let since_time = format!("{}", now.format("%Y-%m-%dT%H:%M:%SZ"));

            let mut child = match Command::new("docker")
                .arg("compose")
                .arg("-f")
                .arg(&logger_config.compose_path)
                .arg("logs")
                .arg("--since")
                .arg(&since_time) // Collect logs until the current time
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn() {
                    Ok(child) => child,
                    Err(e) => {
                        eprintln!("Failed to start docker-compose logs command: {}", e);
                        continue;
                    }
                };

            if let Some(mut stdout) = child.stdout.take() {
                if let Err(e) = copy(&mut stdout, &mut writer) {
                    eprintln!("Failed to write stdout to log file: {}", e);
                }
            }

            if let Some(mut stderr) = child.stderr.take() {
                if let Err(e) = copy(&mut stderr, &mut writer) {
                    eprintln!("Failed to write stderr to log file: {}", e);
                }
            }

            sleep(collection_interval).await;
        }
    });

    // Use tokio::join! to wait for both tasks to complete and handle results
    let (retention_result, collection_result) = tokio::join!(retention_handle, collection_handle);

    if let Err(e) = retention_result {
        eprintln!("Log retention task failed: {}", e);
    }

    if let Err(e) = collection_result {
        eprintln!("Log collection task failed: {}", e);
    }
}
