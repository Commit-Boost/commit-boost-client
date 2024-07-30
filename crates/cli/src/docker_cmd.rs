use std::process::{Command, Stdio};

use std::fs;
use chrono::{Utc, Duration as ChronoDuration};


pub fn handle_docker_start(compose_path: String, env_path: String) -> eyre::Result<()> {
    println!("Starting Commit-Boost with compose file: {}", compose_path);

    // load env file
    let env_file = dotenvy::from_filename_override(env_path)?;

    println!("Loaded env file: {:?}", env_file);

    // TODO: if permission denied, print warning to run as sudo

    // start docker compose
    Command::new("docker")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .arg("compose")
        .arg("-f")
        .arg(compose_path)
        .arg("up")
        .arg("-d")
        .output()?;

    Ok(())
}

pub fn handle_docker_stop(compose_path: String, env_path: String) -> eyre::Result<()> {
    println!("Stopping Commit-Boost with compose file: {}", compose_path);

    // load env file
    dotenvy::from_filename_override(env_path)?;

    // TODO: if permission denied, print warning to run as sudo

    // start docker compose
    Command::new("docker")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .arg("compose")
        .arg("-f")
        .arg(compose_path)
        .arg("down")
        .output()?;

    Ok(())
}

pub async fn handle_docker_logs(compose_path: String, log_file_name: Option<String>, retention_period_days: Option<i64>) -> Result<()> {
    let log_file_name = log_file_name.unwrap_or_else(|| "logs.txt".to_string());
    let retention_period_days = retention_period_days.unwrap_or(1);

    println!("Querying Commit-Boost with compose file: {}", compose_path);

    // Create or append to the log file
    let file = File::create(&log_file_name)?;
    let mut writer = BufWriter::new(file);

    // Start docker compose and redirect output to log file
    let mut child = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(&compose_path)
        .arg("logs")
        .arg("-f")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdout) = child.stdout.take() {
        std::io::copy(&mut stdout, &mut writer)?;
    }

    if let Some(mut stderr) = child.stderr.take() {
        std::io::copy(&mut stderr, &mut writer)?;
    }
}
