use std::process::{Command, Stdio};

use eyre::Result;

pub fn handle_docker_start(compose_path: String, env_path: String) -> Result<()> {
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

pub fn handle_docker_stop(compose_path: String, env_path: String) -> Result<()> {
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

// TODO: we shouldnt use docker logs
pub fn handle_docker_logs(compose_path: String) -> Result<()> {
    println!("Querying Commit-Boost with compose file: {}", compose_path);

    // TODO: if permission denied, print warning to run as sudo

    // start docker compose
    Command::new("docker")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .arg("compose")
        .arg("-f")
        .arg(compose_path)
        .arg("logs")
        .arg("-f")
        .output()?;

    Ok(())
}
