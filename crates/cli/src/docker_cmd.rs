use std::{
    mem,
    process::{Command, Stdio},
    str,
};

use eyre::Result;

macro_rules! run_docker_compose {
    ($compose_path:expr, $($arg:expr),*) => {{
        let cmd_info = determine_docker_compose_command();
        match cmd_info {
            Some((mut command, _version)) => {
                // Set the COMPOSE_FILE environment variable
                command.env("COMPOSE_FILE", $compose_path);

                match command.args(&[$($arg),*]).output() {
                    Ok(output) => {
                        if !output.status.success() {
                            let stderr = str::from_utf8(&output.stderr).unwrap_or("");
                            if stderr.contains("permission denied") {
                                println!("Warning: Permission denied. Try running with sudo.");
                            } else {
                                println!("Command failed with error: {}", stderr);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Failed to execute command: {}", e);
                    }
                }
            }
            None => {
                println!("Neither `docker compose` nor `docker-compose` were found on your operating system.");
            }
        }
    }};
}

fn determine_docker_compose_command() -> Option<(Command, &'static str)> {
    if is_command_available("docker compose") {
        let mut docker: Command = Command::new("docker");
        Some((
            mem::replace(
                docker.arg("compose").stdout(Stdio::inherit()).stderr(Stdio::inherit()),
                Command::new("docker"),
            ),
            "v2",
        ))
    } else if is_command_available("docker-compose") {
        println!(
            "using docker-compose. the command is being deprecated, install docker compose plugin"
        );
        let mut docker: Command = Command::new("docker-compose");
        Some((
            mem::replace(
                docker.stdout(Stdio::inherit()).stderr(Stdio::inherit()),
                Command::new("docker"),
            ),
            "v1",
        ))
    } else {
        None
    }
}

fn is_command_available(command: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {}", command))
        .output()
        .map_or(false, |output| output.status.success())
}

pub fn handle_docker_start(compose_path: String, env_path: Option<String>) -> Result<()> {
    println!("Starting Commit-Boost with compose file: {}", compose_path);

    // load env file if present
    if let Some(env_path) = env_path {
        let env_file = dotenvy::from_filename_override(env_path)?;
        println!("Loaded env file: {:?}", env_file);
    }

    // start docker compose
    run_docker_compose!(compose_path, "up", "-d");

    Ok(())
}

pub fn handle_docker_stop(compose_path: String, env_path: String) -> Result<()> {
    println!("Stopping Commit-Boost with compose file: {}", compose_path);

    // load env file
    dotenvy::from_filename_override(env_path)?;

    // start docker compose
    run_docker_compose!(compose_path, "down");

    Ok(())
}

// TODO: we shouldnt use docker logs
pub fn handle_docker_logs(compose_path: String) -> Result<()> {
    println!("Querying Commit-Boost with compose file: {}", compose_path);

    // start docker compose
    run_docker_compose!(compose_path, "logs", "-f");

    Ok(())
}
