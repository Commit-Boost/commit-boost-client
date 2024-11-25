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
                                eprintln!("Warning: Permission denied. Follow Docker's official post-installation steps to add your user to the docker group: https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user");
                                std::process::exit(1);
                            } else {
                                eprintln!("Command failed with error: {}", stderr);
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to execute command: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            None => {
                eprintln!("Neither `docker compose` nor `docker-compose` were found on your operating system.");
                std::process::exit(1);
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
    windows_not_supported();

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
    windows_not_supported();

    // load env file
    dotenvy::from_filename_override(env_path)?;

    // start docker compose
    run_docker_compose!(compose_path, "down");

    Ok(())
}

pub fn handle_docker_logs(compose_path: String) -> Result<()> {
    println!("Querying Commit-Boost with compose file: {}", compose_path);
    windows_not_supported();

    // start docker compose
    run_docker_compose!(compose_path, "logs", "-f");

    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_not_supported() {
    eprintln!(
        "Windows is currently only partially supported, please run `docker compose` manually and consider filing an issue at https://github.com/Commit-Boost/commit-boost-client"
    );
    std::process::exit(1);
}

#[cfg(not(target_os = "windows"))]
fn windows_not_supported() {}
