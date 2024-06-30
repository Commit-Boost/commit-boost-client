use std::process::{Command, Stdio};

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
        .output()?;

    Ok(())
}
