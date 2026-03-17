use assert_cmd::{Command, cargo};
use cb_cli::docker_init::{CB_COMPOSE_FILE, CB_ENV_FILE};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const MINIMAL_PBS_TOML: &str = r#"
chain = "Holesky"
[pbs]
docker_image = "ghcr.io/commit-boost/pbs:latest"
"#;

const MINIMAL_WITH_MODULE_TOML: &str = r#"
chain = "Holesky"
[pbs]
docker_image = "ghcr.io/commit-boost/pbs:latest"

[signer.local.loader]
key_path = "/keys/keys.json"

[[modules]]
id = "DA_COMMIT"
type = "commit"
docker_image = "test_da_commit"
"#;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns a `Command` pointed at the `commit-boost` binary under test.
fn cmd() -> Command {
    Command::new(cargo::cargo_bin!())
}

/// Writes `contents` to `cb.toml` inside `dir` and returns the path.
fn write_config(dir: &tempfile::TempDir, contents: &str) -> std::path::PathBuf {
    let path = dir.path().join("cb.toml");
    std::fs::write(&path, contents).expect("write test config");
    path
}

/// Returns a `commit-boost init` command configured with the given config and
/// output directory.
fn init_cmd(config: &std::path::Path, output_dir: &std::path::Path) -> Command {
    let mut c = cmd();
    c.args([
        "init",
        "--config",
        config.to_str().expect("valid config path"),
        "--output",
        output_dir.to_str().expect("valid output dir"),
    ]);
    c
}

// ---------------------------------------------------------------------------
// Binary smoke tests
// ---------------------------------------------------------------------------

/// Tests that the binary can be run and returns a version string
#[test]
fn test_load_example_config() {
    let expected_version = format!("Commit-Boost {}\n", commit_boost::VERSION);
    cmd().arg("--version").assert().success().stdout(expected_version);
}

/// Tests that the init command can be run and complains about not having
/// --config set
#[test]
fn test_run_init() {
    cmd().args(["init"]).assert().failure().stderr(predicates::str::contains(
        "error: the following required arguments were not provided:\n  --config <CONFIG_PATH>",
    ));
}

/// Tests that PBS runs without CB_CONFIG being set and complains normally
#[test]
fn test_run_pbs_no_config() {
    cmd()
        .args(["pbs"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("CB_CONFIG is not set"));
}

/// Tests that Signer runs without CB_CONFIG being set and complains normally
#[test]
fn test_run_signer_no_config() {
    cmd()
        .args(["signer"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("CB_CONFIG is not set"));
}

// ---------------------------------------------------------------------------
// handle_docker_init (via `commit-boost init`) integration tests
// ---------------------------------------------------------------------------

/// Minimal PBS-only config produces a compose file and no .env file.
#[test]
fn test_init_pbs_only_creates_compose_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(&dir, MINIMAL_PBS_TOML);

    init_cmd(&config, dir.path()).assert().success();

    assert!(dir.path().join(CB_COMPOSE_FILE).exists(), "compose file should be created");
    assert!(!dir.path().join(CB_ENV_FILE).exists(), "no .env file for PBS-only config");
}

/// PBS-only compose file has the expected service structure.
#[test]
fn test_init_compose_file_pbs_service_structure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(&dir, MINIMAL_PBS_TOML);

    init_cmd(&config, dir.path()).assert().success();

    let contents =
        std::fs::read_to_string(dir.path().join(CB_COMPOSE_FILE)).expect("read compose file");
    let compose: serde_yaml::Value =
        serde_yaml::from_str(&contents).expect("compose file is valid YAML");

    let pbs = &compose["services"]["cb_pbs"];
    assert!(!pbs.is_null(), "cb_pbs service must exist");
    assert_eq!(pbs["image"].as_str(), Some("ghcr.io/commit-boost/pbs:latest"), "image");
    assert_eq!(pbs["container_name"].as_str(), Some("cb_pbs"), "container_name");

    // Config file must be mounted inside the container.
    let volumes = pbs["volumes"].as_sequence().expect("volumes is a list");
    assert!(
        volumes.iter().any(|v| v.as_str().map_or(false, |s| s.ends_with(":/cb-config.toml:ro"))),
        "config must be mounted at /cb-config.toml"
    );

    // Required environment variables must be present.
    let env = &pbs["environment"];
    assert!(!env["CB_CONFIG"].is_null(), "CB_CONFIG env var must be set");
    assert!(!env["CB_PBS_ENDPOINT"].is_null(), "CB_PBS_ENDPOINT env var must be set");

    // Port 18550 must be exposed.
    let ports = pbs["ports"].as_sequence().expect("ports is a list");
    assert!(
        ports.iter().any(|p| p.as_str().map_or(false, |s| s.contains("18550"))),
        "port 18550 must be exposed"
    );

    // No signer service and no extra network in a PBS-only config.
    assert!(compose["services"]["cb_signer"].is_null(), "cb_signer must not exist");
    assert!(compose["networks"].is_null(), "no networks for PBS-only config");
}

/// Config with a commit module produces both a compose file and a .env file.
#[test]
fn test_init_with_module_creates_env_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(&dir, MINIMAL_WITH_MODULE_TOML);

    init_cmd(&config, dir.path()).assert().success();

    assert!(dir.path().join(CB_COMPOSE_FILE).exists(), "compose file should be created");
    assert!(dir.path().join(CB_ENV_FILE).exists(), ".env file should be created for modules");
}

/// .env file contains a JWT entry for the module.
#[test]
fn test_init_env_file_contains_module_jwt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(&dir, MINIMAL_WITH_MODULE_TOML);

    init_cmd(&config, dir.path()).assert().success();

    let env_contents =
        std::fs::read_to_string(dir.path().join(CB_ENV_FILE)).expect("read .env file");
    assert!(env_contents.contains("CB_JWT_DA_COMMIT="), ".env must contain module JWT");
}

/// Missing --config argument produces a clear error message.
#[test]
fn test_init_missing_config_flag_fails_with_message() {
    cmd().args(["init"]).assert().failure().stderr(predicates::str::contains("--config"));
}

/// Non-existent config file produces an error.
#[test]
fn test_init_nonexistent_config_file_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    cmd()
        .args([
            "init",
            "--config",
            "/nonexistent/path/cb.toml",
            "--output",
            dir.path().to_str().expect("valid dir"),
        ])
        .assert()
        .failure();
}
