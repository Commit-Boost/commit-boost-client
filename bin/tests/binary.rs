use assert_cmd::{Command, cargo};

/// Tests that the binary can be run and returns a version string
#[test]
fn test_load_example_config() {
    let mut cmd = Command::new(cargo::cargo_bin!());
    let expected_version = format!("Commit-Boost {}\n", commit_boost::VERSION);
    cmd.arg("--version").assert().success().stdout(expected_version);
}

/// Tests that the init command can be run and complains about not having
/// --config set
#[test]
fn test_run_init() {
    let mut cmd = Command::new(cargo::cargo_bin!());
    cmd.args(["init"]).assert().failure().stderr(predicates::str::contains(
        "error: the following required arguments were not provided:\n  --config <CONFIG_PATH>",
    ));
}

/// Tests that PBS runs without CB_CONFIG being set and complains normally
#[test]
fn test_run_pbs_no_config() {
    let mut cmd = Command::new(cargo::cargo_bin!());
    cmd.args(["pbs"]).assert().failure().stderr(predicates::str::contains("CB_CONFIG is not set"));
}

/// Tests that Signer runs without CB_CONFIG being set and complains normally
#[test]
fn test_run_signer_no_config() {
    let mut cmd = Command::new(cargo::cargo_bin!());
    cmd.args(["signer"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("CB_CONFIG is not set"));
}
