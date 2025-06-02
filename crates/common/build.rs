use std::process::Command;

fn main() {
    let target = std::env::var("TARGET").unwrap();
    let host = std::env::var("HOST").unwrap();

    if target != host {
        println!("cargo:warning=Skipping build script because TARGET != HOST");
        return;
    }

    let output = Command::new("git").args(["rev-parse", "HEAD"]).output().unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();
    println!("cargo:rustc-env=GIT_HASH={git_hash}");
}
