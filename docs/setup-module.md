# Setting up a lean custom module in Rust
1. Currently `cb_*` crates are not uploaded to crates.io , so easiest way to get started is to clone the commit-boost-client repo and initialize a new module in the examples folder
2. Initialize a new project using `cargo new <my_module_name>`
3. The Cargo.toml needs to have the cb_* dependencies from the root project
```[dependencies]
cb-cli.workspace = true
cb-common.workspace = true
cb-pbs.workspace = true
cb-crypto.workspace = true```
4. Import the cb modules in your main.rs:
```use cb_common::{
    commit::request::SignRequest,
    config::{load_module_config, StartModuleConfig},
    utils::initialize_tracing_log,
};
use cb_metrics::sdk::MetricsProvider;```
5. Declare the extra config you need to parse in a struct:
```// Extra configurations parameters can be set here and will be automatically parsed from the
// .config.toml file These parameters will be in the .extra field of the
// StartModuleConfig<ExtraConfig> struct you get after calling
// `load_module_config::<ExtraConfig>()`
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    sleep_secs: u64,
}```

6. Your main method needs to have the setup boilerplate code:
```#[tokio::main]
async fn main() {
    initialize_tracing_log();

    match load_module_config::<ExtraConfig>() {
        Ok(config) => {
            info!(
                module_id = config.id,
                sleep_secs = config.extra.sleep_secs,
                "Starting module with custom data"
            );

            let service = DaCommitService { config };

            if let Err(err) = service.run().await {
                error!(?err, "Service failed");
            }
        }
        Err(err) => {
            error!(?err, "Failed to load module config");
        }
    }
}```
## Build docker container
Firstly, ensure you have Docker Engine up and running and authenticate using:
```docker login```
Then give execute permissions to the `scripts/build_local_modules.sh` script:
```chmod +x scripts/build_local_modules.sh```