use std::{
    path::{Path, PathBuf},
    vec,
};

use cb_common::{
    config::{
        CommitBoostConfig, ModuleKind, BUILDER_SERVER_ENV, CB_BASE_LOG_PATH, CB_CONFIG_ENV,
        CB_CONFIG_NAME, JWTS_ENV, METRICS_SERVER_ENV, MODULE_ID_ENV, MODULE_JWT_ENV,
        PBS_MODULE_NAME, SIGNER_DIR_KEYS, SIGNER_DIR_KEYS_ENV, SIGNER_DIR_SECRETS,
        SIGNER_DIR_SECRETS_ENV, SIGNER_KEYS, SIGNER_KEYS_ENV, SIGNER_MODULE_NAME,
        SIGNER_SERVER_ENV,
    },
    loader::SignerLoader,
    utils::{random_jwt, MAX_LOG_FILES_ENV, ROLLING_DURATION_ENV, RUST_LOG_ENV},
};
use docker_compose_types::{
    Compose, ComposeVolume, DependsOnOptions, Environment, Labels, LoggingParameters, MapOrEmpty,
    NetworkSettings, Networks, Ports, Service, Services, SingleValue, TopLevelVolumes, Volumes,
};
use eyre::Result;
use indexmap::IndexMap;
use serde::Serialize;

pub(super) const CB_CONFIG_FILE: &str = "cb-config.toml";
pub(super) const CB_COMPOSE_FILE: &str = "cb.docker-compose.yml";
pub(super) const CB_ENV_FILE: &str = ".cb.env";
pub(super) const CB_TARGETS_FILE: &str = "targets.json"; // needs to match prometheus.yml
pub(super) const PROMETHEUS_DATA_VOLUME: &str = "prometheus-data";
pub(super) const GRAFANA_DATA_VOLUME: &str = "grafana-data";

const DEFAULT_NETWORK: &str = "default_network";
const SIGNER_NETWORK: &str = "signer_network";

/// Builds the docker compose file for the Commit-Boost services

// TODO: do more validation for paths, images, etc
#[allow(unused_assignments)]
pub fn handle_docker_init(config_path: String, output_dir: String) -> Result<()> {
    println!("Initializing Commit-Boost with config file: {}", config_path);

    let cb_config = CommitBoostConfig::from_file(&config_path)?;

    let mut services = IndexMap::new();
    let mut volumes = IndexMap::new();

    // config volume to pass to all services
    let config_volume = Volumes::Simple(format!("./{}:{}:ro", config_path, CB_CONFIG_NAME));

    let mut jwts = IndexMap::new();
    // envs to write in .env file
    let mut envs = IndexMap::from([(CB_CONFIG_ENV.into(), CB_CONFIG_NAME.into())]);
    // targets to pass to prometheus
    let mut targets = Vec::new();
    let metrics_port = 10000;
    let cadvisor_port = 8080;

    // address for signer API communication
    let signer_port = 20000;
    let signer_server = format!("cb_signer:{signer_port}");

    let builder_events_port = 30000;
    let mut builder_events_modules = Vec::new();

    let mut exposed_ports_warn = Vec::new();

    // setup pbs service
    targets.push(PrometheusTargetConfig {
        targets: vec![format!("cb_pbs:{metrics_port}")],
        labels: PrometheusLabelsConfig { job: "pbs".to_owned() },
    });

    let mut pbs_envs = IndexMap::from([
        get_env_same(CB_CONFIG_ENV),
        get_env_uval(METRICS_SERVER_ENV, metrics_port as u64),
        get_env_val(ROLLING_DURATION_ENV, &cb_config.logs.rotation.to_string()),
        get_env_val(RUST_LOG_ENV, &cb_config.logs.log_level),
    ]);
    if let Some(max_files) = cb_config.logs.max_log_files {
        let (key, val) = get_env_uval(MAX_LOG_FILES_ENV, max_files as u64);
        pbs_envs.insert(key, val);
    }

    let mut needs_signer_module = cb_config.pbs.with_signer;

    // setup modules
    if let Some(modules_config) = cb_config.modules {
        for module in modules_config {
            // TODO: support modules volumes and network
            let module_cid = format!("cb_{}", module.id.to_lowercase());

            targets.push(PrometheusTargetConfig {
                targets: vec![format!("{module_cid}:{metrics_port}")],
                labels: PrometheusLabelsConfig { job: module_cid.clone() },
            });

            let module_service = match module.kind {
                // a commit module needs a JWT and access to the signer network
                ModuleKind::Commit => {
                    needs_signer_module = true;

                    let jwt = random_jwt();
                    let jwt_name = format!("CB_JWT_{}", module.id.to_uppercase());

                    // module ids are assumed unique, so envs dont override each other
                    let mut module_envs = IndexMap::from([
                        get_env_val(MODULE_ID_ENV, &module.id),
                        get_env_same(CB_CONFIG_ENV),
                        get_env_interp(MODULE_JWT_ENV, &jwt_name),
                        get_env_uval(METRICS_SERVER_ENV, metrics_port as u64),
                        get_env_val(SIGNER_SERVER_ENV, &signer_server),
                        get_env_val(ROLLING_DURATION_ENV, &cb_config.logs.rotation.to_string()),
                        get_env_val(RUST_LOG_ENV, &cb_config.logs.log_level),
                    ]);
                    if let Some(max_files) = cb_config.logs.max_log_files {
                        let (key, val) = get_env_uval(MAX_LOG_FILES_ENV, max_files as u64);
                        module_envs.insert(key, val);
                    }

                    envs.insert(jwt_name.clone(), jwt.clone());
                    jwts.insert(module.id.clone(), jwt);
                    let log_volume =
                        get_log_volume(cb_config.logs.log_dir_path.clone(), &module.id);
                    Service {
                        container_name: Some(module_cid.clone()),
                        image: Some(module.docker_image),
                        // TODO: allow service to open ports here
                        networks: Networks::Simple(vec![
                            DEFAULT_NETWORK.to_owned(),
                            SIGNER_NETWORK.to_owned(),
                        ]),
                        volumes: vec![config_volume.clone(), log_volume],
                        environment: Environment::KvPair(module_envs),
                        depends_on: DependsOnOptions::Simple(vec!["cb_signer".to_owned()]),
                        ..Service::default()
                    }
                }
                // an event module just needs a port to listen on
                ModuleKind::Events => {
                    // module ids are assumed unique, so envs dont override each other
                    let mut module_envs = IndexMap::from([
                        get_env_val(MODULE_ID_ENV, &module.id),
                        get_env_same(CB_CONFIG_ENV),
                        get_env_uval(METRICS_SERVER_ENV, metrics_port as u64),
                        get_env_val(BUILDER_SERVER_ENV, &builder_events_port.to_string()),
                        get_env_val(ROLLING_DURATION_ENV, &cb_config.logs.rotation.to_string()),
                        get_env_val(RUST_LOG_ENV, &cb_config.logs.log_level),
                    ]);
                    if let Some(max_files) = cb_config.logs.max_log_files {
                        let (key, val) = get_env_uval(MAX_LOG_FILES_ENV, max_files as u64);
                        module_envs.insert(key, val);
                    }

                    builder_events_modules.push(format!("{module_cid}:{builder_events_port}"));
                    let log_volume =
                        get_log_volume(cb_config.logs.log_dir_path.clone(), &module.id);
                    Service {
                        container_name: Some(module_cid.clone()),
                        image: Some(module.docker_image),
                        networks: Networks::Simple(vec![DEFAULT_NETWORK.to_owned()]),
                        volumes: vec![config_volume.clone(), log_volume],
                        environment: Environment::KvPair(module_envs),
                        depends_on: DependsOnOptions::Simple(vec!["cb_pbs".to_owned()]),
                        ..Service::default()
                    }
                }
            };

            services.insert(module_cid, Some(module_service));
        }
    };

    if !builder_events_modules.is_empty() {
        let env = builder_events_modules.join(",");
        let (k, v) = get_env_val(BUILDER_SERVER_ENV, &env);
        pbs_envs.insert(k, v);
    }

    let log_volume = get_log_volume(cb_config.logs.log_dir_path.clone(), PBS_MODULE_NAME);
    exposed_ports_warn
        .push(format!("pbs has an exported port on {}", cb_config.pbs.pbs_config.port));
    let pbs_service = Service {
        container_name: Some("cb_pbs".to_owned()),
        image: Some(cb_config.pbs.docker_image),
        ports: Ports::Short(vec![format!(
            "{}:{}",
            cb_config.pbs.pbs_config.port, cb_config.pbs.pbs_config.port
        )]),
        networks: Networks::Simple(vec![DEFAULT_NETWORK.to_owned()]),
        volumes: vec![config_volume.clone(), log_volume],
        environment: Environment::KvPair(pbs_envs),
        ..Service::default()
    };

    services.insert("cb_pbs".to_owned(), Some(pbs_service));

    // TODO: validate if we have signer modules but not signer config

    // setup signer service

    if let Some(signer_config) = cb_config.signer {
        if needs_signer_module {
            let log_volume =
                get_log_volume(cb_config.logs.log_dir_path.clone(), SIGNER_MODULE_NAME);
            let mut volumes = vec![config_volume.clone(), log_volume];

            targets.push(PrometheusTargetConfig {
                targets: vec![format!("cb_signer:{metrics_port}")],
                labels: PrometheusLabelsConfig { job: "signer".into() },
            });

            let mut signer_envs = IndexMap::from([
                get_env_same(CB_CONFIG_ENV),
                get_env_same(JWTS_ENV),
                get_env_uval(METRICS_SERVER_ENV, metrics_port as u64),
                get_env_uval(SIGNER_SERVER_ENV, signer_port as u64),
                get_env_val(ROLLING_DURATION_ENV, &cb_config.logs.rotation.to_string()),
                get_env_val(RUST_LOG_ENV, &cb_config.logs.log_level),
            ]);
            if let Some(max_files) = cb_config.logs.max_log_files {
                let (key, val) = get_env_uval(MAX_LOG_FILES_ENV, max_files as u64);
                signer_envs.insert(key, val);
            }

            // TODO: generalize this, different loaders may not need volumes but eg ports
            match signer_config.loader {
                SignerLoader::File { key_path } => {
                    volumes.push(Volumes::Simple(format!("./{}:{}:ro", key_path, SIGNER_KEYS)));
                    let (k, v) = get_env_val(SIGNER_KEYS_ENV, SIGNER_KEYS);
                    signer_envs.insert(k, v);
                }
                SignerLoader::ValidatorsDir { keys_path, secrets_path } => {
                    volumes.push(Volumes::Simple(format!("{}:{}:ro", keys_path, SIGNER_DIR_KEYS)));
                    let (k, v) = get_env_val(SIGNER_DIR_KEYS_ENV, SIGNER_DIR_KEYS);
                    signer_envs.insert(k, v);

                    volumes.push(Volumes::Simple(format!(
                        "{}:{}:ro",
                        secrets_path, SIGNER_DIR_SECRETS
                    )));
                    let (k, v) = get_env_val(SIGNER_DIR_SECRETS_ENV, SIGNER_DIR_SECRETS);
                    signer_envs.insert(k, v);
                }
            };

            // write jwts to env
            let jwts_json = serde_json::to_string(&jwts).unwrap().clone();
            envs.insert(JWTS_ENV.into(), format!("{jwts_json:?}"));

            let signer_service = Service {
                container_name: Some("cb_signer".to_owned()),
                image: Some(signer_config.docker_image),
                networks: Networks::Simple(vec![
                    DEFAULT_NETWORK.to_owned(),
                    SIGNER_NETWORK.to_owned(),
                ]),
                volumes,
                environment: Environment::KvPair(signer_envs),
                ..Service::default()
            };

            services.insert("cb_signer".to_owned(), Some(signer_service));
        }
    } else if needs_signer_module {
        panic!("Signer module required but no signer config provided");
    }

    // setup metrics services
    // TODO: make this metrics optional?

    let mut compose = Compose::default();

    compose.networks.0.insert(
        DEFAULT_NETWORK.to_owned(),
        MapOrEmpty::Map(NetworkSettings {
            driver: Some("bridge".to_owned()),
            ..NetworkSettings::default()
        }),
    );
    compose.networks.0.insert(
        SIGNER_NETWORK.to_owned(),
        MapOrEmpty::Map(NetworkSettings {
            driver: Some("bridge".to_owned()),
            ..NetworkSettings::default()
        }),
    );
    if let Some(metrics) = cb_config.metrics {
        let prom_volume = Volumes::Simple(format!(
            "{}:/etc/prometheus/prometheus.yml",
            metrics.prometheus_config
        ));
        // TODO: fix path to targets file
        let targets_volume =
            Volumes::Simple(format!("./{}:/etc/prometheus/targets.json", CB_TARGETS_FILE));

        let data_volume = Volumes::Simple(format!("{}:/prometheus", PROMETHEUS_DATA_VOLUME));

        let grafana_data_volume =
            Volumes::Simple(format!("{}:/var/lib/grafana", GRAFANA_DATA_VOLUME));

        volumes.insert(
            PROMETHEUS_DATA_VOLUME.to_owned(),
            MapOrEmpty::Map(ComposeVolume {
                driver: Some("local".to_owned()),
                driver_opts: IndexMap::default(),
                external: None,
                labels: Labels::default(),
                name: None,
            }),
        );

        volumes.insert(
            GRAFANA_DATA_VOLUME.to_owned(),
            MapOrEmpty::Map(ComposeVolume {
                driver: Some("local".to_owned()),
                driver_opts: IndexMap::default(),
                external: None,
                labels: Labels::default(),
                name: None,
            }),
        );
        exposed_ports_warn.push("prometheus has an exported port on 9090".to_string());
        let prometheus_service = Service {
            container_name: Some("cb_prometheus".to_owned()),
            image: Some("prom/prometheus:latest".to_owned()),
            volumes: vec![prom_volume, targets_volume, data_volume],
            // to inspect prometheus from localhost
            ports: Ports::Short(vec!["9090:9090".to_owned()]),
            networks: Networks::Simple(vec![DEFAULT_NETWORK.to_owned()]),
            ..Service::default()
        };

        services.insert("cb_prometheus".to_owned(), Some(prometheus_service));

        if metrics.use_grafana {
            exposed_ports_warn.push("grafana has an exported port on 3000".to_string());
            let grafana_service = Service {
                container_name: Some("cb_grafana".to_owned()),
                image: Some("grafana/grafana:latest".to_owned()),
                ports: Ports::Short(vec!["3000:3000".to_owned()]),
                networks: Networks::Simple(vec![DEFAULT_NETWORK.to_owned()]),
                depends_on: DependsOnOptions::Simple(vec!["cb_prometheus".to_owned()]),
                environment: Environment::List(vec!["GF_SECURITY_ADMIN_PASSWORD=admin".to_owned()]),
                volumes: vec![
                    Volumes::Simple(
                        "./grafana/dashboards:/etc/grafana/provisioning/dashboards".to_owned(),
                    ),
                    Volumes::Simple(
                        "./grafana/datasources:/etc/grafana/provisioning/datasources".to_owned(),
                    ),
                    grafana_data_volume,
                ],
                // TODO: re-enable logging here once we move away from docker logs
                logging: Some(LoggingParameters { driver: Some("none".to_owned()), options: None }),
                ..Service::default()
            };

            services.insert("cb_grafana".to_owned(), Some(grafana_service));
        }
        exposed_ports_warn.push("cadvisor has an exported port on 8080".to_string());
        services.insert(
            "cb_cadvisor".to_owned(),
            Some(Service {
                container_name: Some("cb_cadvisor".to_owned()),
                image: Some("gcr.io/cadvisor/cadvisor".to_owned()),
                ports: Ports::Short(vec![format!("{cadvisor_port}:8080")]),
                networks: Networks::Simple(vec![DEFAULT_NETWORK.to_owned()]),
                volumes: vec![
                    Volumes::Simple("/var/run/docker.sock:/var/run/docker.sock:ro".to_owned()),
                    Volumes::Simple("/sys:/sys:ro".to_owned()),
                    Volumes::Simple("/var/lib/docker/:/var/lib/docker:ro".to_owned()),
                ],
                ..Service::default()
            }),
        );

        targets.push(PrometheusTargetConfig {
            targets: vec![format!("cb_cadvisor:{cadvisor_port}")],
            labels: PrometheusLabelsConfig { job: "cadvisor".to_owned() },
        });
    } else {
        println!("[WARN]: metrics disabled")
    }

    compose.services = Services(services);
    compose.volumes = TopLevelVolumes(volumes);

    // write compose to file
    let compose_str = serde_yaml::to_string(&compose)?;
    let compose_path = Path::new(&output_dir).join(CB_COMPOSE_FILE);
    // TODO: check if file exists already and avoid overwriting
    std::fs::write(&compose_path, compose_str)?;
    if !exposed_ports_warn.is_empty() {
        println!("\n");
        for exposed_port in exposed_ports_warn {
            println!("Warning: {}", exposed_port);
        }
        println!("\n");
    }
    println!("Compose file written to: {:?}", compose_path);

    // write envs to .env file
    let envs_str = {
        let mut envs_str = String::new();
        for (k, v) in envs {
            envs_str.push_str(&format!("{}={}\n", k, v));
        }
        envs_str
    };
    let env_path = Path::new(&output_dir).join(CB_ENV_FILE);
    // TODO: check if file exists already and avoid overwriting
    std::fs::write(&env_path, envs_str)?;
    println!("Env file written to: {:?}", env_path);

    // write prometheus targets to file
    let targets_str = serde_json::to_string_pretty(&targets)?;
    let targets_path = Path::new(&output_dir).join(CB_TARGETS_FILE);
    // TODO: check if file exists already and avoid overwriting
    std::fs::write(&targets_path, targets_str)?;
    println!("Targets file written to: {:?}", targets_path);

    println!("Run with:\n\t`commit-boost start --docker {:?} --env {:?}`", compose_path, env_path);

    Ok(())
}

// FOO=${FOO}
fn get_env_same(k: &str) -> (String, Option<SingleValue>) {
    get_env_interp(k, k)
}

// FOO=${BAR}
fn get_env_interp(k: &str, v: &str) -> (String, Option<SingleValue>) {
    get_env_val(k, &format!("${{{v}}}"))
}

// FOO=bar
fn get_env_val(k: &str, v: &str) -> (String, Option<SingleValue>) {
    (k.into(), Some(SingleValue::String(v.into())))
}

fn get_env_uval(k: &str, v: u64) -> (String, Option<SingleValue>) {
    (k.into(), Some(SingleValue::Unsigned(v)))
}

/// A prometheus target, use to dynamically add targets to the prometheus config
#[derive(Debug, Serialize)]
struct PrometheusTargetConfig {
    targets: Vec<String>,
    labels: PrometheusLabelsConfig,
}

#[derive(Debug, Serialize)]
struct PrometheusLabelsConfig {
    job: String,
}

fn get_log_volume(host_path: PathBuf, module_id: &str) -> Volumes {
    let p = host_path.join(module_id);
    Volumes::Simple(format!(
        "{}:{}",
        p.to_str().expect("could not convert pathbuf to str"),
        CB_BASE_LOG_PATH
    ))
}
