use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    vec,
};

use cb_common::{
    config::{
        CommitBoostConfig, LogsSettings, ModuleKind, BUILDER_PORT_ENV, BUILDER_URLS_ENV,
        CHAIN_SPEC_ENV, CONFIG_DEFAULT, CONFIG_ENV, JWTS_ENV, LOGS_DIR_DEFAULT, LOGS_DIR_ENV,
        METRICS_PORT_ENV, MODULE_ID_ENV, MODULE_JWT_ENV, PBS_ENDPOINT_ENV, PBS_MODULE_NAME,
        PROXY_DIR_DEFAULT, PROXY_DIR_ENV, SIGNER_DEFAULT, SIGNER_DIR_KEYS_DEFAULT,
        SIGNER_DIR_KEYS_ENV, SIGNER_DIR_SECRETS_DEFAULT, SIGNER_DIR_SECRETS_ENV, SIGNER_KEYS_ENV,
        SIGNER_MODULE_NAME, SIGNER_PORT_ENV, SIGNER_URL_ENV,
    },
    signer::{ProxyStore, SignerLoader},
    types::ModuleId,
    utils::random_jwt,
};
use docker_compose_types::{
    Compose, ComposeVolume, DependsOnOptions, EnvFile, Environment, Labels, LoggingParameters,
    MapOrEmpty, NetworkSettings, Networks, Ports, Service, Services, SingleValue, TopLevelVolumes,
    Volumes,
};
use eyre::Result;
use indexmap::IndexMap;
use serde::Serialize;

pub(super) const CB_COMPOSE_FILE: &str = "cb.docker-compose.yml";
pub(super) const CB_ENV_FILE: &str = ".cb.env";
pub(super) const CB_TARGETS_FILE: &str = "targets.json"; // needs to match prometheus.yml
pub(super) const PROMETHEUS_DATA_VOLUME: &str = "prometheus-data";
pub(super) const GRAFANA_DATA_VOLUME: &str = "grafana-data";

const METRICS_NETWORK: &str = "monitoring_network";
const SIGNER_NETWORK: &str = "signer_network";

/// Builds the docker compose file for the Commit-Boost services

// TODO: do more validation for paths, images, etc

pub fn handle_docker_init(config_path: String, output_dir: String) -> Result<()> {
    println!("Initializing Commit-Boost with config file: {}", config_path);
    let cb_config = CommitBoostConfig::from_file(&config_path)?;
    let chain_spec_path = CommitBoostConfig::chain_spec_file(&config_path);

    let metrics_enabled = cb_config.metrics.is_some();
    let log_to_file = cb_config.logs.is_some();

    let mut services = IndexMap::new();
    let mut volumes = IndexMap::new();

    // config volume to pass to all services
    let config_volume = Volumes::Simple(format!("./{}:{}:ro", config_path, CONFIG_DEFAULT));
    let chain_spec_volume = chain_spec_path.as_ref().and_then(|p| {
        // this is ok since the config has already been loaded once
        let file_name = p.file_name()?.to_str()?;
        Some(Volumes::Simple(format!("{}:/{}:ro", p.display(), file_name)))
    });

    let chain_spec_env = chain_spec_path.and_then(|p| {
        // this is ok since the config has already been loaded once
        let file_name = p.file_name()?.to_str()?;
        Some(get_env_val(CHAIN_SPEC_ENV, &format!("/{file_name}")))
    });

    let mut jwts = IndexMap::new();
    // envs to write in .env file
    let mut envs = IndexMap::new();
    // targets to pass to prometheus
    let mut targets = Vec::new();
    let metrics_port = 10000;
    let cadvisor_port = 8080;

    // address for signer API communication
    let signer_port = 20000;
    let signer_server = format!("http://cb_signer:{signer_port}");

    let builder_events_port = 30000;
    let mut builder_events_modules = Vec::new();

    let mut exposed_ports_warn = Vec::new();

    let mut needs_signer_module = cb_config.pbs.with_signer;

    // setup modules
    if let Some(modules_config) = cb_config.modules {
        for module in modules_config {
            let module_cid = format!("cb_{}", module.id.to_lowercase());

            if metrics_enabled {
                targets.push(PrometheusTargetConfig {
                    targets: vec![format!("{module_cid}:{metrics_port}")],
                    labels: PrometheusLabelsConfig { job: module_cid.clone() },
                });
            }

            let module_service = match module.kind {
                // a commit module needs a JWT and access to the signer network
                ModuleKind::Commit => {
                    needs_signer_module = true;

                    let jwt = random_jwt();
                    let jwt_name = format!("CB_JWT_{}", module.id.to_uppercase());

                    // module ids are assumed unique, so envs dont override each other
                    let mut module_envs = IndexMap::from([
                        get_env_val(MODULE_ID_ENV, &module.id),
                        get_env_val(CONFIG_ENV, CONFIG_DEFAULT),
                        get_env_interp(MODULE_JWT_ENV, &jwt_name),
                        get_env_val(SIGNER_URL_ENV, &signer_server),
                    ]);

                    // Pass on the env variables
                    if let Some(envs) = module.env {
                        for (k, v) in envs {
                            module_envs.insert(k, Some(SingleValue::String(v)));
                        }
                    }

                    // Set environment file
                    let env_file = module.env_file.map(EnvFile::Simple);

                    if let Some((key, val)) = chain_spec_env.clone() {
                        module_envs.insert(key, val);
                    }
                    if metrics_enabled {
                        let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
                        module_envs.insert(key, val);
                    }
                    if log_to_file {
                        let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
                        module_envs.insert(key, val);
                    }

                    envs.insert(jwt_name.clone(), jwt.clone());
                    jwts.insert(module.id.clone(), jwt);

                    // networks
                    let mut module_networks = vec![SIGNER_NETWORK.to_owned()];
                    if metrics_enabled {
                        module_networks.push(METRICS_NETWORK.to_owned());
                    }

                    // volumes
                    let mut module_volumes = vec![config_volume.clone()];
                    module_volumes.extend(chain_spec_volume.clone());
                    module_volumes.extend(get_log_volume(&cb_config.logs, &module.id));

                    Service {
                        container_name: Some(module_cid.clone()),
                        image: Some(module.docker_image),
                        networks: Networks::Simple(module_networks),
                        volumes: module_volumes,
                        environment: Environment::KvPair(module_envs),
                        depends_on: DependsOnOptions::Simple(vec!["cb_signer".to_owned()]),
                        env_file,
                        ..Service::default()
                    }
                }
                // an event module just needs a port to listen on
                ModuleKind::Events => {
                    builder_events_modules
                        .push(format!("http://{module_cid}:{builder_events_port}"));

                    // module ids are assumed unique, so envs dont override each other
                    let mut module_envs = IndexMap::from([
                        get_env_val(MODULE_ID_ENV, &module.id),
                        get_env_val(CONFIG_ENV, CONFIG_DEFAULT),
                        get_env_uval(BUILDER_PORT_ENV, builder_events_port),
                    ]);

                    if let Some((key, val)) = chain_spec_env.clone() {
                        module_envs.insert(key, val);
                    }
                    if metrics_enabled {
                        let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
                        module_envs.insert(key, val);
                    }
                    if log_to_file {
                        let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
                        module_envs.insert(key, val);
                    }

                    // networks
                    let modules_networks = if metrics_enabled {
                        Networks::Simple(vec![METRICS_NETWORK.to_owned()])
                    } else {
                        Networks::default()
                    };

                    // volumes
                    let mut module_volumes = vec![config_volume.clone()];
                    module_volumes.extend(chain_spec_volume.clone());
                    module_volumes.extend(get_log_volume(&cb_config.logs, &module.id));

                    Service {
                        container_name: Some(module_cid.clone()),
                        image: Some(module.docker_image),
                        networks: modules_networks,
                        volumes: module_volumes,
                        environment: Environment::KvPair(module_envs),
                        depends_on: DependsOnOptions::Simple(vec!["cb_pbs".to_owned()]),
                        ..Service::default()
                    }
                }
            };

            services.insert(module_cid, Some(module_service));
        }
    };

    // setup pbs service
    if metrics_enabled {
        targets.push(PrometheusTargetConfig {
            targets: vec![format!("cb_pbs:{metrics_port}")],
            labels: PrometheusLabelsConfig { job: "pbs".to_owned() },
        });
    }

    let mut pbs_envs = IndexMap::from([get_env_val(CONFIG_ENV, CONFIG_DEFAULT)]);

    if let Some((key, val)) = chain_spec_env.clone() {
        pbs_envs.insert(key, val);
    }
    if metrics_enabled {
        let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
        pbs_envs.insert(key, val);
    }
    if log_to_file {
        let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
        pbs_envs.insert(key, val);
    }
    if !builder_events_modules.is_empty() {
        let env = builder_events_modules.join(",");
        let (k, v) = get_env_val(BUILDER_URLS_ENV, &env);
        pbs_envs.insert(k, v);
    }

    // ports
    let host_endpoint =
        SocketAddr::from((cb_config.pbs.pbs_config.host, cb_config.pbs.pbs_config.port));
    let ports = Ports::Short(vec![format!("{}:{}", host_endpoint, cb_config.pbs.pbs_config.port)]);
    exposed_ports_warn
        .push(format!("pbs has an exported port on {}", cb_config.pbs.pbs_config.port));

    // inside the container expose on 0.0.0.0
    let container_endpoint =
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, cb_config.pbs.pbs_config.port));
    let (key, val) = get_env_val(PBS_ENDPOINT_ENV, &container_endpoint.to_string());
    pbs_envs.insert(key, val);

    // volumes
    let mut pbs_volumes = vec![config_volume.clone()];
    pbs_volumes.extend(chain_spec_volume.clone());
    pbs_volumes.extend(get_log_volume(&cb_config.logs, PBS_MODULE_NAME));

    // networks
    let pbs_networs = if metrics_enabled {
        Networks::Simple(vec![METRICS_NETWORK.to_owned()])
    } else {
        Networks::default()
    };

    let pbs_service = Service {
        container_name: Some("cb_pbs".to_owned()),
        image: Some(cb_config.pbs.docker_image),
        ports,
        networks: pbs_networs,
        volumes: pbs_volumes,
        environment: Environment::KvPair(pbs_envs),
        ..Service::default()
    };

    services.insert("cb_pbs".to_owned(), Some(pbs_service));

    // setup signer service
    if let Some(signer_config) = cb_config.signer {
        if needs_signer_module {
            if metrics_enabled {
                targets.push(PrometheusTargetConfig {
                    targets: vec![format!("cb_signer:{metrics_port}")],
                    labels: PrometheusLabelsConfig { job: "signer".into() },
                });
            }

            let mut signer_envs = IndexMap::from([
                get_env_val(CONFIG_ENV, CONFIG_DEFAULT),
                get_env_same(JWTS_ENV),
                get_env_uval(SIGNER_PORT_ENV, signer_port as u64),
            ]);

            if let Some((key, val)) = chain_spec_env.clone() {
                signer_envs.insert(key, val);
            }
            if metrics_enabled {
                let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
                signer_envs.insert(key, val);
            }
            if log_to_file {
                let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
                signer_envs.insert(key, val);
            }

            // write jwts to env
            envs.insert(JWTS_ENV.into(), format_comma_separated(&jwts));

            // volumes
            let mut volumes = vec![config_volume.clone()];
            volumes.extend(chain_spec_volume.clone());

            match signer_config.loader {
                SignerLoader::File { key_path } => {
                    volumes.push(Volumes::Simple(format!(
                        "{}:{}:ro",
                        key_path.display(),
                        SIGNER_DEFAULT
                    )));
                    let (k, v) = get_env_val(SIGNER_KEYS_ENV, SIGNER_DEFAULT);
                    signer_envs.insert(k, v);
                }
                SignerLoader::ValidatorsDir { keys_path, secrets_path, format: _ } => {
                    volumes.push(Volumes::Simple(format!(
                        "{}:{}:ro",
                        keys_path.display(),
                        SIGNER_DIR_KEYS_DEFAULT
                    )));
                    let (k, v) = get_env_val(SIGNER_DIR_KEYS_ENV, SIGNER_DIR_KEYS_DEFAULT);
                    signer_envs.insert(k, v);

                    volumes.push(Volumes::Simple(format!(
                        "{}:{}:ro",
                        secrets_path.display(),
                        SIGNER_DIR_SECRETS_DEFAULT
                    )));
                    let (k, v) = get_env_val(SIGNER_DIR_SECRETS_ENV, SIGNER_DIR_SECRETS_DEFAULT);
                    signer_envs.insert(k, v);
                }
            };

            if let Some(store) = signer_config.store {
                match store {
                    ProxyStore::File { proxy_dir } => {
                        volumes.push(Volumes::Simple(format!(
                            "{}:{}:rw",
                            proxy_dir.display(),
                            PROXY_DIR_DEFAULT
                        )));
                        let (k, v) = get_env_val(PROXY_DIR_ENV, PROXY_DIR_DEFAULT);
                        signer_envs.insert(k, v);
                    }
                }
            }

            volumes.extend(get_log_volume(&cb_config.logs, SIGNER_MODULE_NAME));

            // networks
            let mut signer_networks = vec![SIGNER_NETWORK.to_owned()];
            if metrics_enabled {
                signer_networks.push(METRICS_NETWORK.to_owned());
            }

            let signer_service = Service {
                container_name: Some("cb_signer".to_owned()),
                image: Some(signer_config.docker_image),
                networks: Networks::Simple(signer_networks),
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

    let mut compose = Compose::default();

    if metrics_enabled {
        compose.networks.0.insert(
            METRICS_NETWORK.to_owned(),
            MapOrEmpty::Map(NetworkSettings {
                driver: Some("bridge".to_owned()),
                ..NetworkSettings::default()
            }),
        );
    }

    if needs_signer_module {
        compose.networks.0.insert(
            SIGNER_NETWORK.to_owned(),
            MapOrEmpty::Map(NetworkSettings {
                driver: Some("bridge".to_owned()),
                ..NetworkSettings::default()
            }),
        );
    }

    if let Some(metrics_config) = cb_config.metrics {
        // prometheus
        exposed_ports_warn.push("prometheus has an exported port on 9090".to_string());

        let prom_volume = Volumes::Simple(format!(
            "{}:/etc/prometheus/prometheus.yml",
            metrics_config.prometheus_config
        ));

        // TODO: fix path to targets file
        let targets_volume =
            Volumes::Simple(format!("./{}:/etc/prometheus/targets.json", CB_TARGETS_FILE));

        let data_volume = Volumes::Simple(format!("{}:/prometheus", PROMETHEUS_DATA_VOLUME));

        let prometheus_service = Service {
            container_name: Some("cb_prometheus".to_owned()),
            image: Some("prom/prometheus:v3.0.0".to_owned()),
            volumes: vec![prom_volume, targets_volume, data_volume],
            // to inspect prometheus from localhost
            ports: Ports::Short(vec![format!("{}:9090:9090", metrics_config.host)]),
            networks: Networks::Simple(vec![METRICS_NETWORK.to_owned()]),
            ..Service::default()
        };

        services.insert("cb_prometheus".to_owned(), Some(prometheus_service));
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

        // grafana
        if metrics_config.use_grafana {
            exposed_ports_warn.push("grafana has an exported port on 3000".to_string());
            exposed_ports_warn.push(
                "Grafana has the default admin password of 'admin'. Login to change it".to_string(),
            );

            let grafana_data_volume =
                Volumes::Simple(format!("{}:/var/lib/grafana", GRAFANA_DATA_VOLUME));

            let grafana_service = Service {
                container_name: Some("cb_grafana".to_owned()),
                image: Some("grafana/grafana:11.3.1".to_owned()),
                ports: Ports::Short(vec![format!("{}:3000:3000", metrics_config.host)]),
                networks: Networks::Simple(vec![METRICS_NETWORK.to_owned()]),
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
                // disable verbose grafana logs
                logging: Some(LoggingParameters { driver: Some("none".to_owned()), options: None }),
                ..Service::default()
            };

            services.insert("cb_grafana".to_owned(), Some(grafana_service));
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
        }

        // cadvisor
        if metrics_config.use_cadvisor {
            exposed_ports_warn.push("cadvisor has an exported port on 8080".to_string());

            services.insert(
                "cb_cadvisor".to_owned(),
                Some(Service {
                    container_name: Some("cb_cadvisor".to_owned()),
                    image: Some("gcr.io/cadvisor/cadvisor".to_owned()),
                    ports: Ports::Short(vec![format!("{}:8080:8080", metrics_config.host)]),
                    networks: Networks::Simple(vec![METRICS_NETWORK.to_owned()]),
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
        }
    }

    compose.services = Services(services);
    compose.volumes = TopLevelVolumes(volumes);

    // write compose to file
    let compose_str = serde_yaml::to_string(&compose)?;
    let compose_path = Path::new(&output_dir).join(CB_COMPOSE_FILE);
    std::fs::write(&compose_path, compose_str)?;
    if !exposed_ports_warn.is_empty() {
        println!("\n");
        for exposed_port in exposed_ports_warn {
            println!("Warning: {}", exposed_port);
        }
        println!("\n");
    }
    // if file logging is enabled, warn about permissions
    if let Some(logs_config) = cb_config.logs {
        let log_dir = logs_config.log_dir_path;
        println!(
            "Warning: file logging is enabled, you may need to update permissions for the logs directory. e.g. with:\n\t`sudo chown -R 10001:10001 {}`",
            log_dir.display()
        );
    }

    println!("Compose file written to: {:?}", compose_path);

    // write prometheus targets to file
    if !targets.is_empty() {
        let targets_str = serde_json::to_string_pretty(&targets)?;
        let targets_path = Path::new(&output_dir).join(CB_TARGETS_FILE);
        std::fs::write(&targets_path, targets_str)?;
        println!("Targets file written to: {:?}", targets_path);
    }

    if envs.is_empty() {
        println!("Run with:\n\t`commit-boost-cli start --docker {:?}`", compose_path);
    } else {
        // write envs to .env file
        let envs_str = {
            let mut envs_str = String::new();
            for (k, v) in envs {
                envs_str.push_str(&format!("{}={}\n", k, v));
            }
            envs_str
        };
        let env_path = Path::new(&output_dir).join(CB_ENV_FILE);
        std::fs::write(&env_path, envs_str)?;
        println!("Env file written to: {:?}", env_path);

        println!(
            "Run with:\n\t`commit-boost-cli start --docker {:?} --env {:?}`",
            compose_path, env_path
        );
    }

    Ok(())
}

/// FOO=${FOO}
fn get_env_same(k: &str) -> (String, Option<SingleValue>) {
    get_env_interp(k, k)
}

/// FOO=${BAR}
fn get_env_interp(k: &str, v: &str) -> (String, Option<SingleValue>) {
    get_env_val(k, &format!("${{{v}}}"))
}

/// FOO=bar
fn get_env_val(k: &str, v: &str) -> (String, Option<SingleValue>) {
    (k.into(), Some(SingleValue::String(v.into())))
}

fn get_env_uval(k: &str, v: u64) -> (String, Option<SingleValue>) {
    (k.into(), Some(SingleValue::Unsigned(v)))
}

// fn get_env_bool(k: &str, v: bool) -> (String, Option<SingleValue>) {
//     (k.into(), Some(SingleValue::Bool(v)))
// }

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

fn get_log_volume(maybe_config: &Option<LogsSettings>, module_id: &str) -> Option<Volumes> {
    maybe_config.as_ref().map(|config| {
        let p = config.log_dir_path.join(module_id.to_lowercase());
        Volumes::Simple(format!(
            "{}:{}",
            p.to_str().expect("could not convert pathbuf to str"),
            LOGS_DIR_DEFAULT
        ))
    })
}

/// Formats as a comma separated list of key=value
fn format_comma_separated(map: &IndexMap<ModuleId, String>) -> String {
    map.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(",")
}
