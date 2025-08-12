use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    vec,
};

use cb_common::{
    config::{
        CommitBoostConfig, LogsSettings, ModuleKind, SignerConfig, SignerType, ADMIN_JWT_ENV,
        BUILDER_PORT_ENV, BUILDER_URLS_ENV, CHAIN_SPEC_ENV, CONFIG_DEFAULT, CONFIG_ENV,
        DIRK_CA_CERT_DEFAULT, DIRK_CA_CERT_ENV, DIRK_CERT_DEFAULT, DIRK_CERT_ENV,
        DIRK_DIR_SECRETS_DEFAULT, DIRK_DIR_SECRETS_ENV, DIRK_KEY_DEFAULT, DIRK_KEY_ENV, JWTS_ENV,
        LOGS_DIR_DEFAULT, LOGS_DIR_ENV, METRICS_PORT_ENV, MODULE_ID_ENV, MODULE_JWT_ENV,
        PBS_ENDPOINT_ENV, PBS_MODULE_NAME, PROXY_DIR_DEFAULT, PROXY_DIR_ENV,
        PROXY_DIR_KEYS_DEFAULT, PROXY_DIR_KEYS_ENV, PROXY_DIR_SECRETS_DEFAULT,
        PROXY_DIR_SECRETS_ENV, SIGNER_DEFAULT, SIGNER_DIR_KEYS_DEFAULT, SIGNER_DIR_KEYS_ENV,
        SIGNER_DIR_SECRETS_DEFAULT, SIGNER_DIR_SECRETS_ENV, SIGNER_ENDPOINT_ENV, SIGNER_KEYS_ENV,
        SIGNER_MODULE_NAME, SIGNER_PORT_DEFAULT, SIGNER_URL_ENV,
    },
    pbs::{BUILDER_V1_API_PATH, GET_STATUS_PATH},
    signer::{ProxyStore, SignerLoader},
    types::ModuleId,
    utils::random_jwt_secret,
};
use docker_compose_types::{
    Compose, DependsCondition, DependsOnOptions, EnvFile, Environment, Healthcheck,
    HealthcheckTest, MapOrEmpty, NetworkSettings, Networks, Ports, Service, Services, SingleValue,
    Volumes,
};
use eyre::Result;
use indexmap::IndexMap;

/// Name of the docker compose file
pub(super) const CB_COMPOSE_FILE: &str = "cb.docker-compose.yml";
/// Name of the envs file
pub(super) const CB_ENV_FILE: &str = ".cb.env";

const SIGNER_NETWORK: &str = "signer_network";

/// Builds the docker compose file for the Commit-Boost services
// TODO: do more validation for paths, images, etc
pub async fn handle_docker_init(config_path: PathBuf, output_dir: PathBuf) -> Result<()> {
    println!("Initializing Commit-Boost with config file: {}", config_path.display());
    let cb_config = CommitBoostConfig::from_file(&config_path)?;
    cb_config.validate().await?;

    let chain_spec_path = CommitBoostConfig::chain_spec_file(&config_path);

    let log_to_file = cb_config.logs.file.enabled;
    let mut metrics_port = cb_config.metrics.as_ref().map(|m| m.start_port).unwrap_or_default();

    let mut services = IndexMap::new();

    // config volume to pass to all services
    let config_volume =
        Volumes::Simple(format!("./{}:{}:ro", config_path.display(), CONFIG_DEFAULT));
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

    // address for signer API communication
    let signer_port = cb_config.signer.as_ref().map(|s| s.port).unwrap_or(SIGNER_PORT_DEFAULT);
    let signer_server =
        if let Some(SignerConfig { inner: SignerType::Remote { url }, .. }) = &cb_config.signer {
            url.to_string()
        } else {
            format!("http://cb_signer:{signer_port}")
        };

    let builder_events_port = 30000;
    let mut builder_events_modules = Vec::new();

    let mut warnings = Vec::new();

    let needs_signer_module = cb_config.pbs.with_signer ||
        cb_config.modules.as_ref().is_some_and(|modules| {
            modules.iter().any(|module| matches!(module.kind, ModuleKind::Commit))
        });

    // setup modules
    if let Some(modules_config) = cb_config.modules {
        for module in modules_config {
            let module_cid = format!("cb_{}", module.id.to_lowercase());

            let module_service = match module.kind {
                // a commit module needs a JWT and access to the signer network
                ModuleKind::Commit => {
                    let mut ports = vec![];

                    let jwt_secret = random_jwt_secret();
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

                    if let Some(metrics_config) = &cb_config.metrics {
                        if metrics_config.enabled {
                            let host_endpoint =
                                SocketAddr::from((metrics_config.host, metrics_port));
                            ports.push(format!("{}:{}", host_endpoint, metrics_port));
                            warnings.push(format!(
                                "{} has an exported port on {}",
                                module_cid, metrics_port
                            ));
                            targets.push(format!("{host_endpoint}"));
                            let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
                            module_envs.insert(key, val);

                            metrics_port += 1;
                        }
                    }

                    if log_to_file {
                        let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
                        module_envs.insert(key, val);
                    }

                    envs.insert(jwt_name.clone(), jwt_secret.clone());
                    jwts.insert(module.id.clone(), jwt_secret);

                    // networks
                    let module_networks = vec![SIGNER_NETWORK.to_owned()];

                    // volumes
                    let mut module_volumes = vec![config_volume.clone()];
                    module_volumes.extend(chain_spec_volume.clone());
                    module_volumes.extend(get_log_volume(&cb_config.logs, &module.id));

                    // depends_on
                    let mut module_dependencies = IndexMap::new();
                    module_dependencies.insert("cb_signer".into(), DependsCondition {
                        condition: "service_healthy".into(),
                    });

                    Service {
                        container_name: Some(module_cid.clone()),
                        image: Some(module.docker_image),
                        networks: Networks::Simple(module_networks),
                        ports: Ports::Short(ports),
                        volumes: module_volumes,
                        environment: Environment::KvPair(module_envs),
                        depends_on: if let Some(SignerConfig {
                            inner: SignerType::Remote { .. },
                            ..
                        }) = &cb_config.signer
                        {
                            DependsOnOptions::Simple(vec![])
                        } else {
                            DependsOnOptions::Conditional(module_dependencies)
                        },
                        env_file,
                        ..Service::default()
                    }
                }
                // an event module just needs a port to listen on
                ModuleKind::Events => {
                    let mut ports = vec![];
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
                    if let Some(metrics_config) = &cb_config.metrics {
                        if metrics_config.enabled {
                            let host_endpoint =
                                SocketAddr::from((metrics_config.host, metrics_port));
                            ports.push(format!("{}:{}", host_endpoint, metrics_port));
                            warnings.push(format!(
                                "{} has an exported port on {}",
                                module_cid, metrics_port
                            ));
                            targets.push(format!("{host_endpoint}"));
                            let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
                            module_envs.insert(key, val);

                            metrics_port += 1;
                        }
                    }
                    if log_to_file {
                        let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
                        module_envs.insert(key, val);
                    }

                    // volumes
                    let mut module_volumes = vec![config_volume.clone()];
                    module_volumes.extend(chain_spec_volume.clone());
                    module_volumes.extend(get_log_volume(&cb_config.logs, &module.id));

                    Service {
                        container_name: Some(module_cid.clone()),
                        image: Some(module.docker_image),
                        ports: Ports::Short(ports),
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

    let mut pbs_envs = IndexMap::from([get_env_val(CONFIG_ENV, CONFIG_DEFAULT)]);
    let mut pbs_volumes = vec![config_volume.clone()];

    // ports
    let host_endpoint =
        SocketAddr::from((cb_config.pbs.pbs_config.host, cb_config.pbs.pbs_config.port));
    let mut ports = vec![format!("{}:{}", host_endpoint, cb_config.pbs.pbs_config.port)];
    warnings.push(format!("cb_pbs has an exported port on {}", cb_config.pbs.pbs_config.port));

    if let Some(mux_config) = cb_config.muxes {
        for mux in mux_config.muxes.iter() {
            if let Some((env_name, actual_path, internal_path)) = mux.loader_env()? {
                let (key, val) = get_env_val(&env_name, &internal_path);
                pbs_envs.insert(key, val);
                pbs_volumes.push(Volumes::Simple(format!("{}:{}:ro", actual_path, internal_path)));
            }
        }
    }

    if let Some((key, val)) = chain_spec_env.clone() {
        pbs_envs.insert(key, val);
    }
    if let Some(metrics_config) = &cb_config.metrics {
        if metrics_config.enabled {
            let host_endpoint = SocketAddr::from((metrics_config.host, metrics_port));
            ports.push(format!("{}:{}", host_endpoint, metrics_port));
            warnings.push(format!("cb_pbs has an exported port on {}", metrics_port));
            targets.push(format!("{host_endpoint}"));
            let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
            pbs_envs.insert(key, val);

            metrics_port += 1;
        }
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

    // inside the container expose on 0.0.0.0
    let container_endpoint =
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, cb_config.pbs.pbs_config.port));
    let (key, val) = get_env_val(PBS_ENDPOINT_ENV, &container_endpoint.to_string());
    pbs_envs.insert(key, val);

    // volumes
    pbs_volumes.extend(chain_spec_volume.clone());
    pbs_volumes.extend(get_log_volume(&cb_config.logs, PBS_MODULE_NAME));

    let pbs_service = Service {
        container_name: Some("cb_pbs".to_owned()),
        image: Some(cb_config.pbs.docker_image),
        ports: Ports::Short(ports),
        volumes: pbs_volumes,
        environment: Environment::KvPair(pbs_envs),
        healthcheck: Some(Healthcheck {
            test: Some(HealthcheckTest::Single(format!(
                "curl -f http://localhost:{}{}{}",
                cb_config.pbs.pbs_config.port, BUILDER_V1_API_PATH, GET_STATUS_PATH
            ))),
            interval: Some("30s".into()),
            timeout: Some("5s".into()),
            retries: 3,
            start_interval: None,
            start_period: Some("5s".into()),
            disable: false,
        }),
        ..Service::default()
    };

    services.insert("cb_pbs".to_owned(), Some(pbs_service));

    // setup signer service
    if needs_signer_module {
        let Some(signer_config) = cb_config.signer else {
            panic!("Signer module required but no signer config provided");
        };

        match signer_config.inner {
            SignerType::Local { loader, store } => {
                let mut signer_envs = IndexMap::from([
                    get_env_val(CONFIG_ENV, CONFIG_DEFAULT),
                    get_env_same(JWTS_ENV),
                    get_env_same(ADMIN_JWT_ENV),
                ]);

                // Bind the signer API to 0.0.0.0
                let container_endpoint =
                    SocketAddr::from((Ipv4Addr::UNSPECIFIED, signer_config.port));
                let (key, val) = get_env_val(SIGNER_ENDPOINT_ENV, &container_endpoint.to_string());
                signer_envs.insert(key, val);

                let host_endpoint = SocketAddr::from((signer_config.host, signer_config.port));
                let mut ports = vec![format!("{}:{}", host_endpoint, signer_config.port)];
                warnings.push(format!("cb_signer has an exported port on {}", signer_config.port));

                if let Some((key, val)) = chain_spec_env.clone() {
                    signer_envs.insert(key, val);
                }
                if let Some(metrics_config) = &cb_config.metrics {
                    if metrics_config.enabled {
                        let host_endpoint = SocketAddr::from((metrics_config.host, metrics_port));
                        ports.push(format!("{}:{}", host_endpoint, metrics_port));
                        warnings
                            .push(format!("cb_signer has an exported port on {}", metrics_port));
                        targets.push(format!("{host_endpoint}"));
                        let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
                        signer_envs.insert(key, val);
                    }
                }
                if log_to_file {
                    let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
                    signer_envs.insert(key, val);
                }

                // write jwts to env
                envs.insert(JWTS_ENV.into(), format_comma_separated(&jwts));
                envs.insert(ADMIN_JWT_ENV.into(), random_jwt_secret());

                // volumes
                let mut volumes = vec![config_volume.clone()];
                volumes.extend(chain_spec_volume.clone());

                match loader {
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
                        let (k, v) =
                            get_env_val(SIGNER_DIR_SECRETS_ENV, SIGNER_DIR_SECRETS_DEFAULT);
                        signer_envs.insert(k, v);
                    }
                };

                if let Some(store) = store {
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
                        ProxyStore::ERC2335 { keys_path, secrets_path } => {
                            volumes.push(Volumes::Simple(format!(
                                "{}:{}:rw",
                                keys_path.display(),
                                PROXY_DIR_KEYS_DEFAULT
                            )));
                            let (k, v) = get_env_val(PROXY_DIR_KEYS_ENV, PROXY_DIR_KEYS_DEFAULT);
                            signer_envs.insert(k, v);

                            volumes.push(Volumes::Simple(format!(
                                "{}:{}:rw",
                                secrets_path.display(),
                                PROXY_DIR_SECRETS_DEFAULT
                            )));
                            let (k, v) =
                                get_env_val(PROXY_DIR_SECRETS_ENV, PROXY_DIR_SECRETS_DEFAULT);
                            signer_envs.insert(k, v);
                        }
                    }
                }

                volumes.extend(get_log_volume(&cb_config.logs, SIGNER_MODULE_NAME));

                // networks
                let signer_networks = vec![SIGNER_NETWORK.to_owned()];

                let signer_service = Service {
                    container_name: Some("cb_signer".to_owned()),
                    image: Some(signer_config.docker_image),
                    networks: Networks::Simple(signer_networks),
                    ports: Ports::Short(ports),
                    volumes,
                    environment: Environment::KvPair(signer_envs),
                    healthcheck: Some(Healthcheck {
                        test: Some(HealthcheckTest::Single(format!(
                            "curl -f http://localhost:{signer_port}/status"
                        ))),
                        interval: Some("30s".into()),
                        timeout: Some("5s".into()),
                        retries: 3,
                        start_interval: None,
                        start_period: Some("5s".into()),
                        disable: false,
                    }),
                    ..Service::default()
                };

                services.insert("cb_signer".to_owned(), Some(signer_service));
            }
            SignerType::Dirk { cert_path, key_path, secrets_path, ca_cert_path, store, .. } => {
                let mut signer_envs = IndexMap::from([
                    get_env_val(CONFIG_ENV, CONFIG_DEFAULT),
                    get_env_same(JWTS_ENV),
                    get_env_val(DIRK_CERT_ENV, DIRK_CERT_DEFAULT),
                    get_env_val(DIRK_KEY_ENV, DIRK_KEY_DEFAULT),
                    get_env_val(DIRK_DIR_SECRETS_ENV, DIRK_DIR_SECRETS_DEFAULT),
                ]);

                // Bind the signer API to 0.0.0.0
                let container_endpoint =
                    SocketAddr::from((Ipv4Addr::UNSPECIFIED, signer_config.port));
                let (key, val) = get_env_val(SIGNER_ENDPOINT_ENV, &container_endpoint.to_string());
                signer_envs.insert(key, val);

                let host_endpoint = SocketAddr::from((signer_config.host, signer_config.port));
                let mut ports = vec![format!("{}:{}", host_endpoint, signer_config.port)];
                warnings.push(format!("cb_signer has an exported port on {}", signer_config.port));

                if let Some((key, val)) = chain_spec_env.clone() {
                    signer_envs.insert(key, val);
                }
                if let Some(metrics_config) = &cb_config.metrics {
                    if metrics_config.enabled {
                        let host_endpoint = SocketAddr::from((metrics_config.host, metrics_port));
                        ports.push(format!("{}:{}", host_endpoint, metrics_port));
                        warnings
                            .push(format!("cb_signer has an exported port on {}", metrics_port));
                        targets.push(format!("{host_endpoint}"));
                        let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
                        signer_envs.insert(key, val);
                    }
                }
                if log_to_file {
                    let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
                    signer_envs.insert(key, val);
                }

                // write jwts to env
                envs.insert(JWTS_ENV.into(), format_comma_separated(&jwts));

                // volumes
                let mut volumes = vec![
                    config_volume.clone(),
                    Volumes::Simple(format!("{}:{}:ro", cert_path.display(), DIRK_CERT_DEFAULT)),
                    Volumes::Simple(format!("{}:{}:ro", key_path.display(), DIRK_KEY_DEFAULT)),
                    Volumes::Simple(format!(
                        "{}:{}",
                        secrets_path.display(),
                        DIRK_DIR_SECRETS_DEFAULT
                    )),
                ];
                volumes.extend(chain_spec_volume.clone());
                volumes.extend(get_log_volume(&cb_config.logs, SIGNER_MODULE_NAME));

                if let Some(ca_cert_path) = ca_cert_path {
                    volumes.push(Volumes::Simple(format!(
                        "{}:{}:ro",
                        ca_cert_path.display(),
                        DIRK_CA_CERT_DEFAULT
                    )));
                    let (key, val) = get_env_val(DIRK_CA_CERT_ENV, DIRK_CA_CERT_DEFAULT);
                    signer_envs.insert(key, val);
                }

                match store {
                    Some(ProxyStore::File { proxy_dir }) => {
                        volumes.push(Volumes::Simple(format!(
                            "{}:{}",
                            proxy_dir.display(),
                            PROXY_DIR_DEFAULT
                        )));
                        let (key, val) = get_env_val(PROXY_DIR_ENV, PROXY_DIR_DEFAULT);
                        signer_envs.insert(key, val);
                    }
                    Some(ProxyStore::ERC2335 { .. }) => {
                        panic!("ERC2335 store not supported with Dirk signer");
                    }
                    None => {}
                }

                // networks
                let signer_networks = vec![SIGNER_NETWORK.to_owned()];

                let signer_service = Service {
                    container_name: Some("cb_signer".to_owned()),
                    image: Some(signer_config.docker_image),
                    networks: Networks::Simple(signer_networks),
                    ports: Ports::Short(ports),
                    volumes,
                    environment: Environment::KvPair(signer_envs),
                    healthcheck: Some(Healthcheck {
                        test: Some(HealthcheckTest::Single(format!(
                            "curl -f http://localhost:{signer_port}/status"
                        ))),
                        interval: Some("30s".into()),
                        timeout: Some("5s".into()),
                        retries: 3,
                        start_interval: None,
                        start_period: Some("5s".into()),
                        disable: false,
                    }),
                    ..Service::default()
                };

                services.insert("cb_signer".to_owned(), Some(signer_service));
            }
            SignerType::Remote { .. } => {
                panic!("Signer module required but remote config provided");
            }
        }
    }

    let mut compose = Compose::default();

    if needs_signer_module {
        compose.networks.0.insert(
            SIGNER_NETWORK.to_owned(),
            MapOrEmpty::Map(NetworkSettings {
                driver: Some("bridge".to_owned()),
                ..NetworkSettings::default()
            }),
        );
    }

    compose.services = Services(services);

    // write compose to file
    let compose_str = serde_yaml::to_string(&compose)?;
    let compose_path = Path::new(&output_dir).join(CB_COMPOSE_FILE);
    std::fs::write(&compose_path, compose_str)?;
    if !warnings.is_empty() {
        println!();
        for exposed_port in warnings {
            println!("Warning: {}", exposed_port);
        }
        println!()
    }
    // if file logging is enabled, warn about permissions
    if cb_config.logs.file.enabled {
        let log_dir = cb_config.logs.file.dir_path;
        println!(
            "Warning: file logging is enabled, you may need to update permissions for the logs directory. e.g. with:\n\t`sudo chown -R 10001:10001 {}`",
            log_dir.display()
        );
        println!()
    }

    println!("Docker Compose file written to: {:?}", compose_path);

    // write prometheus targets to file
    if !targets.is_empty() {
        let targets = targets.join(", ");
        println!("Note: Make sure to add these targets for Prometheus to scrape: {targets}");
        println!("Check out the docs on how to configure Prometheus/Grafana/cAdvisor: https://commit-boost.github.io/commit-boost-client/get_started/running/metrics");
    }

    if envs.is_empty() {
        println!("Run with:\n\tdocker compose -f {:?} up -d", compose_path);
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

        println!();
        println!(
            "Run with:\n\tdocker compose --env-file {:?} -f {:?} up -d",
            env_path, compose_path
        );
        println!(
            "Stop with:\n\tdocker compose --env-file {:?} -f {:?} down",
            env_path, compose_path
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

fn get_log_volume(config: &LogsSettings, module_id: &str) -> Option<Volumes> {
    config.file.enabled.then_some({
        let p = config.file.dir_path.join(module_id.to_lowercase());
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
