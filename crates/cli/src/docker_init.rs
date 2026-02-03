use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    vec,
};

use cb_common::{
    config::{
        CHAIN_SPEC_ENV, CONFIG_DEFAULT, CONFIG_ENV, CommitBoostConfig, DIRK_CA_CERT_DEFAULT,
        DIRK_CA_CERT_ENV, DIRK_CERT_DEFAULT, DIRK_CERT_ENV, DIRK_DIR_SECRETS_DEFAULT,
        DIRK_DIR_SECRETS_ENV, DIRK_KEY_DEFAULT, DIRK_KEY_ENV, JWTS_ENV, LOGS_DIR_DEFAULT,
        LOGS_DIR_ENV, LogsSettings, METRICS_PORT_ENV, MODULE_ID_ENV, MODULE_JWT_ENV, ModuleKind,
        PBS_ENDPOINT_ENV, PBS_SERVICE_NAME, PROXY_DIR_DEFAULT, PROXY_DIR_ENV,
        PROXY_DIR_KEYS_DEFAULT, PROXY_DIR_KEYS_ENV, PROXY_DIR_SECRETS_DEFAULT,
        PROXY_DIR_SECRETS_ENV, SIGNER_DEFAULT, SIGNER_DIR_KEYS_DEFAULT, SIGNER_DIR_KEYS_ENV,
        SIGNER_DIR_SECRETS_DEFAULT, SIGNER_DIR_SECRETS_ENV, SIGNER_ENDPOINT_ENV, SIGNER_KEYS_ENV,
        SIGNER_PORT_DEFAULT, SIGNER_SERVICE_NAME, SIGNER_URL_ENV, SignerConfig, SignerType,
        StaticModuleConfig,
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

// Info about a custom chain spec to use
struct ServiceChainSpecInfo {
    // Environment variable to set for the chain spec file's path
    env: (String, Option<SingleValue>),

    // Volume for binding the chain spec file into a container
    volume: Volumes,
}

// Info about the Commit-Boost config being used to create services
struct CommitBoostConfigInfo {
    // Commit-Boost config
    cb_config: CommitBoostConfig,

    // Volume for binding the config file into a container
    config_volume: Volumes,
}

// Information needed to create a Commit-Boost service
struct ServiceCreationInfo {
    // Info about the Commit-Boost config being used
    config_info: CommitBoostConfigInfo,

    // Environment variables to write in .env file
    envs: IndexMap<String, String>,

    // Targets to pass to prometheus
    targets: Vec<String>,

    // Warnings that need to be shown to the user
    warnings: Vec<String>,

    // JWTs for any modules owned by this service (TODO: are we going to offload modules to the
    // user instead of owning them?)
    jwts: IndexMap<ModuleId, String>,

    // Custom chain spec info, if any
    chain_spec: Option<ServiceChainSpecInfo>,

    // Next available port for metrics (TODO: this should be a setting in PBS and in Signer instead
    // of a universal one)
    metrics_port: u16,
}

/// Builds the docker compose file for the Commit-Boost services
// TODO: do more validation for paths, images, etc
pub async fn handle_docker_init(config_path: PathBuf, output_dir: PathBuf) -> Result<()> {
    // Initialize variables
    let mut services = IndexMap::new();
    println!("Initializing Commit-Boost with config file: {}", config_path.display());
    let mut service_config = ServiceCreationInfo {
        config_info: CommitBoostConfigInfo {
            config_volume: Volumes::Simple(format!(
                "./{}:{}:ro",
                config_path.display(),
                CONFIG_DEFAULT
            )),
            cb_config: CommitBoostConfig::from_file(&config_path)?,
        },
        envs: IndexMap::new(),
        targets: Vec::new(),
        warnings: Vec::new(),
        jwts: IndexMap::new(),
        chain_spec: None,
        metrics_port: 9100,
    };
    service_config.config_info.cb_config.validate().await?;

    // Get the custom chain spec, if any
    let chain_spec_path = CommitBoostConfig::chain_spec_file(&config_path);
    if let Some(spec) = chain_spec_path {
        // this is ok since the config has already been loaded once
        let filename = spec.file_name().unwrap().to_str().unwrap();
        let chain_spec = ServiceChainSpecInfo {
            env: get_env_val(CHAIN_SPEC_ENV, &format!("/{}", filename)),
            volume: Volumes::Simple(format!("{}:/{}:ro", spec.display(), filename)),
        };
        service_config.chain_spec = Some(chain_spec);
    }

    // Set up variables
    service_config.metrics_port = service_config
        .config_info
        .cb_config
        .metrics
        .as_ref()
        .map(|m| m.start_port)
        .unwrap_or_default();
    let needs_signer_module = service_config.config_info.cb_config.pbs.with_signer ||
        service_config.config_info.cb_config.modules.as_ref().is_some_and(|modules| {
            modules.iter().any(|module| matches!(module.kind, ModuleKind::Commit))
        });
    let signer_config =
        if needs_signer_module {
            Some(service_config.config_info.cb_config.signer.clone().expect(
                "Signer module required but no signer config provided in Commit-Boost config",
            ))
        } else {
            None
        };
    let signer_server = if let Some(SignerConfig { inner: SignerType::Remote { url }, .. }) =
        &service_config.config_info.cb_config.signer
    {
        url.to_string()
    } else {
        let signer_port = service_config
            .config_info
            .cb_config
            .signer
            .as_ref()
            .map(|s| s.port)
            .unwrap_or(SIGNER_PORT_DEFAULT);
        format!("http://cb_signer:{signer_port}")
    };

    // setup modules
    if let Some(ref modules_config) = service_config.config_info.cb_config.modules {
        for module in modules_config.clone() {
            let (module_cid, module_service) =
                create_module_service(&module, signer_server.as_str(), &mut service_config)?;
            services.insert(module_cid, Some(module_service));
        }
    };

    // setup pbs service
    let pbs_service = create_pbs_service(&mut service_config)?;
    services.insert("cb_pbs".to_owned(), Some(pbs_service));

    // setup signer service
    if let Some(signer_config) = signer_config {
        match &signer_config.inner {
            SignerType::Local { loader, store } => {
                let signer_service = create_signer_service_local(
                    &mut service_config,
                    &signer_config,
                    loader,
                    store,
                )?;
                services.insert("cb_signer".to_owned(), Some(signer_service));
            }
            SignerType::Dirk { cert_path, key_path, secrets_path, ca_cert_path, store, .. } => {
                let signer_service = create_signer_service_dirk(
                    &mut service_config,
                    &signer_config,
                    cert_path,
                    key_path,
                    secrets_path,
                    ca_cert_path,
                    store,
                )?;
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

    // write compose to file
    compose.services = Services(services);
    let compose_path = Path::new(&output_dir).join(CB_COMPOSE_FILE);
    write_compose_file(&compose, &compose_path, &service_config)?;

    // Inform user about Prometheus targets
    if !service_config.targets.is_empty() {
        let targets = service_config.targets.join(", ");
        println!("Note: Make sure to add these targets for Prometheus to scrape: {targets}");
        println!(
            "Check out the docs on how to configure Prometheus/Grafana/cAdvisor: https://commit-boost.github.io/commit-boost-client/get_started/running/metrics"
        );
    }

    if service_config.envs.is_empty() {
        println!("Run with:\n\tdocker compose -f {compose_path:?} up -d");
    } else {
        // write envs to .env file
        let env_path = Path::new(&output_dir).join(CB_ENV_FILE);
        write_env_file(&service_config.envs, &env_path)?;
        println!();
        println!("Run with:\n\tdocker compose --env-file {env_path:?} -f {compose_path:?} up -d");
        println!("Stop with:\n\tdocker compose --env-file {env_path:?} -f {compose_path:?} down");
    }

    Ok(())
}

// Creates a PBS service
fn create_pbs_service(service_config: &mut ServiceCreationInfo) -> eyre::Result<Service> {
    let metrics_port = service_config.metrics_port;
    let cb_config = &service_config.config_info.cb_config;
    let config_volume = &service_config.config_info.config_volume;
    let mut envs = IndexMap::from([get_env_val(CONFIG_ENV, CONFIG_DEFAULT)]);
    let mut volumes = vec![config_volume.clone()];

    // Bind the API to 0.0.0.0
    let container_endpoint =
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, cb_config.pbs.pbs_config.port));
    let host_endpoint =
        SocketAddr::from((cb_config.pbs.pbs_config.host, cb_config.pbs.pbs_config.port));
    let (key, val) = get_env_val(PBS_ENDPOINT_ENV, &container_endpoint.to_string());
    envs.insert(key, val);

    // Exposed ports
    let mut ports = vec![format!("{}:{}", host_endpoint, cb_config.pbs.pbs_config.port)];
    service_config
        .warnings
        .push(format!("cb_pbs has an exported port on {}", cb_config.pbs.pbs_config.port));

    // Volumes for file-based mux config files
    if let Some(ref mux_config) = cb_config.muxes {
        for mux in mux_config.muxes.iter() {
            if let Some((env_name, actual_path, internal_path)) = mux.loader_env()? {
                let (key, val) = get_env_val(&env_name, &internal_path);
                envs.insert(key, val);
                volumes.push(Volumes::Simple(format!("{actual_path}:{internal_path}:ro")));
            }
        }
    }

    // Chain spec env/volume
    if let Some(spec) = &service_config.chain_spec {
        envs.insert(spec.env.0.clone(), spec.env.1.clone());
        volumes.push(spec.volume.clone());
    }

    // Metrics
    if let Some(metrics_config) = &cb_config.metrics &&
        metrics_config.enabled
    {
        let host_endpoint = SocketAddr::from((metrics_config.host, metrics_port));
        ports.push(format!("{host_endpoint}:{metrics_port}"));
        service_config.warnings.push(format!("cb_pbs has an exported port on {metrics_port}"));
        service_config.targets.push(format!("{host_endpoint}"));
        let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
        envs.insert(key, val);

        service_config.metrics_port += 1;
    }

    // Logging
    if cb_config.logs.file.enabled {
        let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
        envs.insert(key, val);
    }

    // Create the service
    volumes.extend(get_log_volume(&cb_config.logs, PBS_SERVICE_NAME));
    let pbs_service = Service {
        container_name: Some("cb_pbs".to_owned()),
        image: Some(cb_config.pbs.docker_image.clone()),
        ports: Ports::Short(ports),
        volumes,
        environment: Environment::KvPair(envs),
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

    Ok(pbs_service)
}

// Creates a Signer service using a local signer
fn create_signer_service_local(
    service_config: &mut ServiceCreationInfo,
    signer_config: &SignerConfig,
    loader: &SignerLoader,
    store: &Option<ProxyStore>,
) -> eyre::Result<Service> {
    let cb_config = &service_config.config_info.cb_config;
    let config_volume = &service_config.config_info.config_volume;
    let metrics_port = service_config.metrics_port;
    let mut envs =
        IndexMap::from([get_env_val(CONFIG_ENV, CONFIG_DEFAULT), get_env_same(JWTS_ENV)]);
    let mut volumes = vec![config_volume.clone()];

    // Bind the API to 0.0.0.0
    let container_endpoint = SocketAddr::from((Ipv4Addr::UNSPECIFIED, signer_config.port));
    let host_endpoint = SocketAddr::from((signer_config.host, signer_config.port));
    let (key, val) = get_env_val(SIGNER_ENDPOINT_ENV, &container_endpoint.to_string());
    envs.insert(key, val);

    // Exposed ports
    let mut ports = vec![format!("{}:{}", host_endpoint, signer_config.port)];
    service_config
        .warnings
        .push(format!("cb_signer has an exported port on {}", signer_config.port));

    // Chain spec env/volume
    if let Some(spec) = &service_config.chain_spec {
        envs.insert(spec.env.0.clone(), spec.env.1.clone());
        volumes.push(spec.volume.clone());
    }

    // Metrics
    if let Some(metrics_config) = &cb_config.metrics &&
        metrics_config.enabled
    {
        let host_endpoint = SocketAddr::from((metrics_config.host, metrics_port));
        ports.push(format!("{host_endpoint}:{metrics_port}"));
        service_config.warnings.push(format!("cb_signer has an exported port on {metrics_port}"));
        service_config.targets.push(format!("{host_endpoint}"));
        let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
        envs.insert(key, val);
        service_config.metrics_port += 1;
    }

    // Logging
    if cb_config.logs.file.enabled {
        let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
        envs.insert(key, val);
    }
    volumes.extend(get_log_volume(&cb_config.logs, SIGNER_SERVICE_NAME));

    // write jwts to env
    service_config.envs.insert(JWTS_ENV.into(), format_comma_separated(&service_config.jwts));

    // Signer loader volumes and envs
    match loader {
        SignerLoader::File { key_path } => {
            volumes.push(Volumes::Simple(format!("{}:{}:ro", key_path.display(), SIGNER_DEFAULT)));
            let (k, v) = get_env_val(SIGNER_KEYS_ENV, SIGNER_DEFAULT);
            envs.insert(k, v);
        }
        SignerLoader::ValidatorsDir { keys_path, secrets_path, format: _ } => {
            volumes.push(Volumes::Simple(format!(
                "{}:{}:ro",
                keys_path.display(),
                SIGNER_DIR_KEYS_DEFAULT
            )));
            let (k, v) = get_env_val(SIGNER_DIR_KEYS_ENV, SIGNER_DIR_KEYS_DEFAULT);
            envs.insert(k, v);

            volumes.push(Volumes::Simple(format!(
                "{}:{}:ro",
                secrets_path.display(),
                SIGNER_DIR_SECRETS_DEFAULT
            )));
            let (k, v) = get_env_val(SIGNER_DIR_SECRETS_ENV, SIGNER_DIR_SECRETS_DEFAULT);
            envs.insert(k, v);
        }
    };

    // Proxy keystore volumes and envs
    if let Some(store) = store {
        match store {
            ProxyStore::File { proxy_dir } => {
                volumes.push(Volumes::Simple(format!(
                    "{}:{}:rw",
                    proxy_dir.display(),
                    PROXY_DIR_DEFAULT
                )));
                let (k, v) = get_env_val(PROXY_DIR_ENV, PROXY_DIR_DEFAULT);
                envs.insert(k, v);
            }
            ProxyStore::ERC2335 { keys_path, secrets_path } => {
                volumes.push(Volumes::Simple(format!(
                    "{}:{}:rw",
                    keys_path.display(),
                    PROXY_DIR_KEYS_DEFAULT
                )));
                let (k, v) = get_env_val(PROXY_DIR_KEYS_ENV, PROXY_DIR_KEYS_DEFAULT);
                envs.insert(k, v);

                volumes.push(Volumes::Simple(format!(
                    "{}:{}:rw",
                    secrets_path.display(),
                    PROXY_DIR_SECRETS_DEFAULT
                )));
                let (k, v) = get_env_val(PROXY_DIR_SECRETS_ENV, PROXY_DIR_SECRETS_DEFAULT);
                envs.insert(k, v);
            }
        }
    }

    // Create the service
    let signer_networks = vec![SIGNER_NETWORK.to_owned()];
    let signer_service = Service {
        container_name: Some("cb_signer".to_owned()),
        image: Some(signer_config.docker_image.clone()),
        networks: Networks::Simple(signer_networks),
        ports: Ports::Short(ports),
        volumes,
        environment: Environment::KvPair(envs),
        healthcheck: Some(Healthcheck {
            test: Some(HealthcheckTest::Single(format!(
                "curl -f http://localhost:{}/status",
                signer_config.port,
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

    Ok(signer_service)
}

// Creates a Signer service that's tied to Dirk
fn create_signer_service_dirk(
    service_config: &mut ServiceCreationInfo,
    signer_config: &SignerConfig,
    cert_path: &Path,
    key_path: &Path,
    secrets_path: &Path,
    ca_cert_path: &Option<PathBuf>,
    store: &Option<ProxyStore>,
) -> eyre::Result<Service> {
    let cb_config = &service_config.config_info.cb_config;
    let config_volume = &service_config.config_info.config_volume;
    let metrics_port = service_config.metrics_port;
    let mut envs = IndexMap::from([
        get_env_val(CONFIG_ENV, CONFIG_DEFAULT),
        get_env_same(JWTS_ENV),
        get_env_val(DIRK_CERT_ENV, DIRK_CERT_DEFAULT),
        get_env_val(DIRK_KEY_ENV, DIRK_KEY_DEFAULT),
        get_env_val(DIRK_DIR_SECRETS_ENV, DIRK_DIR_SECRETS_DEFAULT),
    ]);
    let mut volumes = vec![
        config_volume.clone(),
        Volumes::Simple(format!("{}:{}:ro", cert_path.display(), DIRK_CERT_DEFAULT)),
        Volumes::Simple(format!("{}:{}:ro", key_path.display(), DIRK_KEY_DEFAULT)),
        Volumes::Simple(format!("{}:{}", secrets_path.display(), DIRK_DIR_SECRETS_DEFAULT)),
    ];

    // Bind the API to 0.0.0.0
    let container_endpoint = SocketAddr::from((Ipv4Addr::UNSPECIFIED, signer_config.port));
    let host_endpoint = SocketAddr::from((signer_config.host, signer_config.port));
    let (key, val) = get_env_val(SIGNER_ENDPOINT_ENV, &container_endpoint.to_string());
    envs.insert(key, val);

    // Exposed ports
    let mut ports = vec![format!("{}:{}", host_endpoint, signer_config.port)];
    service_config
        .warnings
        .push(format!("cb_signer has an exported port on {}", signer_config.port));

    // Chain spec env/volume
    if let Some(spec) = &service_config.chain_spec {
        envs.insert(spec.env.0.clone(), spec.env.1.clone());
        volumes.push(spec.volume.clone());
    }

    // Metrics
    if let Some(metrics_config) = &cb_config.metrics &&
        metrics_config.enabled
    {
        let host_endpoint = SocketAddr::from((metrics_config.host, metrics_port));
        ports.push(format!("{host_endpoint}:{metrics_port}"));
        service_config.warnings.push(format!("cb_signer has an exported port on {metrics_port}"));
        service_config.targets.push(format!("{host_endpoint}"));
        let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
        envs.insert(key, val);
        service_config.metrics_port += 1;
    }

    // Logging
    if cb_config.logs.file.enabled {
        let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
        envs.insert(key, val);
    }
    volumes.extend(get_log_volume(&cb_config.logs, SIGNER_SERVICE_NAME));

    // write jwts to env
    service_config.envs.insert(JWTS_ENV.into(), format_comma_separated(&service_config.jwts));

    // CA cert volume and env
    if let Some(ca_cert_path) = ca_cert_path {
        volumes.push(Volumes::Simple(format!(
            "{}:{}:ro",
            ca_cert_path.display(),
            DIRK_CA_CERT_DEFAULT
        )));
        let (key, val) = get_env_val(DIRK_CA_CERT_ENV, DIRK_CA_CERT_DEFAULT);
        envs.insert(key, val);
    }

    // Keystore volumes and envs
    match store {
        Some(ProxyStore::File { proxy_dir }) => {
            volumes.push(Volumes::Simple(format!("{}:{}", proxy_dir.display(), PROXY_DIR_DEFAULT)));
            let (key, val) = get_env_val(PROXY_DIR_ENV, PROXY_DIR_DEFAULT);
            envs.insert(key, val);
        }
        Some(ProxyStore::ERC2335 { .. }) => {
            panic!("ERC2335 store not supported with Dirk signer");
        }
        None => {}
    }

    // Create the service
    let signer_networks = vec![SIGNER_NETWORK.to_owned()];
    let signer_service = Service {
        container_name: Some("cb_signer".to_owned()),
        image: Some(signer_config.docker_image.clone()),
        networks: Networks::Simple(signer_networks),
        ports: Ports::Short(ports),
        volumes,
        environment: Environment::KvPair(envs),
        healthcheck: Some(Healthcheck {
            test: Some(HealthcheckTest::Single(format!(
                "curl -f http://localhost:{}/status",
                signer_config.port,
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

    Ok(signer_service)
}

/// Creates a Commit-Boost module service
fn create_module_service(
    module: &StaticModuleConfig,
    signer_server: &str,
    service_config: &mut ServiceCreationInfo,
) -> eyre::Result<(String, Service)> {
    let cb_config = &service_config.config_info.cb_config;
    let config_volume = &service_config.config_info.config_volume;
    let metrics_port = service_config.metrics_port;
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
                get_env_val(SIGNER_URL_ENV, signer_server),
            ]);

            // Pass on the env variables
            if let Some(envs) = &module.env {
                for (k, v) in envs {
                    module_envs.insert(k.clone(), Some(SingleValue::String(v.clone())));
                }
            };

            // volumes
            let mut module_volumes = vec![config_volume.clone()];
            module_volumes.extend(get_log_volume(&cb_config.logs, &module.id));

            // Chain spec env/volume
            if let Some(spec) = &service_config.chain_spec {
                module_envs.insert(spec.env.0.clone(), spec.env.1.clone());
                module_volumes.push(spec.volume.clone());
            }

            if let Some(metrics_config) = &cb_config.metrics &&
                metrics_config.enabled
            {
                let host_endpoint = SocketAddr::from((metrics_config.host, metrics_port));
                ports.push(format!("{host_endpoint}:{metrics_port}"));
                service_config
                    .warnings
                    .push(format!("{module_cid} has an exported port on {metrics_port}"));
                service_config.targets.push(format!("{host_endpoint}"));
                let (key, val) = get_env_uval(METRICS_PORT_ENV, metrics_port as u64);
                module_envs.insert(key, val);

                service_config.metrics_port += 1;
            }

            // Logging
            if cb_config.logs.file.enabled {
                let (key, val) = get_env_val(LOGS_DIR_ENV, LOGS_DIR_DEFAULT);
                module_envs.insert(key, val);
            }

            // write jwts to env
            service_config.envs.insert(jwt_name.clone(), jwt_secret.clone());
            service_config.jwts.insert(module.id.clone(), jwt_secret);

            // Dependencies
            let mut module_dependencies = IndexMap::new();
            module_dependencies.insert("cb_signer".into(), DependsCondition {
                condition: "service_healthy".into(),
            });

            // Create the service
            let module_networks = vec![SIGNER_NETWORK.to_owned()];
            Service {
                container_name: Some(module_cid.clone()),
                image: Some(module.docker_image.clone()),
                networks: Networks::Simple(module_networks),
                ports: Ports::Short(ports),
                volumes: module_volumes,
                environment: Environment::KvPair(module_envs),
                depends_on: if let Some(SignerConfig { inner: SignerType::Remote { .. }, .. }) =
                    &cb_config.signer
                {
                    DependsOnOptions::Simple(vec![])
                } else {
                    DependsOnOptions::Conditional(module_dependencies)
                },
                env_file: module.env_file.clone().map(EnvFile::Simple),
                ..Service::default()
            }
        }
    };

    Ok((module_cid, module_service))
}

/// Writes the docker compose file to disk and prints any warnings
fn write_compose_file(
    compose: &Compose,
    output_path: &Path,
    service_config: &ServiceCreationInfo,
) -> Result<()> {
    let compose_str = serde_yaml::to_string(compose)?;
    std::fs::write(output_path, compose_str)?;
    if !service_config.warnings.is_empty() {
        println!();
        for exposed_port in &service_config.warnings {
            println!("Warning: {exposed_port}");
        }
        println!()
    }
    // if file logging is enabled, warn about permissions
    let cb_config = &service_config.config_info.cb_config;
    if cb_config.logs.file.enabled {
        let log_dir = &cb_config.logs.file.dir_path;
        println!(
            "Warning: file logging is enabled, you may need to update permissions for the logs directory. e.g. with:\n\t`sudo chown -R 10001:10001 {}`",
            log_dir.display()
        );
        println!()
    }
    println!("Docker Compose file written to: {output_path:?}");
    Ok(())
}

/// Writes the envs to a .env file
fn write_env_file(envs: &IndexMap<String, String>, output_path: &Path) -> Result<()> {
    let envs_str = {
        let mut envs_str = String::new();
        for (k, v) in envs {
            envs_str.push_str(&format!("{k}={v}\n"));
        }
        envs_str
    };
    std::fs::write(output_path, envs_str)?;
    println!("Env file written to: {output_path:?}");
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
    map.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",")
}
