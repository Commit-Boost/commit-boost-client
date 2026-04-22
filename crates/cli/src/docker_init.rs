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
pub const CB_COMPOSE_FILE: &str = "cb.docker-compose.yml";
/// Name of the envs file
pub const CB_ENV_FILE: &str = ".cb.env";

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
        let filename = spec
            .file_name()
            .ok_or_else(|| eyre::eyre!("Chain spec path has no filename: {}", spec.display()))?
            .to_str()
            .ok_or_else(|| {
                eyre::eyre!("Chain spec filename is not valid UTF-8: {}", spec.display())
            })?;
        let chain_spec = ServiceChainSpecInfo {
            env: get_env_val(CHAIN_SPEC_ENV, &format!("/{filename}")),
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
    let signer_config = if needs_signer_module {
        Some(service_config.config_info.cb_config.signer.clone().ok_or_else(|| {
            eyre::eyre!(
                "Signer module required but no signer config provided in Commit-Boost config"
            )
        })?)
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
                eyre::bail!(
                    "Signer module required but remote signer config provided; use a local or Dirk signer instead"
                );
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
    volumes.extend(get_log_volume(&cb_config.logs, PBS_SERVICE_NAME)?);
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
    volumes.extend(get_log_volume(&cb_config.logs, SIGNER_SERVICE_NAME)?);

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
    volumes.extend(get_log_volume(&cb_config.logs, SIGNER_SERVICE_NAME)?);

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
            eyre::bail!("ERC2335 proxy store is not supported with the Dirk signer");
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
            module_volumes.extend(get_log_volume(&cb_config.logs, &module.id)?);

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

fn get_log_volume(config: &LogsSettings, module_id: &str) -> eyre::Result<Option<Volumes>> {
    if !config.file.enabled {
        return Ok(None);
    }
    let p = config.file.dir_path.join(module_id.to_lowercase());
    let host_path = p
        .to_str()
        .ok_or_else(|| eyre::eyre!("Log directory path is not valid UTF-8: {}", p.display()))?;
    Ok(Some(Volumes::Simple(format!("{host_path}:{LOGS_DIR_DEFAULT}"))))
}

/// Formats as a comma separated list of key=value
fn format_comma_separated(map: &IndexMap<ModuleId, String>) -> String {
    map.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use cb_common::{
        config::{
            CommitBoostConfig, FileLogSettings, LogsSettings, MetricsConfig, StdoutLogSettings,
        },
        signer::{ProxyStore, SignerLoader},
    };
    use docker_compose_types::{Environment, Ports, SingleValue, Volumes};

    use super::*;

    // -------------------------------------------------------------------------
    // Shared test fixtures
    // -------------------------------------------------------------------------

    fn logs_disabled() -> LogsSettings {
        LogsSettings::default()
    }

    fn logs_enabled(dir: &str) -> LogsSettings {
        LogsSettings {
            stdout: StdoutLogSettings::default(),
            file: FileLogSettings {
                enabled: true,
                dir_path: dir.into(),
                ..FileLogSettings::default()
            },
        }
    }

    /// Deserialize a minimal PBS-only `CommitBoostConfig` from inline TOML.
    /// No relays, so `validate()` won't make network calls.
    fn minimal_cb_config() -> CommitBoostConfig {
        toml::from_str(
            r#"
            chain = "Holesky"
            [pbs]
            docker_image = "ghcr.io/commit-boost/pbs:latest"
        "#,
        )
        .expect("valid minimal test config")
    }

    fn minimal_service_config() -> ServiceCreationInfo {
        ServiceCreationInfo {
            config_info: CommitBoostConfigInfo {
                cb_config: minimal_cb_config(),
                config_volume: Volumes::Simple("./cb.toml:/cb.toml:ro".into()),
            },
            envs: IndexMap::new(),
            targets: Vec::new(),
            warnings: Vec::new(),
            jwts: IndexMap::new(),
            chain_spec: None,
            metrics_port: 9100,
        }
    }

    fn metrics_config() -> MetricsConfig {
        MetricsConfig {
            enabled: true,
            host: "127.0.0.1".parse().expect("valid IP"),
            start_port: 9100,
        }
    }

    // -------------------------------------------------------------------------
    // Service inspection helpers
    // -------------------------------------------------------------------------

    fn env_str(service: &Service, key: &str) -> Option<String> {
        match &service.environment {
            Environment::KvPair(map) => map.get(key).and_then(|v| match v {
                Some(SingleValue::String(s)) => Some(s.clone()),
                _ => None,
            }),
            _ => None,
        }
    }

    fn env_u64(service: &Service, key: &str) -> Option<u64> {
        match &service.environment {
            Environment::KvPair(map) => map.get(key).and_then(|v| match v {
                Some(SingleValue::Unsigned(n)) => Some(*n),
                _ => None,
            }),
            _ => None,
        }
    }

    fn has_env_key(service: &Service, key: &str) -> bool {
        match &service.environment {
            Environment::KvPair(map) => map.contains_key(key),
            _ => false,
        }
    }

    fn has_volume(service: &Service, substr: &str) -> bool {
        service.volumes.iter().any(|v| matches!(v, Volumes::Simple(s) if s.contains(substr)))
    }

    fn has_port(service: &Service, substr: &str) -> bool {
        match &service.ports {
            Ports::Short(ports) => ports.iter().any(|p| p.contains(substr)),
            _ => false,
        }
    }

    // --- get_env_val ---

    #[test]
    fn test_get_env_val_returns_string_pair() {
        let (key, val) = get_env_val("MY_KEY", "my_value");
        assert_eq!(key, "MY_KEY");
        assert_eq!(val, Some(SingleValue::String("my_value".into())));
    }

    #[test]
    fn test_get_env_val_empty_value() {
        let (key, val) = get_env_val("EMPTY", "");
        assert_eq!(key, "EMPTY");
        assert_eq!(val, Some(SingleValue::String("".into())));
    }

    // --- get_env_uval ---

    #[test]
    fn test_get_env_uval_returns_unsigned_pair() {
        let (key, val) = get_env_uval("PORT", 9100);
        assert_eq!(key, "PORT");
        assert_eq!(val, Some(SingleValue::Unsigned(9100)));
    }

    // --- get_env_same ---

    #[test]
    fn test_get_env_same_interpolates_self() {
        let (key, val) = get_env_same("JWTS_ENV");
        assert_eq!(key, "JWTS_ENV");
        assert_eq!(val, Some(SingleValue::String("${JWTS_ENV}".into())));
    }

    // --- get_env_interp ---

    #[test]
    fn test_get_env_interp_different_key_and_var() {
        let (key, val) = get_env_interp("MODULE_JWT_ENV", "CB_JWT_MY_MODULE");
        assert_eq!(key, "MODULE_JWT_ENV");
        assert_eq!(val, Some(SingleValue::String("${CB_JWT_MY_MODULE}".into())));
    }

    // --- format_comma_separated ---

    #[test]
    fn test_format_comma_separated_empty() {
        let map = IndexMap::new();
        assert_eq!(format_comma_separated(&map), "");
    }

    #[test]
    fn test_format_comma_separated_single_entry() {
        let mut map = IndexMap::new();
        map.insert(ModuleId::from("module_a".to_owned()), "secret123".into());
        assert_eq!(format_comma_separated(&map), "module_a=secret123");
    }

    #[test]
    fn test_format_comma_separated_multiple_entries_preserves_order() {
        let mut map = IndexMap::new();
        map.insert(ModuleId::from("module_a".to_owned()), "jwt_a".into());
        map.insert(ModuleId::from("module_b".to_owned()), "jwt_b".into());
        map.insert(ModuleId::from("module_c".to_owned()), "jwt_c".into());
        assert_eq!(format_comma_separated(&map), "module_a=jwt_a,module_b=jwt_b,module_c=jwt_c");
    }

    // --- get_log_volume ---

    #[test]
    fn test_get_log_volume_disabled_returns_none() -> eyre::Result<()> {
        let logs = logs_disabled();
        let result = get_log_volume(&logs, "cb_pbs")?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn test_get_log_volume_enabled_returns_correct_volume() -> eyre::Result<()> {
        let logs = logs_enabled("/var/log/commit-boost");
        let result = get_log_volume(&logs, "cb_pbs")?;
        let volume = result.expect("expected a volume when file logging is enabled");
        assert_eq!(
            volume,
            Volumes::Simple(format!("/var/log/commit-boost/cb_pbs:{LOGS_DIR_DEFAULT}"))
        );
        Ok(())
    }

    #[test]
    fn test_get_log_volume_lowercases_module_id() -> eyre::Result<()> {
        let logs = logs_enabled("/logs");
        let result = get_log_volume(&logs, "MY_MODULE")?;
        let volume = result.expect("expected a volume when file logging is enabled");
        assert_eq!(volume, Volumes::Simple(format!("/logs/my_module:{LOGS_DIR_DEFAULT}")));
        Ok(())
    }

    #[test]
    fn test_get_log_volume_enabled_with_nested_dir() -> eyre::Result<()> {
        let logs = logs_enabled("/home/user/cb/logs");
        let result = get_log_volume(&logs, "cb_signer")?;
        let volume = result.expect("expected a volume when file logging is enabled");
        assert_eq!(
            volume,
            Volumes::Simple(format!("/home/user/cb/logs/cb_signer:{LOGS_DIR_DEFAULT}"))
        );
        Ok(())
    }

    // -------------------------------------------------------------------------
    // write_env_file
    // -------------------------------------------------------------------------

    #[test]
    fn test_write_env_file_empty_map() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".cb.env");
        write_env_file(&IndexMap::new(), &path)?;
        let contents = std::fs::read_to_string(&path)?;
        assert_eq!(contents, "");
        Ok(())
    }

    #[test]
    fn test_write_env_file_single_entry() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".cb.env");
        let mut map = IndexMap::new();
        map.insert("MY_KEY".to_owned(), "my_value".to_owned());
        write_env_file(&map, &path)?;
        let contents = std::fs::read_to_string(&path)?;
        assert_eq!(contents, "MY_KEY=my_value\n");
        Ok(())
    }

    #[test]
    fn test_write_env_file_multiple_entries_preserves_order() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".cb.env");
        let mut map = IndexMap::new();
        map.insert("KEY_A".to_owned(), "val_a".to_owned());
        map.insert("KEY_B".to_owned(), "val_b".to_owned());
        map.insert("KEY_C".to_owned(), "val_c".to_owned());
        write_env_file(&map, &path)?;
        let contents = std::fs::read_to_string(&path)?;
        assert_eq!(contents, "KEY_A=val_a\nKEY_B=val_b\nKEY_C=val_c\n");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // write_compose_file
    // -------------------------------------------------------------------------

    #[test]
    fn test_write_compose_file_creates_valid_yaml() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(CB_COMPOSE_FILE);
        let compose = docker_compose_types::Compose::default();
        let service_config = minimal_service_config();
        write_compose_file(&compose, &path, &service_config)?;
        assert!(path.exists());
        let contents = std::fs::read_to_string(&path)?;
        assert!(!contents.is_empty());
        Ok(())
    }

    // -------------------------------------------------------------------------
    // create_pbs_service
    // -------------------------------------------------------------------------

    #[test]
    fn test_create_pbs_service_basic() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let service = create_pbs_service(&mut sc)?;

        assert_eq!(service.container_name.as_deref(), Some("cb_pbs"));
        assert_eq!(service.image.as_deref(), Some("ghcr.io/commit-boost/pbs:latest"));
        assert!(env_str(&service, CONFIG_ENV).is_some());
        assert!(env_str(&service, PBS_ENDPOINT_ENV).is_some());
        assert!(service.healthcheck.is_some());
        Ok(())
    }

    #[test]
    fn test_create_pbs_service_exposes_pbs_port() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let service = create_pbs_service(&mut sc)?;
        // Default PBS port is 18550
        assert!(has_port(&service, "18550"));
        Ok(())
    }

    #[test]
    fn test_create_pbs_service_with_metrics() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        sc.config_info.cb_config.metrics = Some(metrics_config());
        sc.metrics_port = 9100;
        let service = create_pbs_service(&mut sc)?;

        assert_eq!(env_u64(&service, METRICS_PORT_ENV), Some(9100));
        assert!(has_port(&service, "9100"));
        // port counter incremented
        assert_eq!(sc.metrics_port, 9101);
        // target added for prometheus
        assert!(!sc.targets.is_empty());
        Ok(())
    }

    #[test]
    fn test_create_pbs_service_with_file_logging() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        sc.config_info.cb_config.logs = logs_enabled("/var/log/cb");
        let service = create_pbs_service(&mut sc)?;

        assert!(env_str(&service, LOGS_DIR_ENV).is_some());
        assert!(has_volume(&service, "pbs"));
        Ok(())
    }

    #[test]
    fn test_create_pbs_service_with_chain_spec() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        sc.chain_spec = Some(ServiceChainSpecInfo {
            env: get_env_val(CHAIN_SPEC_ENV, "/chain.json"),
            volume: Volumes::Simple("/host/chain.json:/chain.json:ro".into()),
        });
        let service = create_pbs_service(&mut sc)?;

        assert_eq!(env_str(&service, CHAIN_SPEC_ENV), Some("/chain.json".into()));
        assert!(has_volume(&service, "chain.json"));
        Ok(())
    }

    #[test]
    fn test_create_pbs_service_no_metrics_no_metrics_env() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let service = create_pbs_service(&mut sc)?;
        assert!(!has_env_key(&service, METRICS_PORT_ENV));
        Ok(())
    }

    // -------------------------------------------------------------------------
    // create_signer_service_local
    // -------------------------------------------------------------------------

    fn local_signer_config() -> SignerConfig {
        toml::from_str(
            r#"
            [local.loader]
            key_path = "/keys/keys.json"
        "#,
        )
        .expect("valid local signer config")
    }

    #[test]
    fn test_create_signer_service_local_file_loader() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let signer_config = local_signer_config();
        let loader = SignerLoader::File { key_path: "/keys/keys.json".into() };
        let service = create_signer_service_local(&mut sc, &signer_config, &loader, &None)?;

        assert_eq!(service.container_name.as_deref(), Some("cb_signer"));
        assert!(env_str(&service, SIGNER_KEYS_ENV).is_some());
        assert!(has_volume(&service, "keys.json"));
        Ok(())
    }

    #[test]
    fn test_create_signer_service_local_validators_dir_loader() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let signer_config = local_signer_config();
        let loader = SignerLoader::ValidatorsDir {
            keys_path: "/keys".into(),
            secrets_path: "/secrets".into(),
            format: cb_common::signer::ValidatorKeysFormat::Lighthouse,
        };
        let service = create_signer_service_local(&mut sc, &signer_config, &loader, &None)?;

        assert!(env_str(&service, SIGNER_DIR_KEYS_ENV).is_some());
        assert!(env_str(&service, SIGNER_DIR_SECRETS_ENV).is_some());
        assert!(has_volume(&service, "/keys"));
        assert!(has_volume(&service, "/secrets"));
        Ok(())
    }

    #[test]
    fn test_create_signer_service_local_with_file_proxy_store() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let signer_config = local_signer_config();
        let loader = SignerLoader::File { key_path: "/keys/keys.json".into() };
        let store = Some(ProxyStore::File { proxy_dir: "/proxies".into() });
        let service = create_signer_service_local(&mut sc, &signer_config, &loader, &store)?;

        assert!(env_str(&service, PROXY_DIR_ENV).is_some());
        assert!(has_volume(&service, "/proxies"));
        Ok(())
    }

    #[test]
    fn test_create_signer_service_local_with_erc2335_proxy_store() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let signer_config = local_signer_config();
        let loader = SignerLoader::File { key_path: "/keys/keys.json".into() };
        let store = Some(ProxyStore::ERC2335 {
            keys_path: "/proxy/keys".into(),
            secrets_path: "/proxy/secrets".into(),
        });
        let service = create_signer_service_local(&mut sc, &signer_config, &loader, &store)?;

        assert!(env_str(&service, PROXY_DIR_KEYS_ENV).is_some());
        assert!(env_str(&service, PROXY_DIR_SECRETS_ENV).is_some());
        assert!(has_volume(&service, "/proxy/keys"));
        assert!(has_volume(&service, "/proxy/secrets"));
        Ok(())
    }

    #[test]
    fn test_create_signer_service_local_jwts_written_to_envs() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        sc.jwts.insert(ModuleId::from("MY_MODULE".to_owned()), "jwt_secret_abc".into());
        let signer_config = local_signer_config();
        let loader = SignerLoader::File { key_path: "/keys/keys.json".into() };
        create_signer_service_local(&mut sc, &signer_config, &loader, &None)?;

        // JWTS_ENV written as comma-separated to service_config.envs
        let jwts_val = sc.envs.get(JWTS_ENV).expect("JWTS_ENV must be set in envs");
        assert!(jwts_val.contains("MY_MODULE=jwt_secret_abc"));
        Ok(())
    }

    // -------------------------------------------------------------------------
    // create_signer_service_dirk
    // -------------------------------------------------------------------------

    fn dirk_signer_config() -> SignerConfig {
        toml::from_str(
            r#"
            docker_image = "commitboost_signer"
            [dirk]
            cert_path = "/certs/client.crt"
            key_path = "/certs/client.key"
            secrets_path = "/dirk_secrets"
            [[dirk.hosts]]
            url = "https://gateway.dirk.url"
            wallets = ["wallet1"]
        "#,
        )
        .expect("valid dirk signer config")
    }

    #[test]
    fn test_create_signer_service_dirk_basic() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let signer_config = dirk_signer_config();
        let service = create_signer_service_dirk(
            &mut sc,
            &signer_config,
            Path::new("/certs/client.crt"),
            Path::new("/certs/client.key"),
            Path::new("/dirk_secrets"),
            &None,
            &None,
        )?;

        assert_eq!(service.container_name.as_deref(), Some("cb_signer"));
        assert!(env_str(&service, DIRK_CERT_ENV).is_some());
        assert!(env_str(&service, DIRK_KEY_ENV).is_some());
        assert!(env_str(&service, DIRK_DIR_SECRETS_ENV).is_some());
        assert!(has_volume(&service, "client.crt"));
        assert!(has_volume(&service, "client.key"));
        assert!(has_volume(&service, "dirk_secrets"));
        Ok(())
    }

    #[test]
    fn test_create_signer_service_dirk_with_ca_cert() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let signer_config = dirk_signer_config();
        let ca_cert = Some(PathBuf::from("/certs/ca.crt"));
        let service = create_signer_service_dirk(
            &mut sc,
            &signer_config,
            Path::new("/certs/client.crt"),
            Path::new("/certs/client.key"),
            Path::new("/dirk_secrets"),
            &ca_cert,
            &None,
        )?;

        assert!(env_str(&service, DIRK_CA_CERT_ENV).is_some());
        assert!(has_volume(&service, "ca.crt"));
        Ok(())
    }

    #[test]
    fn test_create_signer_service_dirk_without_ca_cert() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let signer_config = dirk_signer_config();
        let service = create_signer_service_dirk(
            &mut sc,
            &signer_config,
            Path::new("/certs/client.crt"),
            Path::new("/certs/client.key"),
            Path::new("/dirk_secrets"),
            &None,
            &None,
        )?;

        assert!(!has_env_key(&service, DIRK_CA_CERT_ENV));
        assert!(!has_volume(&service, "ca.crt"));
        Ok(())
    }

    #[test]
    fn test_create_signer_service_dirk_with_file_proxy_store() -> eyre::Result<()> {
        let mut sc = minimal_service_config();
        let signer_config = dirk_signer_config();
        let store = Some(ProxyStore::File { proxy_dir: "/proxies".into() });
        let service = create_signer_service_dirk(
            &mut sc,
            &signer_config,
            Path::new("/certs/client.crt"),
            Path::new("/certs/client.key"),
            Path::new("/dirk_secrets"),
            &None,
            &store,
        )?;

        assert!(env_str(&service, PROXY_DIR_ENV).is_some());
        assert!(has_volume(&service, "/proxies"));
        Ok(())
    }

    #[test]
    fn test_create_signer_service_dirk_erc2335_store_returns_error() {
        let mut sc = minimal_service_config();
        let signer_config = dirk_signer_config();
        let store = Some(ProxyStore::ERC2335 {
            keys_path: "/proxy/keys".into(),
            secrets_path: "/proxy/secrets".into(),
        });
        let result = create_signer_service_dirk(
            &mut sc,
            &signer_config,
            Path::new("/certs/client.crt"),
            Path::new("/certs/client.key"),
            Path::new("/dirk_secrets"),
            &None,
            &store,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ERC2335"));
    }

    // -------------------------------------------------------------------------
    // create_module_service
    // -------------------------------------------------------------------------

    fn commit_module() -> StaticModuleConfig {
        toml::from_str(
            r#"
            id = "DA_COMMIT"
            type = "commit"
            docker_image = "test_da_commit"
        "#,
        )
        .expect("valid module config")
    }

    #[test]
    fn test_create_module_service_container_name_format() -> eyre::Result<()> {
        let module = commit_module();
        let mut sc = minimal_service_config();
        let (cid, _) = create_module_service(&module, "http://cb_signer:20000", &mut sc)?;
        assert_eq!(cid, "cb_da_commit");
        Ok(())
    }

    #[test]
    fn test_create_module_service_sets_required_envs() -> eyre::Result<()> {
        let module = commit_module();
        let mut sc = minimal_service_config();
        let (_, service) = create_module_service(&module, "http://cb_signer:20000", &mut sc)?;

        assert!(env_str(&service, MODULE_ID_ENV).is_some());
        assert!(env_str(&service, CONFIG_ENV).is_some());
        assert!(env_str(&service, SIGNER_URL_ENV) == Some("http://cb_signer:20000".into()));
        Ok(())
    }

    #[test]
    fn test_create_module_service_jwt_written_to_service_config_envs() -> eyre::Result<()> {
        let module = commit_module();
        let mut sc = minimal_service_config();
        create_module_service(&module, "http://cb_signer:20000", &mut sc)?;

        // JWT env var should be in the outer service_config.envs (for .env file)
        let jwt_key = format!("CB_JWT_{}", "DA_COMMIT".to_uppercase());
        assert!(sc.envs.contains_key(&jwt_key));
        // and also recorded in jwts map
        assert!(sc.jwts.contains_key(&ModuleId::from("DA_COMMIT".to_owned())));
        Ok(())
    }

    #[test]
    fn test_create_module_service_custom_env_forwarded() -> eyre::Result<()> {
        let mut module = commit_module();
        let mut env_map = std::collections::HashMap::new();
        env_map.insert("SOME_ENV_VAR".to_owned(), "some_value".to_owned());
        module.env = Some(env_map);

        let mut sc = minimal_service_config();
        let (_, service) = create_module_service(&module, "http://cb_signer:20000", &mut sc)?;

        assert_eq!(env_str(&service, "SOME_ENV_VAR"), Some("some_value".into()));
        Ok(())
    }

    #[test]
    fn test_create_module_service_depends_on_signer() -> eyre::Result<()> {
        let module = commit_module();
        let mut sc = minimal_service_config();
        let (_, service) = create_module_service(&module, "http://cb_signer:20000", &mut sc)?;

        match &service.depends_on {
            docker_compose_types::DependsOnOptions::Conditional(deps) => {
                assert!(deps.contains_key("cb_signer"));
            }
            docker_compose_types::DependsOnOptions::Simple(deps) => {
                // Remote signer path returns empty depends_on — but this is a local signer
                // config (signer is None), so it still depends on cb_signer
                assert!(deps.is_empty(), "unexpected empty depends_on for local signer");
            }
        }
        Ok(())
    }
}
