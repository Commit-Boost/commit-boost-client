use std::{path::Path, vec};

use cb_common::{
    config::{
        CommitBoostConfig, SignerLoader, CB_CONFIG_ENV, CB_CONFIG_NAME, JWTS_ENV, MODULE_JWT_ENV,
        SIGNER_LOADER_ENV, SIGNER_LOADER_NAME,
    },
    utils::random_jwt,
};
use docker_compose_types::{
    AdvancedBuildStep, BuildStep, Compose, DependsOnOptions, Environment, MapOrEmpty,
    NetworkSettings, Networks, Ports, Service, Services, SingleValue, Volumes,
};
use indexmap::IndexMap;

// TODO: pass these via cli
const DEFAULT_PBS_DOCKERFILE: &str = "./docker/pbs.Dockerfile";
const DEFAULT_SIGNER_DOCKERFILE: &str = "./docker/signer.Dockerfile";
const DEFAULT_PROMETHEUS_DOCKERFILE: &str = "./docker/prometheus.Dockerfile";

pub(super) const CB_CONFIG_FILE: &str = "cb-config.toml";
pub(super) const CB_COMPOSE_FILE: &str = "cb.docker-compose.yml";
pub(super) const CB_ENV_FILE: &str = ".cb.env";

/// Builds the docker compose file for the Commit-Boost services

// TODO: do more validation for paths, images, etc
pub fn handle_docker_init(config_path: String, output_dir: String) -> eyre::Result<()> {
    println!("Initializing Commit-Boost with config file: {}", config_path);

    let cb_config = CommitBoostConfig::from_file(&config_path);

    let mut services = IndexMap::new();

    // config volume to pass to all services
    let config_volume = Volumes::Simple(format!("./{}:{}:ro", config_path, CB_CONFIG_NAME));

    let mut jwts = IndexMap::new();
    // envs to write in .env file
    let mut envs = IndexMap::from([(CB_CONFIG_ENV.into(), CB_CONFIG_NAME.into())]);

    // setup pbs service
    // TODO: support custom pbs images + signer with jwt

    // Must be rebuilt, eventually this should be pulled by default from the registry
    let build = AdvancedBuildStep {
        context: ".".to_owned(),
        dockerfile: Some(DEFAULT_PBS_DOCKERFILE.to_owned()),
        ..AdvancedBuildStep::default()
    };

    let pbs_envs = IndexMap::from([get_env_same(CB_CONFIG_ENV)]);

    let pbs_service = Service {
        container_name: Some("cb-pbs".to_owned()),
        build_: Some(BuildStep::Advanced(build)),
        // TODO: namespace networks
        network_mode: Some("host".to_owned()),
        volumes: vec![config_volume.clone()],
        environment: Environment::KvPair(pbs_envs),
        ..Service::default()
    };

    services.insert("cb-pbs".to_owned(), Some(pbs_service));

    // setup modules
    if let Some(modules_config) = cb_config.modules {
        for module in modules_config {
            // TODO: support modules volumes and network

            let module_cid = format!("cb-{}", module.id.to_lowercase());

            let jwt = random_jwt();
            let jwt_name = format!("CB_JWT_{}", module.id.to_uppercase());

            // module ids are assumed unique, so envs dont override each other
            let module_envs = IndexMap::from([
                get_env_same(CB_CONFIG_ENV),
                get_env_interp(MODULE_JWT_ENV, &jwt_name),
            ]);

            envs.insert(jwt_name.clone(), jwt.clone());
            jwts.insert(module.id.clone(), jwt);

            let module_service = Service {
                container_name: Some(module_cid.clone()),
                image: Some(module.docker_image),
                network_mode: Some("host".to_owned()),
                volumes: vec![config_volume.clone()],
                environment: Environment::KvPair(module_envs),
                ..Service::default()
            };

            services.insert(module_cid, Some(module_service));
        }
    };

    // TODO: validate if we have signer moduels but not signer config

    // setup signer service
    if let Some(signer_config) = cb_config.signer {
        // Must be rebuilt, eventually this should be pulled by default from the registry
        let build = AdvancedBuildStep {
            context: ".".to_owned(),
            dockerfile: Some(DEFAULT_SIGNER_DOCKERFILE.to_owned()),
            ..AdvancedBuildStep::default()
        };

        // TODO: generalize this, different loaders may not need volumes but eg ports
        let signer_volume = match signer_config.loader {
            SignerLoader::File { key_path } => {
                Volumes::Simple(format!("./{}:{}:ro", key_path, SIGNER_LOADER_NAME))
            }
        };

        let signer_envs = IndexMap::from([
            get_env_same(CB_CONFIG_ENV),
            get_env_same(SIGNER_LOADER_ENV),
            get_env_same(JWTS_ENV),
        ]);

        envs.insert(SIGNER_LOADER_ENV.into(), SIGNER_LOADER_NAME.into());

        // write jwts to env
        let jwts_json = serde_json::to_string(&jwts).unwrap().clone();
        envs.insert(JWTS_ENV.into(), format!("{jwts_json:?}"));

        let signer_service = Service {
            container_name: Some("cb-signer".to_owned()),
            build_: Some(BuildStep::Advanced(build)),
            // TODO: namespace networks, no need to expose any port outside
            network_mode: Some("host".to_owned()),
            volumes: vec![config_volume.clone(), signer_volume],
            environment: Environment::KvPair(signer_envs),
            ..Service::default()
        };

        services.insert("cb-signer".to_owned(), Some(signer_service));
    };

    // setup metrics services

    let mut compose = Compose::default();

    // TODO: make this configurable
    if let Some(_) = cb_config.metrics {
        let networks = Networks::Simple(vec!["monitoring".to_owned()]);

        compose.networks.0.insert(
            "monitoring".to_owned(),
            MapOrEmpty::Map(NetworkSettings {
                driver: Some("bridge".to_owned()),
                ..NetworkSettings::default()
            }),
        );

        let build = AdvancedBuildStep {
            context: ".".to_owned(),
            dockerfile: Some(DEFAULT_PROMETHEUS_DOCKERFILE.to_owned()),
            ..AdvancedBuildStep::default()
        };

        let prometheus_service = Service {
            container_name: Some("cb-prometheus".to_owned()),
            build_: Some(BuildStep::Advanced(build)),
            // Only in case we'd want to inspect this in the browser, otherwise not needed
            ports: Ports::Short(vec!["9090:9090".to_owned()]),

            networks: networks.clone(),
            ..Service::default()
        };

        services.insert("cb-prometheus".to_owned(), Some(prometheus_service));

        let grafana_service = Service {
            container_name: Some("cb-grafana".to_owned()),
            image: Some("grafana/grafana:latest".to_owned()),
            ports: Ports::Short(vec!["3000:3000".to_owned()]),
            networks: networks.clone(),
            depends_on: DependsOnOptions::Simple(vec!["cb-prometheus".to_owned()]),
            environment: Environment::List(vec!["GF_SECURITY_ADMIN_PASSWORD=admin".to_owned()]),
            ..Service::default()
        };

        services.insert("cb-grafana".to_owned(), Some(grafana_service));
    };

    compose.services = Services(services);

    // write compose to file
    let compose_str = serde_yaml::to_string(&compose)?;
    let compose_path = Path::new(&output_dir).join(CB_COMPOSE_FILE);
    // TODO: check if file exists already and avoid overwriting
    std::fs::write(&compose_path, compose_str)?;
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

    println!("Run with:\n\t`commit-boost start --docker {:?} --env {:?}`", compose_path, env_path);

    Ok(())
}

// FOO=${FOO}
fn get_env_same(k: &str) -> (String, Option<SingleValue>) {
    get_env_interp(k, k)
}

// FOO=${BAR}
fn get_env_interp(k: &str, v: &str) -> (String, Option<SingleValue>) {
    (k.into(), Some(SingleValue::String(format!("${{{v}}}"))))
}
