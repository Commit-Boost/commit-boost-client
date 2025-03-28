use std::collections::HashMap;

use eyre::{ContextCompat, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use toml::Table;

use crate::{
    commit::client::SignerClient,
    config::{
        constants::{CONFIG_ENV, MODULE_ID_ENV, MODULE_JWT_ENV, SIGNER_URL_ENV},
        load_env_var,
        utils::load_file_from_env,
        BUILDER_PORT_ENV,
    },
    types::{Chain, Jwt, ModuleId},
};

#[derive(Debug, Deserialize, Serialize)]
pub enum ModuleKind {
    #[serde(alias = "commit")]
    Commit,
    #[serde(alias = "events")]
    Events,
}

/// Static module config from config file
#[derive(Debug, Deserialize, Serialize)]
pub struct StaticModuleConfig {
    /// Unique id of the module
    pub id: ModuleId,
    /// Docker image of the module
    pub docker_image: String,
    /// Environment variables for the module
    pub env: Option<HashMap<String, String>>,
    /// Environment file for the module
    pub env_file: Option<String>,
    /// Type of the module
    #[serde(rename = "type")]
    pub kind: ModuleKind,
}

/// Runtime config to start a module
#[derive(Debug)]
pub struct StartCommitModuleConfig<T = ()> {
    /// Unique id of the module
    pub id: ModuleId,
    /// Chain spec
    pub chain: Chain,
    /// Signer client to call Signer API
    pub signer_client: SignerClient,
    /// Opaque module config
    pub extra: T,
}

/// Loads a module config from the environment and config file:
/// - [MODULE_ID_ENV] - the id of the module to load
/// - [CB_CONFIG_ENV] - the path to the config file
/// - [MODULE_JWT_ENV] - the jwt token for the module
// TODO: add metrics url here
pub fn load_commit_module_config<T: DeserializeOwned>() -> Result<StartCommitModuleConfig<T>> {
    let module_id = ModuleId(load_env_var(MODULE_ID_ENV)?);
    let module_jwt = Jwt(load_env_var(MODULE_JWT_ENV)?);
    let signer_server_url = load_env_var(SIGNER_URL_ENV)?.parse()?;

    #[derive(Debug, Deserialize)]
    struct ThisModuleConfig<U> {
        #[serde(flatten)]
        static_config: StaticModuleConfig,
        #[serde(flatten)]
        extra: U,
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum ThisModule<U> {
        Target(ThisModuleConfig<U>),
        #[allow(dead_code)]
        Other(Table),
    }

    #[derive(Deserialize, Debug)]
    struct StubConfig<U> {
        chain: Chain,
        modules: Vec<ThisModule<U>>,
    }

    // load module config including the extra data (if any)
    let cb_config: StubConfig<T> = load_file_from_env(CONFIG_ENV)?;

    // find all matching modules config
    let matches: Vec<ThisModuleConfig<T>> = cb_config
        .modules
        .into_iter()
        .filter_map(|m| match m {
            ThisModule::Target(config) => Some(config),
            _ => None,
        })
        .collect();

    eyre::ensure!(!matches.is_empty(), "Failed to find matching config type");

    let module_config = matches
        .into_iter()
        .find(|m| m.static_config.id == module_id)
        .wrap_err(format!("failed to find module for {module_id}"))?;

    let signer_client = SignerClient::new(signer_server_url, module_jwt, module_id)?;

    Ok(StartCommitModuleConfig {
        id: module_config.static_config.id,
        chain: cb_config.chain,
        signer_client,
        extra: module_config.extra,
    })
}

#[derive(Debug)]
pub struct StartBuilderModuleConfig<T> {
    /// Unique id of the module
    pub id: ModuleId,
    /// Chain spec
    pub chain: Chain,
    /// Where to listen for Builder events
    pub server_port: u16,
    /// Opaque module config
    pub extra: T,
}

pub fn load_builder_module_config<T: DeserializeOwned>() -> eyre::Result<StartBuilderModuleConfig<T>>
{
    let module_id = ModuleId(load_env_var(MODULE_ID_ENV)?);
    let builder_events_port: u16 = load_env_var(BUILDER_PORT_ENV)?.parse()?;

    #[derive(Debug, Deserialize)]
    struct ThisModuleConfig<U> {
        #[serde(flatten)]
        static_config: StaticModuleConfig,
        #[serde(flatten)]
        extra: U,
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum ThisModule<U> {
        Target(ThisModuleConfig<U>),
        #[allow(dead_code)]
        Other(Table),
    }

    #[derive(Deserialize, Debug)]
    struct StubConfig<U> {
        chain: Chain,
        modules: Vec<ThisModule<U>>,
    }

    // load module config including the extra data (if any)
    let cb_config: StubConfig<T> = load_file_from_env(CONFIG_ENV)?;

    // find all matching modules config
    let matches: Vec<ThisModuleConfig<T>> = cb_config
        .modules
        .into_iter()
        .filter_map(|m| match m {
            ThisModule::Target(config) => Some(config),
            _ => None,
        })
        .collect();

    eyre::ensure!(!matches.is_empty(), "Failed to find matching config type");

    let module_config = matches
        .into_iter()
        .find(|m| m.static_config.id == module_id)
        .wrap_err(format!("failed to find module for {module_id}"))?;

    Ok(StartBuilderModuleConfig {
        id: module_config.static_config.id,
        chain: cb_config.chain,
        server_port: builder_events_port,
        extra: module_config.extra,
    })
}
