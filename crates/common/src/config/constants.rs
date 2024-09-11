///////////////////////// COMMMON /////////////////////////

/// Path to the main toml config file
pub const CB_CONFIG_ENV: &str = "CB_CONFIG";
pub const CB_CONFIG_DEFAULT: &str = "/cb-config.toml";

/// Where to receive scrape requests from Prometheus
pub const METRICS_SERVER_ENV: &str = "METRICS_SERVER";

/// Path to logs directory
pub const LOGS_DIR_ENV: &str = "CB_LOGS_DIR";
pub const LOGS_DIR_DEFAULT: &str = "/var/logs/commit-boost";

///////////////////////// PBS /////////////////////////

pub const PBS_IMAGE_DEFAULT: &str = "ghcr.io/commit-boost/pbs:latest";
pub const PBS_MODULE_NAME: &str = "pbs";

///////////////////////// SIGNER /////////////////////////

pub const SIGNER_IMAGE_DEFAULT: &str = "ghcr.io/commit-boost/signer:latest";
pub const SIGNER_MODULE_NAME: &str = "signer";

/// Comma separated list module_id=jwt_secret
pub const JWTS_ENV: &str = "CB_JWTS";

/// Path to json file with plaintext keys (testing only)
pub const SIGNER_KEYS_ENV: &str = "CB_SIGNER_FILE";
pub const SIGNER_DEFAULT: &str = "/keys.json";
/// Path to `keys` folder
pub const SIGNER_DIR_KEYS_ENV: &str = "SIGNER_LOADER_DIR_KEYS";
pub const SIGNER_DIR_KEYS_DEFAULT: &str = "/keys";
/// Path to `secrets` folder
pub const SIGNER_DIR_SECRETS_ENV: &str = "SIGNER_LOADER_DIR_SECRETS";
pub const SIGNER_DIR_SECRETS: &str = "/secrets";

///////////////////////// MODULES /////////////////////////

/// The unique ID of the module
pub const MODULE_ID_ENV: &str = "CB_MODULE_ID";

// Commit modules
/// The JWT secret for the module to communicate with the signer module
pub const MODULE_JWT_ENV: &str = "CB_SIGNER_JWT";
/// Where to send signature request
pub const SIGNER_SERVER_ENV: &str = "SIGNER_SERVER";

/// Events modules
/// Where to receive builder events
pub const BUILDER_SERVER_ENV: &str = "BUILDER_SERVER";
