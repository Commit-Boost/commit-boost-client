pub const MODULE_ID_ENV: &str = "CB_MODULE_ID";
pub const MODULE_JWT_ENV: &str = "CB_SIGNER_JWT";
pub const METRICS_SERVER_ENV: &str = "METRICS_SERVER";
pub const SIGNER_SERVER_ENV: &str = "SIGNER_SERVER";
pub const BUILDER_SERVER_ENV: &str = "BUILDER_SERVER";

pub const CB_BASE_LOG_PATH: &str = "/var/logs/";

pub const CB_CONFIG_ENV: &str = "CB_CONFIG";
pub const CB_CONFIG_NAME: &str = "/cb-config.toml";

pub const SIGNER_KEYS_ENV: &str = "CB_SIGNER_FILE";
pub const SIGNER_KEYS: &str = "/keys.json";
pub const SIGNER_DIR_KEYS_ENV: &str = "SIGNER_LOADER_DIR_KEYS";
pub const SIGNER_DIR_KEYS: &str = "/keys";
pub const SIGNER_DIR_SECRETS_ENV: &str = "SIGNER_LOADER_DIR_SECRETS";
pub const SIGNER_DIR_SECRETS: &str = "/secrets";

pub const JWTS_ENV: &str = "CB_JWTS";

// TODO: replace these with an actual image in the registry
pub const PBS_DEFAULT_IMAGE: &str = "commitboost_pbs_default";
pub const SIGNER_IMAGE: &str = "commitboost_signer";
