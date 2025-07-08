use const_format::concatcp;

pub const GET_PUBKEYS_PATH: &str = "/signer/v1/get_pubkeys";
pub const REQUEST_SIGNATURE_BASE_PATH: &str = "/signer/v1/request_signature";
pub const REQUEST_SIGNATURE_BLS_PATH: &str = concatcp!(REQUEST_SIGNATURE_BASE_PATH, "/bls");
pub const REQUEST_SIGNATURE_PROXY_BLS_PATH: &str =
    concatcp!(REQUEST_SIGNATURE_BASE_PATH, "/proxy-bls");
pub const REQUEST_SIGNATURE_PROXY_ECDSA_PATH: &str =
    concatcp!(REQUEST_SIGNATURE_BASE_PATH, "/proxy-ecdsa");
pub const GENERATE_PROXY_KEY_PATH: &str = "/signer/v1/generate_proxy_key";
pub const STATUS_PATH: &str = "/status";
pub const RELOAD_PATH: &str = "/reload";
