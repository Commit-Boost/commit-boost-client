pub const APPLICATION_BUILDER_DOMAIN: [u8; 4] = [0, 0, 0, 1];
// In-protocol builder domain (consensus-specs DOMAIN_BEACON_BUILDER); not the
// legacy builder domain 0x00000001 nor the request-auth domain 0x0B000001.
pub const DOMAIN_BEACON_BUILDER: [u8; 4] = [0x0B, 0x00, 0x00, 0x00];
// Out-of-protocol Builder API request-auth domain (builder-specs
// DOMAIN_REQUEST_AUTH), for `RequestAuth` only.
pub const DOMAIN_REQUEST_AUTH: [u8; 4] = [0x0B, 0x00, 0x00, 0x01];
// TODO placeholders: gloas devnet fork version
pub const GLOAS_FORK_VERSION: [u8; 4] = [0x80, 0x43, 0x50, 0x48];
pub const GENESIS_VALIDATORS_ROOT: [u8; 32] = [0; 32];
pub const COMMIT_BOOST_DOMAIN: [u8; 4] = [109, 109, 111, 67];
pub const COMMIT_BOOST_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const COMMIT_BOOST_COMMIT: &str = env!("GIT_HASH");
pub const SIGNER_JWT_EXPIRATION: u64 = 300; // 5 minutes
