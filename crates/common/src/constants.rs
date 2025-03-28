pub const APPLICATION_BUILDER_DOMAIN: [u8; 4] = [0, 0, 0, 1];
pub const GENESIS_VALIDATORS_ROOT: [u8; 32] = [0; 32];
pub const COMMIT_BOOST_DOMAIN: [u8; 4] = [109, 109, 111, 67];
pub const COMMIT_BOOST_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const COMMIT_BOOST_COMMIT: &str = env!("GIT_HASH");
pub const SIGNER_JWT_EXPIRATION: u64 = 300; // 5 minutes
