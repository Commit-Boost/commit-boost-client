pub const APPLICATION_BUILDER_DOMAIN: [u8; 4] = [0, 0, 0, 1];
pub const GENESIS_VALIDATORS_ROOT: [u8; 32] = [0; 32];

// MAINNET
pub const MAINNET_FORK_VERSION: [u8; 4] = [0u8; 4];
pub const MAINNET_BUILDER_DOMAIN: [u8; 32] = [
    0, 0, 0, 1, 245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0,
    61, 35, 32, 217, 240, 232, 234, 152, 49, 169,
];
pub const MAINNET_GENESIS_TIME_SECONDS: u64 = 1606824023;

// HOLESKY
pub const HOLESKY_FORK_VERSION: [u8; 4] = [1, 1, 112, 0];
pub const HOLESKY_BUILDER_DOMAIN: [u8; 32] = [
    0, 0, 0, 1, 91, 131, 162, 55, 89, 197, 96, 178, 208, 198, 69, 118, 225, 220, 252, 52, 234, 148,
    196, 152, 143, 62, 13, 159, 119, 240, 83, 135,
];
pub const HOLESKY_GENESIS_TIME_SECONDS: u64 = 1695902400;

// RHEA DEVNET
pub const RHEA_FORK_VERSION: [u8; 4] = [16, 0, 0, 56];
pub const RHEA_BUILDER_DOMAIN: [u8; 32] = [
    0, 0, 0, 1, 11, 65, 190, 76, 219, 52, 209, 131, 221, 220, 165, 57, 131, 55, 98, 109, 205, 207,
    175, 23, 32, 193, 32, 45, 59, 149, 248, 78,
];
pub const RHEA_GENESIS_TIME_SECONDS: u64 = 1718117531;

// HELDER
pub const HELDER_FORK_VERSION: [u8; 4] = [50, 13, 27, 36]; // deneb
pub const HELDER_BUILDER_DOMAIN: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
pub const HELDER_GENESIS_TIME_SECONDS: u64 = 1718967660;
