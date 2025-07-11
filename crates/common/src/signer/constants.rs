pub const DEFAULT_SIGNER_PORT: u16 = 20000;

// Rate limit signer API requests for 5 minutes after the endpoint has 3 JWT
// auth failures
pub const DEFAULT_JWT_AUTH_FAIL_LIMIT: u32 = 3;
pub const DEFAULT_JWT_AUTH_FAIL_TIMEOUT_SECONDS: u32 = 5 * 60;
