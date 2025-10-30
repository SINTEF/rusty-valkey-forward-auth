use anyhow::Error;
use confique::Config;
use std::net::IpAddr;

#[derive(Config)]
pub(crate) struct RVFAConfig {
    /// Port to listen on.
    #[config(env = "PORT", default = 8080)]
    pub port: u16,

    /// Bind address.
    #[config(env = "ADDRESS", default = "127.0.0.1")]
    pub address: IpAddr,

    /// Valkey server URL.
    #[config(env = "VALKEY_URL", default = "redis://127.0.0.1:6379")]
    pub valkey_url: String,

    /// Valkey username
    #[config(env = "VALKEY_USERNAME")]
    pub valkey_username: Option<String>,

    /// Valkey password
    #[config(env = "VALKEY_PASSWORD")]
    pub valkey_password: Option<String>,

    /// Token hashing salt (32 bytes hex-encoded, 64 characters). Used as the keyed blake3 salt.
    /// IMPORTANT: Keep this secret and consistent across deployments.
    #[config(
        env = "TOKEN_SALT",
        // echo rusty-valkey-forward-auth | sha256sum
        default = "3794447850d23a5db972dbe556437ec2edfe4294687843d7f0587bd9535beecf"
    )]
    pub token_salt: String,

    #[config(nested)]
    pub oauth: OAuthConfig,
}

impl RVFAConfig {
    pub fn load() -> Result<Self, Error> {
        let file = std::env::var("CONFIG_FILE").unwrap_or("settings.toml".to_string());
        Ok(RVFAConfig::builder().env().file(file).load()?)
    }

    pub fn token_salt_bytes(&self) -> Result<[u8; 32], Error> {
        let decoded = hex::decode(&self.token_salt)?;
        if decoded.len() != 32 {
            anyhow::bail!(
                "TOKEN_SALT must be exactly 32 bytes (64 hex characters), got {} bytes",
                decoded.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }
}

#[derive(Clone, Config)]
pub(crate) struct OAuthConfig {
    /// Issuer URL used for OIDC discovery and issuer validation.
    #[config(env = "OAUTH_ISSUER_URL")]
    pub issuer_url: Option<String>,

    /// Optional JWKS URL. When provided, discovery is skipped and the JWKS is polled directly.
    #[config(env = "OAUTH_JWKS_URL")]
    pub jwks_url: Option<String>,

    /// Optional tenant identifier to distinguish the configured authorization server.
    #[config(env = "OAUTH_TENANT_ID")]
    pub tenant_id: Option<String>,

    /// Audiences that incoming tokens must contain.
    #[config(default = [])]
    pub audiences: Vec<String>,

    /// Interval (in seconds) for JWKS refresh when jwks_url is set.
    #[config(env = "OAUTH_JWKS_REFRESH_SECS", default = 300)]
    pub jwks_refresh_interval_secs: u64,

    #[config(nested)]
    pub claims: OAuthClaimsConfig,

    #[config(nested)]
    pub admin: OAuthAdminConfig,
}

#[derive(Clone, Config)]
pub(crate) struct OAuthClaimsConfig {
    /// Claim name used as the subject identifier.
    #[config(env = "OAUTH_SUBJECT_CLAIM", default = "sub")]
    pub subject: String,

    /// Claim containing group or role memberships.
    #[config(env = "OAUTH_GROUPS_CLAIM", default = "groups")]
    pub groups: String,
}

#[derive(Clone, Config)]
pub(crate) struct OAuthAdminConfig {
    /// Group/role value required for admin access. Set to an empty string to disable enforcement.
    #[config(env = "OAUTH_ADMIN_GROUP", default = "admin")]
    pub group: String,

    /// Treat admin group comparisons as case-sensitive.
    #[config(env = "OAUTH_ADMIN_CASE_SENSITIVE", default = false)]
    pub group_case_sensitive: bool,
}
