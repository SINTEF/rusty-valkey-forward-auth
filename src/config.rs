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

    /// Redis server URL.
    #[config(env = "REDIS_URL", default = "redis://127.0.0.1:6379")]
    pub redis_url: String,

    /// Redis username
    #[config(env = "REDIS_USERNAME")]
    pub redis_username: Option<String>,

    /// Redis password
    #[config(env = "REDIS_PASSWORD")]
    pub redis_password: Option<String>,

    /// Blake3 hashing key (32 bytes hex-encoded, 64 characters). Used to salt token hashes.
    /// IMPORTANT: Keep this secret and consistent across deployments.
    #[config(
        env = "BLAKE3_KEY",
        default = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub blake3_key: String,
}

impl RVFAConfig {
    pub fn load() -> Result<Self, Error> {
        let file = std::env::var("CONFIG_FILE").unwrap_or("settings.toml".to_string());
        Ok(RVFAConfig::builder().env().file(file).load()?)
    }

    pub fn blake3_key_bytes(&self) -> Result<[u8; 32], Error> {
        let decoded = hex::decode(&self.blake3_key)?;
        if decoded.len() != 32 {
            anyhow::bail!(
                "BLAKE3_KEY must be exactly 32 bytes (64 hex characters), got {} bytes",
                decoded.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }
}
