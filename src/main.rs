#![forbid(unsafe_code)]
use anyhow::{Context, Result};
use fred::prelude::{ClientLike, EventInterface};
mod config;
mod http;
mod storage;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .with_target(false)
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to create Tokio runtime")?;

    let config = config::RVFAConfig::load().context("Failed to load configuration")?;

    runtime.block_on(async_main(config))
}

async fn async_main(config: config::RVFAConfig) -> Result<()> {
    let valkey_client = storage::client_from_config(&config)
        .await
        .context("Failed to create Valkey client")?;

    valkey_client
        .init()
        .await
        .context("Failed to initialize Valkey client")?;
    valkey_client.connect();
    valkey_client
        .wait_for_connect()
        .await
        .context("Failed to connect to Valkey")?;

    valkey_client.on_error(|(error, server)| async move {
        eprintln!("{:?}: Valkey client error: {:?}", server, error);
        Ok(())
    });

    http::serve(&config, valkey_client)
        .await
        .context("HTTP server failed")?;

    Ok(())
}
