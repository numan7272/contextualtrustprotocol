//! ctp-guard binary entry point. Loads config, initializes structured
//! logging, and runs the Unix-socket guard server.

use std::path::PathBuf;
use std::process::ExitCode;

use ctp_core::CtpConfig;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ctp.toml"));

    let config = match CtpConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, path = %config_path.display(), "failed to load config");
            return ExitCode::FAILURE;
        }
    };

    match ctp_guard::serve(&config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "guard server terminated with error");
            ExitCode::FAILURE
        }
    }
}
