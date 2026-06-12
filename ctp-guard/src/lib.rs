//! # ctp-guard
//!
//! CTP Layer 2: the guard process. A separate OS binary, reachable only via
//! a Unix domain socket, with no network access (enforced by its systemd
//! unit). It holds classification power and ZERO execution power: its only
//! output channel is a GBNF-constrained verdict, re-validated by a strict
//! fail-closed parser before it leaves the process.

pub mod grammar;
pub mod inference;
pub mod parse;
pub mod server;

/// Generated gRPC bindings for `proto/guard.proto`.
#[allow(unused, clippy::all, clippy::pedantic, unsafe_code)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/ctp.guard.v1.rs"));
}

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use ctp_core::{CtpConfig, CtpError, GuardBackendKind};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

pub use inference::{InferenceBackend, MockBackend, build_prompt};
pub use parse::{ParseError, StrictVerdict, parse_strict};
pub use server::GuardServer;

use crate::proto::guard_service_server::GuardServiceServer;

/// Build the configured inference backend. The backend choice is explicit
/// in config (no default); selecting `llama` without the build feature is a
/// configuration error, not a silent fallback.
fn build_backend(config: &CtpConfig) -> Result<Arc<dyn InferenceBackend>, CtpError> {
    match config.guard.backend {
        GuardBackendKind::Mock => {
            tracing::warn!(
                "GUARD RUNNING WITH MOCK BACKEND — no real classification is performed. \
                 For testing only; never deploy this to production."
            );
            Ok(Arc::new(MockBackend))
        }
        GuardBackendKind::Llama => build_llama_backend(config),
    }
}

#[cfg(feature = "llama")]
fn build_llama_backend(config: &CtpConfig) -> Result<Arc<dyn InferenceBackend>, CtpError> {
    let model_path =
        config.guard.model_path.as_ref().ok_or_else(|| {
            CtpError::Config("guard.model_path required for llama backend".into())
        })?;
    let model_id = format!(
        "{}/{}",
        model_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("model"),
        config.guard.prompt_version
    );
    let backend = inference::LlamaBackend::load(
        model_path,
        crate::grammar::VERDICT_GBNF.to_string(),
        model_id,
    )
    .map_err(|e| CtpError::Config(format!("llama backend: {e}")))?;
    Ok(Arc::new(backend))
}

#[cfg(not(feature = "llama"))]
fn build_llama_backend(_config: &CtpConfig) -> Result<Arc<dyn InferenceBackend>, CtpError> {
    Err(CtpError::Config(
        "guard.backend = \"llama\" requires building ctp-guard with --features llama".into(),
    ))
}

/// Bind the guard's Unix socket, lock its permissions to the owner, and
/// serve until a shutdown signal arrives.
pub async fn serve(config: &CtpConfig) -> Result<(), CtpError> {
    let system_prompt =
        inference::system_prompt(&config.guard.prompt_version).ok_or_else(|| {
            CtpError::Config(format!(
                "unknown guard.prompt_version '{}'",
                config.guard.prompt_version
            ))
        })?;

    let backend = build_backend(config)?;
    let server = GuardServer::new(
        backend.clone(),
        Arc::from(system_prompt),
        config.guard.max_window_bytes,
    );

    let socket_path = &config.guard.socket_path;
    prepare_socket_path(socket_path)?;
    let listener = UnixListener::bind(socket_path)?;
    // SECURITY: lock the socket to the owner (0600). Only the orchestrator,
    // running as the same user, may dial the guard — no other local user can
    // reach Layer 2 to probe it or feed it crafted requests.
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    tracing::info!(
        socket = %socket_path.display(),
        model = backend.model_id(),
        "ctp-guard listening on unix socket"
    );

    // Signal readiness and arm the systemd watchdog. Both are no-ops outside
    // systemd (NOTIFY_SOCKET / WATCHDOG_USEC unset). The watchdog is a coarse
    // process-liveness check: a fully wedged runtime stops pinging and systemd
    // SIGKILLs + restarts it. It is NOT a per-request cancel — a single hung
    // classify is the client's authoritative timeout's job; a native inference
    // call cannot be cancelled mid-flight, so "restart the wedged process" is
    // the best-effort guard-side cancel.
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    spawn_watchdog();

    let incoming = UnixListenerStream::new(listener);
    let result = Server::builder()
        .add_service(GuardServiceServer::new(server))
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await;

    // Best-effort cleanup so a restart can re-bind the path.
    let _ = std::fs::remove_file(socket_path);
    result.map_err(|e| CtpError::Config(format!("guard server: {e}")))
}

/// If systemd set a watchdog interval, ping it at half that period. No-op
/// when `WATCHDOG_USEC` is unset (not under systemd, or no `WatchdogSec=`).
fn spawn_watchdog() {
    if let Some(timeout) = sd_notify::watchdog_enabled() {
        let period = timeout / 2;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            loop {
                tick.tick().await;
                let _ = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]);
            }
        });
    }
}

fn prepare_socket_path(path: &Path) -> Result<(), CtpError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    // Remove a stale socket from a previous run.
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return,
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("shutdown signal received; draining");
}
