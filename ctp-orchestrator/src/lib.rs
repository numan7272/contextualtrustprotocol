//! # ctp-orchestrator
//!
//! CTP Layer 4: the system gateway. Composes challenge (L1), the real guard
//! client (L2, over the Unix socket), and the anomaly ledger into a single
//! [`Orchestrator::evaluate`] entry point, exposed as a tonic gRPC service
//! with Prometheus metrics and structured tracing at every layer boundary.

pub mod grpc;
pub mod guard_client;
pub mod metrics;
pub mod pipeline;

/// Generated gRPC bindings for `proto/guard.proto` (orchestrator dials the guard).
#[allow(unused, clippy::all, clippy::pedantic, unsafe_code)]
pub mod guard_proto {
    include!(concat!(env!("OUT_DIR"), "/ctp.guard.v1.rs"));
}

/// Generated gRPC bindings for `proto/orchestrator.proto` (external surface).
#[allow(unused, clippy::all, clippy::pedantic, unsafe_code)]
pub mod orchestrator_proto {
    include!(concat!(env!("OUT_DIR"), "/ctp.orchestrator.v1.rs"));
}

use std::sync::Arc;
use std::time::Duration;

use ctp_challenge::ChallengeLayer;
use ctp_core::{ChallengeScanner, CtpConfig, CtpError};
use ctp_kernel::{AnomalyLedger, GuardFanout};
use tonic::transport::Server;

pub use grpc::GrpcGateway;
pub use guard_client::GuardClient;
pub use pipeline::Orchestrator;

use crate::orchestrator_proto::orchestrator_service_server::OrchestratorServiceServer;

/// Assemble the pipeline from config: challenge layer, a guard client dialing
/// the configured Unix socket, and the anomaly ledger. The client timeout is
/// authoritative; the fan-out carries a longer backstop timeout so the
/// client's typed timeout surfaces first.
pub fn build_orchestrator(config: &CtpConfig) -> Result<Orchestrator, CtpError> {
    let challenge_layer = ChallengeLayer::from_config(&config.challenge)?;
    let active_rules = challenge_layer.rule_names().len();
    let challenge: Arc<dyn ChallengeScanner> = Arc::new(challenge_layer);

    let client_timeout = Duration::from_millis(config.guard.timeout_ms);
    let guard_client = GuardClient::connect(config.guard.socket_path.clone(), client_timeout);
    let backstop = Duration::from_millis(config.guard.timeout_ms.saturating_mul(2).max(200));
    let fanout = Arc::new(GuardFanout::new(
        Arc::new(guard_client),
        config.guard.max_window_bytes,
        config.guard.window_overlap_bytes,
        backstop,
    ));

    let ledger = Arc::new(AnomalyLedger::from_config(&config.kernel));
    Ok(Orchestrator::new(challenge, fanout, ledger, active_rules))
}

/// Install metrics, assemble the pipeline, and serve the gRPC gateway until
/// a shutdown signal arrives.
pub async fn serve(config: &CtpConfig) -> Result<(), CtpError> {
    metrics::install(config.orchestrator.metrics_listen)?;
    tracing::info!(
        metrics = %config.orchestrator.metrics_listen,
        "prometheus exporter listening"
    );

    let orchestrator = Arc::new(build_orchestrator(config)?);
    let gateway = GrpcGateway::new(orchestrator);

    let listen = config.orchestrator.listen;
    tracing::info!(%listen, "ctp-orchestrator gRPC gateway listening");

    Server::builder()
        .add_service(OrchestratorServiceServer::new(gateway))
        .serve_with_shutdown(listen, shutdown_signal())
        .await
        .map_err(|e| CtpError::Config(format!("orchestrator server: {e}")))
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(sig) => sig,
        Err(_) => return,
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("shutdown signal received; draining");
}
