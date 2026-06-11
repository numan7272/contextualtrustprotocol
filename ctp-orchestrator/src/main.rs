//! # ctp-orchestrator
//!
//! CTP Layer 4: the system gateway. Single async entry point composing all
//! layers: challenge (L1) → guard proxy (L2) → kernel wrapper (L3), exposed
//! as a tonic gRPC endpoint with Prometheus metrics and structured tracing
//! at every layer boundary.

mod grpc;
mod guard_client;
mod metrics;
mod pipeline;

/// Generated gRPC bindings for `proto/guard.proto`.
#[allow(unused, clippy::all, clippy::pedantic, unsafe_code)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/ctp.guard.v1.rs"));
}

fn main() {
    // Wired up in Step 7: config load, guard client, pipeline, gRPC server.
}
