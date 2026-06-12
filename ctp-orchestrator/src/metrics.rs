//! Prometheus metrics — the only evidence later available for the post-Step-8
//! benchmark, so they are recorded PER LAYER, not just in aggregate.
//!
//! * `ctp_layer_latency_seconds{layer}` — histogram per layer
//!   (`challenge`, `guard`, `kernel`). A single total would hide which layer
//!   costs what; the benchmark needs the breakdown.
//! * `ctp_pipeline_latency_seconds` — end-to-end histogram.
//! * `ctp_decisions_total{direction,verdict}` — counter; block rate is
//!   `block / (block + pass)`, sliceable by direction.
//! * `ctp_guard_timeouts_total`, `ctp_guard_unavailable_total`,
//!   `ctp_guard_contract_violations_total` — counters for the guard failure
//!   modes, each of which fails closed to BLOCK.
//!
//! These call the global `metrics` facade. Without an installed recorder
//! (e.g. in unit tests) every call is a no-op, so the pipeline records
//! unconditionally and the binary installs the Prometheus recorder once.

use std::net::SocketAddr;
use std::time::Duration;

use ctp_core::{CtpError, Direction, Verdict};
use metrics_exporter_prometheus::PrometheusBuilder;

pub const LAYER_LATENCY: &str = "ctp_layer_latency_seconds";
pub const PIPELINE_LATENCY: &str = "ctp_pipeline_latency_seconds";
pub const DECISIONS: &str = "ctp_decisions_total";
pub const GUARD_TIMEOUTS: &str = "ctp_guard_timeouts_total";
pub const GUARD_UNAVAILABLE: &str = "ctp_guard_unavailable_total";
pub const GUARD_CONTRACT_VIOLATIONS: &str = "ctp_guard_contract_violations_total";

/// Install the Prometheus recorder and its HTTP scrape listener. Call once,
/// inside the tokio runtime. Idempotency is the caller's concern.
pub fn install(listen: SocketAddr) -> Result<(), CtpError> {
    PrometheusBuilder::new()
        .with_http_listener(listen)
        .install()
        .map_err(|e| CtpError::Config(format!("metrics exporter: {e}")))?;
    describe();
    Ok(())
}

fn describe() {
    metrics::describe_histogram!(
        LAYER_LATENCY,
        metrics::Unit::Seconds,
        "Per-layer verification latency"
    );
    metrics::describe_histogram!(
        PIPELINE_LATENCY,
        metrics::Unit::Seconds,
        "End-to-end pipeline latency"
    );
    metrics::describe_counter!(DECISIONS, "Pipeline decisions by direction and verdict");
    metrics::describe_counter!(GUARD_TIMEOUTS, "Guard classify calls that timed out");
    metrics::describe_counter!(
        GUARD_UNAVAILABLE,
        "Guard classify calls that failed transport"
    );
    metrics::describe_counter!(
        GUARD_CONTRACT_VIOLATIONS,
        "Guard responses that violated the verdict contract"
    );
}

pub fn dir_label(direction: Direction) -> &'static str {
    match direction {
        Direction::Inbound => "inbound",
        Direction::Outbound => "outbound",
    }
}

pub fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Pass => "pass",
        Verdict::Block => "block",
    }
}

pub fn record_layer_latency(layer: &'static str, elapsed: Duration) {
    metrics::histogram!(LAYER_LATENCY, "layer" => layer).record(elapsed.as_secs_f64());
}

pub fn record_pipeline_latency(elapsed: Duration) {
    metrics::histogram!(PIPELINE_LATENCY).record(elapsed.as_secs_f64());
}

pub fn record_decision(direction: Direction, verdict: Verdict) {
    metrics::counter!(DECISIONS, "direction" => dir_label(direction), "verdict" => verdict_label(verdict))
        .increment(1);
}

pub fn record_guard_timeout() {
    metrics::counter!(GUARD_TIMEOUTS).increment(1);
}

pub fn record_guard_unavailable() {
    metrics::counter!(GUARD_UNAVAILABLE).increment(1);
}

pub fn record_guard_contract_violation() {
    metrics::counter!(GUARD_CONTRACT_VIOLATIONS).increment(1);
}
