//! Pipeline composition: the single async entry point that runs a payload
//! through challenge (L1) → guard (L2) → anomaly ledger and returns an
//! audit-ready [`Decision`]. Per-layer latency is recorded on every path —
//! including blocks — so the benchmark sees where time goes.
//!
//! `evaluate` never returns an error: every failure (block, guard timeout,
//! transport loss, config) is converted to a BLOCK [`Decision`] via
//! [`CtpError::to_block_decision`], fail-closed by construction.

use std::sync::Arc;
use std::time::Instant;

use ctp_core::{
    ChallengeScanner, CtpError, Decision, Direction, Finding, Layer, Payload, Severity,
};
use ctp_kernel::{AnomalyLedger, GuardFanout};
use uuid::Uuid;

use crate::metrics;

pub struct Orchestrator {
    challenge: Arc<dyn ChallengeScanner>,
    guard: Arc<GuardFanout>,
    ledger: Arc<AnomalyLedger>,
    active_rules: usize,
}

impl Orchestrator {
    pub fn new(
        challenge: Arc<dyn ChallengeScanner>,
        guard: Arc<GuardFanout>,
        ledger: Arc<AnomalyLedger>,
        active_rules: usize,
    ) -> Self {
        Orchestrator {
            challenge,
            guard,
            ledger,
            active_rules,
        }
    }

    pub fn active_rules(&self) -> usize {
        self.active_rules
    }

    /// Run one payload through the full pipeline. Always returns a Decision.
    #[tracing::instrument(skip(self, payload), fields(direction = %direction, session = %session_id, bytes = payload.len()))]
    pub async fn evaluate(
        &self,
        payload: Vec<u8>,
        direction: Direction,
        tool_name: Option<String>,
        session_id: Uuid,
    ) -> Decision {
        let _ = tool_name; // reserved for per-tool policy in embedded mode
        let start = Instant::now();
        let payload = Payload::new(payload, direction);

        // --- Layer 1: challenge --------------------------------------------
        let challenge_start = Instant::now();
        let challenge_result = payload.challenge(self.challenge.as_ref(), session_id);
        metrics::record_layer_latency("challenge", challenge_start.elapsed());
        let (challenged, challenge_report) = match challenge_result {
            Ok(pair) => pair,
            Err(err) => return self.finish_block(err, session_id, direction, start),
        };
        let mut advisory = challenge_report.advisory_flags().count();
        let mut findings: Vec<Finding> = challenge_report.findings().to_vec();
        tracing::debug!(layer = "challenge", verdict = "pass", advisory);

        // --- Layer 2: guard (windowed, parallel, time-bounded) -------------
        let guard_start = Instant::now();
        let guard_result = challenged.guard(self.guard.as_ref(), session_id).await;
        metrics::record_layer_latency("guard", guard_start.elapsed());
        let (_vetted, guard_report) = match guard_result {
            Ok(pair) => pair,
            Err(err) => return self.finish_block(err, session_id, direction, start),
        };
        advisory += guard_report.advisory_flags().count();
        findings.extend(guard_report.findings().iter().cloned());
        tracing::debug!(layer = "guard", verdict = "pass", advisory);

        // --- Kernel: multi-turn anomaly ledger -----------------------------
        let kernel_start = Instant::now();
        let outcome = self.ledger.record(session_id, advisory);
        metrics::record_layer_latency("kernel", kernel_start.elapsed());
        if outcome.blocked {
            let decision = Decision::block(
                Layer::Kernel,
                vec![Finding::blocking(
                    "anomaly_threshold",
                    format!(
                        "cumulative session anomaly score {:.2} crossed the threshold",
                        outcome.score
                    ),
                    Severity::High,
                )],
                session_id,
                direction,
                start.elapsed(),
            );
            tracing::info!(
                verdict = "block",
                layer = "kernel",
                reason = "anomaly_threshold"
            );
            metrics::record_decision(direction, decision.verdict);
            metrics::record_pipeline_latency(start.elapsed());
            return decision;
        }

        let decision = Decision::pass(
            Layer::Orchestrator,
            findings,
            session_id,
            direction,
            start.elapsed(),
        );
        metrics::record_decision(direction, decision.verdict);
        metrics::record_pipeline_latency(start.elapsed());
        decision
    }

    /// Convert any pipeline error into an audit-ready BLOCK decision and
    /// record the block metrics. The error's Display is structural (the
    /// guard client already kept raw guard output out of it).
    fn finish_block(
        &self,
        err: CtpError,
        session_id: Uuid,
        direction: Direction,
        start: Instant,
    ) -> Decision {
        // SECURITY: `evaluate` never returns Result — every failure funnels
        // here and becomes a BLOCK Decision. A caller cannot accidentally treat
        // a pipeline error as "no decision" and proceed; the only outcomes are
        // PASS and BLOCK, and errors are BLOCK.
        let decision = err.to_block_decision(session_id, direction);
        tracing::info!(
            verdict = "block",
            layer = %decision.layer,
            security_block = err.is_security_block(),
            "pipeline blocked"
        );
        metrics::record_decision(direction, decision.verdict);
        metrics::record_pipeline_latency(start.elapsed());
        decision
    }
}
