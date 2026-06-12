//! # ctp-kernel
//!
//! CTP Layer 3: the kernel wrapper. Decorates any [`ToolExecutor`] and vets
//! BOTH directions of tool I/O:
//!
//! * **Outbound** — the tool arguments, before execution. A block here means
//!   the inner tool never runs.
//! * **Inbound** — the tool result, before it flows back into model context.
//!   A block here means the poisoned result is never returned, even though
//!   the tool already executed. This inbound direction is CTP's reason to
//!   exist: it is the recursive context-poisoning vector.
//!
//! Each direction runs the full pipeline — Layer 1 ([`ChallengeScanner`])
//! then Layer 2 ([`GuardScanner`]) — and is fail-closed: any block, guard
//! timeout, or transport failure aborts with [`CtpError`] and releases
//! nothing. Tool access is deny-by-default. Across turns, an
//! [`AnomalyLedger`] accumulates advisory flags so a slow-burn attack that
//! never trips a single turn is still blocked.

pub mod ledger;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ctp_core::{
    ChallengeScanner, CtpError, Decision, Direction, Finding, GuardCheck, GuardRequest,
    GuardScanner, KernelConfig, Layer, Payload, Severity, ToolContext, ToolExecutor, ToolOutput,
    Verdict,
};
use tokio::task::JoinSet;
use uuid::Uuid;

pub use ledger::{AnomalyLedger, LedgerOutcome, LedgerParams};

/// Layer 2 fan-out: splits a payload into overlapping windows and classifies
/// them through [`GuardCheck`] in parallel, with a client-authoritative
/// per-window timeout. Implements [`GuardScanner`] so it plugs into
/// `Payload::guard`.
pub struct GuardFanout {
    guard: Arc<dyn GuardCheck>,
    max_window_bytes: usize,
    overlap: usize,
    timeout: Duration,
}

impl GuardFanout {
    pub fn new(
        guard: Arc<dyn GuardCheck>,
        max_window_bytes: usize,
        overlap: usize,
        timeout: Duration,
    ) -> Self {
        GuardFanout {
            guard,
            max_window_bytes: max_window_bytes.max(1),
            overlap,
            timeout,
        }
    }

    /// Split into overlapping windows. The overlap ensures a phrase straddling
    /// a boundary is still seen whole by at least one window.
    fn windows(&self, payload: &[u8]) -> Vec<Vec<u8>> {
        if payload.len() <= self.max_window_bytes {
            return vec![payload.to_vec()];
        }
        let step = self.max_window_bytes.saturating_sub(self.overlap).max(1);
        let mut out = Vec::new();
        let mut start = 0;
        while start < payload.len() {
            let end = (start + self.max_window_bytes).min(payload.len());
            out.push(payload[start..end].to_vec());
            if end == payload.len() {
                break;
            }
            start += step;
        }
        out
    }
}

#[async_trait]
impl GuardScanner for GuardFanout {
    async fn guard_findings(
        &self,
        payload: &[u8],
        direction: Direction,
        session_id: Uuid,
    ) -> Result<Vec<Finding>, CtpError> {
        let windows = self.windows(payload);
        let window_count = windows.len() as u32;

        // Fan out. Each window carries its own client-authoritative timeout:
        // a hung guard yields a timeout error for that window, never a hang.
        let mut set: JoinSet<Result<ctp_core::GuardVerdict, CtpError>> = JoinSet::new();
        for (idx, window) in windows.into_iter().enumerate() {
            let guard = self.guard.clone();
            let timeout = self.timeout;
            let request = GuardRequest {
                window,
                window_index: idx as u32,
                window_count,
                direction,
                tool_name: None,
                anomaly_flags: Vec::new(),
                session_id,
            };
            set.spawn(async move {
                match tokio::time::timeout(timeout, guard.classify(request)).await {
                    Ok(result) => result,
                    Err(_elapsed) => Err(CtpError::GuardTimeout {
                        budget_ms: timeout.as_millis() as u64,
                    }),
                }
            });
        }

        // Drain ALL windows before deciding. ANY-BLOCK → BLOCK holds
        // regardless of completion order: a blocking finding from any window
        // makes the aggregate report a Block. Waiting for every window (not
        // racing the first result) is what makes the outcome race-free.
        let mut findings = Vec::new();
        while let Some(joined) = set.join_next().await {
            let result = match joined {
                Ok(result) => result,
                // A panicked guard task is treated as guard-unavailable: block.
                Err(_join_err) => Err(CtpError::GuardUnavailable("guard task panicked".into())),
            };
            match result {
                Ok(verdict) if verdict.verdict == Verdict::Block => {
                    findings.push(Finding::blocking(
                        "guard",
                        format!("window blocked [{}]", verdict.flags.join(",")),
                        Severity::High,
                    ));
                }
                Ok(verdict) => {
                    for flag in verdict.flags {
                        findings.push(Finding::advisory("guard", flag, Severity::Low));
                    }
                }
                Err(err) => {
                    let (source, severity) = match &err {
                        CtpError::GuardTimeout { .. } => ("guard_timeout", Severity::High),
                        CtpError::GuardContractViolation(_) => {
                            ("guard_contract_violation", Severity::Critical)
                        }
                        _ => ("guard_unavailable", Severity::High),
                    };
                    findings.push(Finding::blocking(source, err.to_string(), severity));
                }
            }
        }
        Ok(findings)
    }
}

/// The kernel wrapper. Wraps an inner [`ToolExecutor`] and vets both
/// directions of every tool call through Layer 1 and Layer 2.
pub struct KernelWrapper<T: ToolExecutor> {
    inner: T,
    challenge: Arc<dyn ChallengeScanner>,
    guard: Arc<GuardFanout>,
    ledger: Arc<AnomalyLedger>,
    config: KernelConfig,
}

impl<T: ToolExecutor> KernelWrapper<T> {
    pub fn new(
        inner: T,
        challenge: Arc<dyn ChallengeScanner>,
        guard: Arc<GuardFanout>,
        config: KernelConfig,
    ) -> Self {
        let ledger = Arc::new(AnomalyLedger::from_config(&config));
        KernelWrapper {
            inner,
            challenge,
            guard,
            ledger,
            config,
        }
    }

    /// Shared handle to the anomaly ledger (e.g. for metrics or tests).
    pub fn ledger(&self) -> Arc<AnomalyLedger> {
        self.ledger.clone()
    }

    /// Run one direction's full pipeline. Returns the vetted bytes and the
    /// number of advisory flags raised, or a fail-closed error.
    async fn vet(
        &self,
        bytes: Vec<u8>,
        direction: Direction,
        session_id: Uuid,
    ) -> Result<(Vec<u8>, usize), CtpError> {
        let payload = Payload::new(bytes, direction);
        let (challenged, challenge_report) =
            payload.challenge(self.challenge.as_ref(), session_id)?;
        let mut advisory = challenge_report.advisory_flags().count();
        let (vetted, guard_report) = challenged.guard(self.guard.as_ref(), session_id).await?;
        advisory += guard_report.advisory_flags().count();
        Ok((vetted.release(), advisory))
    }

    fn kernel_block(&self, source: &str, reason: String, session_id: Uuid) -> CtpError {
        CtpError::Blocked(Box::new(Decision::block(
            Layer::Kernel,
            vec![Finding::blocking(source, reason, Severity::High)],
            session_id,
            Direction::Inbound,
            Duration::ZERO,
        )))
    }
}

#[async_trait]
impl<T: ToolExecutor> ToolExecutor for KernelWrapper<T> {
    async fn execute(&self, ctx: ToolContext) -> Result<ToolOutput, CtpError> {
        let ToolContext {
            session_id,
            tool_name,
            arguments,
            turn,
        } = ctx;

        // Deny-by-default: a tool absent from the allowlist, or present
        // without `enabled = true`, never runs.
        let policy = self.config.tool_policy(&tool_name);
        if !policy.enabled {
            return Err(CtpError::PolicyDenied {
                tool: tool_name,
                reason: "tool not enabled (deny-by-default)".into(),
            });
        }

        let mut advisory_total = 0usize;

        // 1. OUTBOUND: vet arguments BEFORE execution. A block here returns
        //    before the inner tool is ever touched.
        let (vetted_args, outbound_advisory) =
            self.vet(arguments, Direction::Outbound, session_id).await?;
        advisory_total += outbound_advisory;

        // 2. Execute the inner tool with the vetted arguments.
        let exec_ctx = ToolContext {
            session_id,
            tool_name: tool_name.clone(),
            arguments: vetted_args,
            turn,
        };
        let result = self.inner.execute(exec_ctx).await?;

        // 3. Oversize result is blocked before vetting and before it can
        //    return to context.
        if result.content.len() > policy.max_result_bytes {
            return Err(self.kernel_block(
                "oversize_result",
                format!(
                    "tool '{tool_name}' result of {} bytes exceeds cap of {}",
                    result.content.len(),
                    policy.max_result_bytes
                ),
                session_id,
            ));
        }

        // 4. INBOUND: vet the tool RESULT before it flows back into context.
        //    A block here discards the poisoned result — the tool ran, but
        //    its output never reaches the model. This is the core guarantee.
        let (vetted_result, inbound_advisory) = self
            .vet(result.content, Direction::Inbound, session_id)
            .await?;
        advisory_total += inbound_advisory;

        // 5. Multi-turn accumulation: even when every layer passed this turn,
        //    a session whose cumulative anomaly score crosses the threshold
        //    is blocked.
        let outcome = self.ledger.record(session_id, advisory_total);
        if outcome.blocked {
            return Err(self.kernel_block(
                "anomaly_threshold",
                format!(
                    "cumulative session anomaly score {:.2} >= threshold",
                    outcome.score
                ),
                session_id,
            ));
        }

        Ok(ToolOutput {
            content: vetted_result,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ctp_core::{FindingDisposition, GuardVerdict};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct PassChallenge;
    impl ChallengeScanner for PassChallenge {
        fn challenge_findings(&self, _payload: &[u8]) -> Vec<Finding> {
            Vec::new()
        }
    }

    /// Guard that blocks any window containing `marker`, optionally after a
    /// delay so the blocking window can be made the slowest to return.
    struct MarkerGuard {
        marker: &'static [u8],
        block_delay: Duration,
    }
    #[async_trait]
    impl GuardCheck for MarkerGuard {
        async fn classify(&self, request: GuardRequest) -> Result<GuardVerdict, CtpError> {
            let hit = request
                .window
                .windows(self.marker.len())
                .any(|w| w == self.marker);
            if hit {
                tokio::time::sleep(self.block_delay).await;
                Ok(GuardVerdict {
                    verdict: Verdict::Block,
                    confidence_telemetry: 0.9,
                    flags: vec!["intent_shift".into()],
                    model_id: "marker".into(),
                    inference: Duration::ZERO,
                })
            } else {
                Ok(GuardVerdict {
                    verdict: Verdict::Pass,
                    confidence_telemetry: 0.1,
                    flags: vec![],
                    model_id: "marker".into(),
                    inference: Duration::ZERO,
                })
            }
        }
    }

    struct HangingGuard;
    #[async_trait]
    impl GuardCheck for HangingGuard {
        async fn classify(&self, _request: GuardRequest) -> Result<GuardVerdict, CtpError> {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            unreachable!("guard should be cancelled by the client timeout")
        }
    }

    fn blocking_count(findings: &[Finding]) -> usize {
        findings
            .iter()
            .filter(|f| f.disposition == FindingDisposition::Blocking)
            .count()
    }

    /// Auflage 3: with overlapping parallel windows where exactly one blocks
    /// — and that window is made the slowest to return — the aggregate is
    /// still BLOCK. The overlap (>= marker length) guarantees one window
    /// sees the marker whole.
    #[tokio::test]
    async fn fanout_blocks_even_when_blocking_window_returns_last() {
        let guard = Arc::new(MarkerGuard {
            marker: b"BLOCKME",
            block_delay: Duration::from_millis(80),
        });
        let fanout = GuardFanout::new(guard, 16, 8, Duration::from_secs(5));
        let mut payload = vec![b'a'; 50];
        payload.extend_from_slice(b"BLOCKME");
        assert!(
            payload.len() > 16,
            "payload must split into several windows"
        );

        let findings = fanout
            .guard_findings(&payload, Direction::Inbound, Uuid::new_v4())
            .await
            .unwrap();
        assert!(
            blocking_count(&findings) >= 1,
            "one blocking window must block the aggregate, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn fanout_all_windows_pass_is_clean() {
        let guard = Arc::new(MarkerGuard {
            marker: b"BLOCKME",
            block_delay: Duration::ZERO,
        });
        let fanout = GuardFanout::new(guard, 16, 8, Duration::from_secs(5));
        let findings = fanout
            .guard_findings(
                b"a wholly benign tool result with nothing to see",
                Direction::Inbound,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert_eq!(blocking_count(&findings), 0);
    }

    /// Auflage 4: a hung guard becomes a BLOCK via the client-authoritative
    /// timeout, fast — not a hang that lets execution through.
    #[tokio::test]
    async fn hung_guard_times_out_to_block_fast() {
        let start = std::time::Instant::now();
        let fanout = GuardFanout::new(Arc::new(HangingGuard), 2048, 256, Duration::from_millis(50));
        let findings = fanout
            .guard_findings(b"anything", Direction::Outbound, Uuid::new_v4())
            .await
            .unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "must resolve via timeout, not hang"
        );
        assert_eq!(blocking_count(&findings), 1);
        assert_eq!(findings[0].source, "guard_timeout");
    }

    struct CountingTool {
        calls: Arc<AtomicUsize>,
        output: Vec<u8>,
    }
    #[async_trait]
    impl ToolExecutor for CountingTool {
        async fn execute(&self, _ctx: ToolContext) -> Result<ToolOutput, CtpError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ToolOutput {
                content: self.output.clone(),
            })
        }
    }

    fn kernel_config(tool: &str, enabled: bool) -> KernelConfig {
        let toml = format!(
            "[challenge]\n[guard]\nbackend = \"mock\"\n[kernel]\n\
             [kernel.tools.{tool}]\nenabled = {enabled}\n[orchestrator]\n"
        );
        ctp_core::CtpConfig::from_toml_str(&toml).unwrap().kernel
    }

    fn pass_guard() -> Arc<GuardFanout> {
        Arc::new(GuardFanout::new(
            Arc::new(MarkerGuard {
                marker: b"\x00NEVER\x00",
                block_delay: Duration::ZERO,
            }),
            2048,
            256,
            Duration::from_secs(1),
        ))
    }

    #[tokio::test]
    async fn disabled_tool_is_denied_before_anything_runs() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingTool {
            calls: calls.clone(),
            output: b"ok".to_vec(),
        };
        let kernel = KernelWrapper::new(
            inner,
            Arc::new(PassChallenge),
            pass_guard(),
            kernel_config("web_fetch", false),
        );
        let ctx = ToolContext {
            session_id: Uuid::new_v4(),
            tool_name: "web_fetch".into(),
            arguments: b"{}".to_vec(),
            turn: 0,
        };
        let result = kernel.execute(ctx).await;
        assert!(matches!(result, Err(CtpError::PolicyDenied { .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "denied tool must not run");
    }
}
