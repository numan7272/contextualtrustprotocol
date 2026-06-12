//! Verdict, finding and audit-report types shared by every CTP layer.
//!
//! The decision vocabulary is deliberately binary: [`Verdict::Pass`] or
//! [`Verdict::Block`]. Anything richer (confidence scores, probabilities)
//! is telemetry and lives outside the decision path.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::payload::{Direction, PayloadId};

/// Severity of a finding. Ordered: `Info < Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// Outcome of a single challenge rule.
///
/// `Flag` passes the payload but annotates it; flags are forwarded to the
/// guard as additive context and feed the kernel's multi-turn anomaly ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum RuleResult {
    Pass,
    Block { reason: String, severity: Severity },
    Flag { reason: String },
}

/// The binary decision vocabulary of CTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Block,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verdict::Pass => "PASS",
            Verdict::Block => "BLOCK",
        })
    }
}

/// The CTP layer a finding or decision originates from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Challenge,
    Guard,
    Kernel,
    Orchestrator,
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Layer::Challenge => "challenge",
            Layer::Guard => "guard",
            Layer::Kernel => "kernel",
            Layer::Orchestrator => "orchestrator",
        })
    }
}

/// Whether a finding blocks on its own or merely annotates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingDisposition {
    Blocking,
    Advisory,
}

/// A single observation made by a rule, the guard, or the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Machine-readable origin, e.g. a rule name or `"guard"`.
    pub source: String,
    /// Human-readable explanation for audit logs. Policy: must not embed
    /// raw payload bytes or raw model output.
    pub reason: String,
    pub severity: Severity,
    pub disposition: FindingDisposition,
}

impl Finding {
    pub fn blocking(
        source: impl Into<String>,
        reason: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Finding {
            source: source.into(),
            reason: reason.into(),
            severity,
            disposition: FindingDisposition::Blocking,
        }
    }

    pub fn advisory(
        source: impl Into<String>,
        reason: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Finding {
            source: source.into(),
            reason: reason.into(),
            severity,
            disposition: FindingDisposition::Advisory,
        }
    }
}

/// The result of running one verification layer over one payload.
///
/// The verdict is *derived* — `new()` computes it from the findings (any
/// blocking finding ⇒ [`Verdict::Block`]). A report whose verdict
/// contradicts its findings cannot be constructed.
///
/// Reports bind to a specific payload via [`PayloadId`]; the typestate
/// promotion in [`crate::payload`] rejects reports for other payloads.
#[derive(Debug, Clone, Serialize)]
pub struct LayerReport {
    payload_id: PayloadId,
    layer: Layer,
    session_id: Uuid,
    verdict: Verdict,
    findings: Vec<Finding>,
    elapsed: Duration,
}

impl LayerReport {
    /// Construct a report from findings. Crate-private on purpose: the only
    /// public paths to a `LayerReport` are [`crate::Payload::challenge`] and
    /// [`crate::Payload::guard`], which run a real scanner first. This keeps
    /// `LayerReport` from being fabricated to forge a passing verdict.
    pub(crate) fn new(
        payload_id: PayloadId,
        layer: Layer,
        session_id: Uuid,
        findings: Vec<Finding>,
        elapsed: Duration,
    ) -> Self {
        let verdict = if findings
            .iter()
            .any(|f| f.disposition == FindingDisposition::Blocking)
        {
            Verdict::Block
        } else {
            Verdict::Pass
        };
        LayerReport {
            payload_id,
            layer,
            session_id,
            verdict,
            findings,
            elapsed,
        }
    }

    pub fn payload_id(&self) -> PayloadId {
        self.payload_id
    }

    pub fn layer(&self) -> Layer {
        self.layer
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Advisory findings only — the anomaly flags forwarded to the guard
    /// and into the kernel's session ledger.
    pub fn advisory_flags(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.disposition == FindingDisposition::Advisory)
    }

    pub fn into_decision(self, direction: Direction) -> Decision {
        Decision {
            verdict: self.verdict,
            layer: self.layer,
            findings: self.findings,
            session_id: self.session_id,
            direction,
            elapsed: self.elapsed,
        }
    }
}

/// The terminal, audit-ready outcome of a pipeline run.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub verdict: Verdict,
    /// The layer that decided (for blocks: the layer that fired).
    pub layer: Layer,
    pub findings: Vec<Finding>,
    pub session_id: Uuid,
    pub direction: Direction,
    pub elapsed: Duration,
}

impl Decision {
    pub fn block(
        layer: Layer,
        findings: Vec<Finding>,
        session_id: Uuid,
        direction: Direction,
        elapsed: Duration,
    ) -> Self {
        Decision {
            verdict: Verdict::Block,
            layer,
            findings,
            session_id,
            direction,
            elapsed,
        }
    }

    pub fn pass(
        layer: Layer,
        findings: Vec<Finding>,
        session_id: Uuid,
        direction: Direction,
        elapsed: Duration,
    ) -> Self {
        Decision {
            verdict: Verdict::Pass,
            layer,
            findings,
            session_id,
            direction,
            elapsed,
        }
    }

    pub fn is_block(&self) -> bool {
        self.verdict == Verdict::Block
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::payload::{Direction, Payload};

    #[test]
    fn report_verdict_derived_from_findings() {
        let p = Payload::new(b"data".to_vec(), Direction::Inbound);
        let sid = Uuid::new_v4();

        let pass = LayerReport::new(p.id(), Layer::Challenge, sid, vec![], Duration::ZERO);
        assert_eq!(pass.verdict(), Verdict::Pass);

        let advisory_only = LayerReport::new(
            p.id(),
            Layer::Challenge,
            sid,
            vec![Finding::advisory("rule_a", "odd but legal", Severity::Low)],
            Duration::ZERO,
        );
        assert_eq!(advisory_only.verdict(), Verdict::Pass);
        assert_eq!(advisory_only.advisory_flags().count(), 1);

        let blocked = LayerReport::new(
            p.id(),
            Layer::Challenge,
            sid,
            vec![
                Finding::advisory("rule_a", "odd but legal", Severity::Low),
                Finding::blocking("rule_b", "injection pattern", Severity::High),
            ],
            Duration::ZERO,
        );
        assert_eq!(blocked.verdict(), Verdict::Block);
    }

    #[test]
    fn decision_serializes_with_uppercase_verdict() {
        let p = Payload::new(b"data".to_vec(), Direction::Outbound);
        let report = LayerReport::new(
            p.id(),
            Layer::Guard,
            Uuid::new_v4(),
            vec![Finding::blocking("guard", "intent_shift", Severity::High)],
            Duration::from_millis(12),
        );
        let decision = report.into_decision(Direction::Outbound);
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["verdict"], "BLOCK");
        assert_eq!(json["layer"], "guard");
        assert_eq!(json["direction"], "outbound");
    }
}
