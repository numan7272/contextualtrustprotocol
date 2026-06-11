//! Typestate taint tracking for payloads.
//!
//! Every byte stream entering CTP is born [`Tainted`]. It becomes
//! [`Challenged`] only by presenting a passing Layer-1 report, and
//! [`Vetted`] only by presenting a passing Layer-2 report — each report
//! bound to this exact payload via [`PayloadId`]. Only `Vetted` payloads
//! expose [`Payload::release`], the single consuming accessor that hands
//! bytes onward to execution or model context.
//!
//! What this enforces: pipeline *order* and *completeness* are compile-time
//! invariants against engineering mistakes (skipped layers, reordered calls,
//! report/payload mix-ups under concurrency). What it does not claim:
//! protection against malicious code linked into the same process — that is
//! outside any in-process type system and is why the guard runs as a
//! separate, sandboxed OS process.
//!
//! `Payload` is deliberately not `Clone`: scanners borrow via
//! [`Payload::bytes`]; ownership moves forward through the pipeline exactly
//! once.

use std::fmt;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::CtpError;
use crate::verdict::{Layer, LayerReport, Verdict};

/// Dataflow direction relative to the model context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Data flowing toward model context (tool results, external streams).
    Inbound,
    /// Tool arguments emitted by the model, about to be executed.
    Outbound,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        })
    }
}

/// Process-unique identity of a payload; binds reports to payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct PayloadId(Uuid);

impl PayloadId {
    fn fresh() -> Self {
        PayloadId(Uuid::new_v4())
    }
}

impl fmt::Display for PayloadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Tainted {}
    impl Sealed for super::Challenged {}
    impl Sealed for super::Vetted {}
}

/// Marker trait for payload trust states. Sealed: the state machine is
/// `Tainted → Challenged → Vetted` and nothing else.
pub trait TrustState: sealed::Sealed + Send + Sync + 'static {}

/// Untrusted input, fresh from the outside world. Scannable, not releasable.
#[derive(Debug)]
pub enum Tainted {}
/// Passed Layer 1 (static heuristics). Still not releasable.
#[derive(Debug)]
pub enum Challenged {}
/// Passed Layer 2 (guard). The only state that can release bytes.
#[derive(Debug)]
pub enum Vetted {}

impl TrustState for Tainted {}
impl TrustState for Challenged {}
impl TrustState for Vetted {}

/// A byte payload tagged with its verification state.
#[derive(Debug)]
pub struct Payload<S: TrustState> {
    id: PayloadId,
    bytes: Vec<u8>,
    direction: Direction,
    _state: PhantomData<S>,
}

impl<S: TrustState> Payload<S> {
    pub fn id(&self) -> PayloadId {
        self.id
    }

    /// Borrow the bytes for scanning. Available in every state — looking
    /// at data is always allowed; releasing it is not.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Check a layer report against this payload before promotion.
    /// Mismatches are protocol violations by the embedding code and map
    /// to a blocked outcome like every other failure.
    fn validate_report(&self, report: &LayerReport, expected: Layer) -> Result<(), CtpError> {
        if report.layer() != expected {
            return Err(CtpError::TrustViolation(format!(
                "promotion requires a {expected} report, got a {} report",
                report.layer()
            )));
        }
        if report.payload_id() != self.id {
            return Err(CtpError::TrustViolation(format!(
                "report is bound to payload {}, not {}",
                report.payload_id(),
                self.id
            )));
        }
        match report.verdict() {
            Verdict::Pass => Ok(()),
            Verdict::Block => Err(CtpError::Blocked(Box::new(
                report.clone().into_decision(self.direction),
            ))),
        }
    }

    fn rebind<T: TrustState>(self) -> Payload<T> {
        Payload {
            id: self.id,
            bytes: self.bytes,
            direction: self.direction,
            _state: PhantomData,
        }
    }
}

impl Payload<Tainted> {
    /// Every payload enters the system tainted. There is no constructor
    /// for any other state.
    pub fn new(bytes: impl Into<Vec<u8>>, direction: Direction) -> Self {
        Payload {
            id: PayloadId::fresh(),
            bytes: bytes.into(),
            direction,
            _state: PhantomData,
        }
    }

    /// Promote with a passing Layer-1 report bound to this payload.
    pub fn into_challenged(self, report: &LayerReport) -> Result<Payload<Challenged>, CtpError> {
        self.validate_report(report, Layer::Challenge)?;
        Ok(self.rebind())
    }
}

impl Payload<Challenged> {
    /// Promote with a passing Layer-2 (guard) report bound to this payload.
    pub fn into_vetted(self, report: &LayerReport) -> Result<Payload<Vetted>, CtpError> {
        self.validate_report(report, Layer::Guard)?;
        Ok(self.rebind())
    }
}

impl Payload<Vetted> {
    /// Hand the bytes onward to execution or model context. This is the
    /// only consuming accessor in any state — unvetted data cannot be
    /// released by construction.
    pub fn release(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::verdict::{Finding, Severity};
    use std::time::Duration;

    fn passing(payload: &Payload<impl TrustState>, layer: Layer) -> LayerReport {
        LayerReport::new(payload.id(), layer, Uuid::new_v4(), vec![], Duration::ZERO)
    }

    #[test]
    fn full_promotion_path_releases_bytes() {
        let tainted = Payload::new(b"hello".to_vec(), Direction::Inbound);
        let r1 = passing(&tainted, Layer::Challenge);
        let challenged = tainted.into_challenged(&r1).unwrap();
        let r2 = passing(&challenged, Layer::Guard);
        let vetted = challenged.into_vetted(&r2).unwrap();
        assert_eq!(vetted.release(), b"hello");
    }

    #[test]
    fn blocking_report_refuses_promotion() {
        let tainted = Payload::new(b"payload".to_vec(), Direction::Inbound);
        let report = LayerReport::new(
            tainted.id(),
            Layer::Challenge,
            Uuid::new_v4(),
            vec![Finding::blocking("rule_x", "match", Severity::High)],
            Duration::ZERO,
        );
        let err = tainted.into_challenged(&report).unwrap_err();
        assert!(matches!(err, CtpError::Blocked(_)));
    }

    #[test]
    fn report_for_other_payload_is_a_trust_violation() {
        let a = Payload::new(b"a".to_vec(), Direction::Inbound);
        let b = Payload::new(b"b".to_vec(), Direction::Inbound);
        let report_for_b = passing(&b, Layer::Challenge);
        let err = a.into_challenged(&report_for_b).unwrap_err();
        assert!(matches!(err, CtpError::TrustViolation(_)));
    }

    #[test]
    fn wrong_layer_report_is_a_trust_violation() {
        let tainted = Payload::new(b"a".to_vec(), Direction::Outbound);
        // A guard report cannot stand in for the challenge layer.
        let guard_report = passing(&tainted, Layer::Guard);
        let err = tainted.into_challenged(&guard_report).unwrap_err();
        assert!(matches!(err, CtpError::TrustViolation(_)));
    }

    // Compile-time guarantees (cannot be expressed as runtime tests):
    // * `Payload::<Vetted>` has no public constructor — the only path is
    //   `new() → into_challenged() → into_vetted()`.
    // * `release()` does not exist on `Tainted`/`Challenged` payloads.
    // * `TrustState` is sealed; no fourth state can be defined downstream.
}
