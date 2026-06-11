//! The three contracts between CTP layers.
//!
//! * [`Rule`] — a single static heuristic in Layer 1. Sync, pure CPU.
//! * [`GuardCheck`] — the kernel's view of Layer 2. The only async I/O a
//!   vetting path performs.
//! * [`ToolExecutor`] — anything that runs tools. Layer 3 wraps one
//!   `ToolExecutor` in another (decorator), vetting both directions.

use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use crate::error::CtpError;
use crate::payload::Direction;
use crate::verdict::{RuleResult, Verdict};

/// A single Layer-1 heuristic. Implementations must be cheap (the whole
/// layer targets <2ms p99 at 32 KiB), allocation-light and side-effect
/// free: no I/O, no globals, no logging beyond `tracing` events.
///
/// `name()` returns `&'static str` per the layer contract; rules created
/// from configuration at startup may leak their name once (bounded by rule
/// count) to satisfy it.
pub trait Rule: Send + Sync {
    fn name(&self) -> &'static str;
    fn check(&self, payload: &[u8]) -> RuleResult;
}

/// Everything the kernel knows about a requested tool call.
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub session_id: Uuid,
    /// Tool the model asked for. Used for policy lookup (deny-by-default).
    pub tool_name: String,
    /// Serialized tool arguments (typically JSON bytes). Outbound payload.
    pub arguments: Vec<u8>,
    /// Monotonic turn counter within the session; drives anomaly decay.
    pub turn: u32,
}

/// Raw result of a tool execution. From a bare executor this is UNTRUSTED
/// data — only outputs obtained through the kernel wrapper have had their
/// content vetted. The composition root decides which one it talks to.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub content: Vec<u8>,
}

/// Executes tools. Implemented by real tool backends (MCP servers, local
/// functions, HTTP APIs) and by the kernel wrapper itself, which decorates
/// an inner executor with both-direction vetting.
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    async fn execute(&self, ctx: ToolContext) -> Result<ToolOutput, CtpError>;
}

/// One payload window submitted to the guard. Windows are raw slices of
/// the payload — never summaries — sized by `guard.max_window_bytes`.
#[derive(Debug, Clone)]
pub struct GuardRequest {
    pub window: Vec<u8>,
    /// Position of this window (0-based) and total window count.
    pub window_index: u32,
    pub window_count: u32,
    pub direction: Direction,
    pub tool_name: Option<String>,
    /// Advisory rule names forwarded verbatim from Layer 1.
    pub anomaly_flags: Vec<String>,
    /// Audit correlation only — the guard is stateless.
    pub session_id: Uuid,
}

/// The guard's answer for one window.
#[derive(Debug, Clone)]
pub struct GuardVerdict {
    pub verdict: Verdict,
    /// TELEMETRY ONLY. Small guard models are not calibrated; no decision
    /// path may branch on this value. The name is hostile to misuse on
    /// purpose.
    pub confidence_telemetry: f32,
    /// Machine-readable findings, e.g. `"intent_shift"`.
    pub flags: Vec<String>,
    /// Model + prompt version for audit, e.g. `"mock"` or
    /// `"qwen2.5-0.5b-instruct/guard_system_v1"`.
    pub model_id: String,
    pub inference: Duration,
}

/// Layer 2 as seen from the kernel: classify one window, fail-closed.
///
/// Implementations MUST map every transport, timeout and contract failure
/// to the corresponding `CtpError` variant — never to a synthetic PASS.
/// The production implementation is the UDS gRPC client in the
/// orchestrator; tests use deterministic mocks.
#[async_trait]
pub trait GuardCheck: Send + Sync {
    async fn classify(&self, request: GuardRequest) -> Result<GuardVerdict, CtpError>;
}
