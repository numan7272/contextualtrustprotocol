//! TOML configuration schema. Deny-by-default in every dimension:
//!
//! * Unknown keys are rejected (`deny_unknown_fields`) — a typo in a
//!   security setting must fail loud at startup, not be silently ignored.
//! * Tools are denied unless explicitly `enabled = true`.
//! * The guard backend has NO default: an operator must consciously pick
//!   `mock` (tests) or `llama` (production). A config that doesn't choose
//!   doesn't start.
//! * Network listeners default to loopback, never `0.0.0.0`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::CtpError;
use crate::verdict::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CtpConfig {
    pub challenge: ChallengeConfig,
    pub guard: GuardConfig,
    pub kernel: KernelConfig,
    pub orchestrator: OrchestratorConfig,
}

impl CtpConfig {
    /// Read, parse and validate. Any failure is `CtpError::Config`; a
    /// process without a valid config refuses to serve.
    pub fn load(path: &Path) -> Result<Self, CtpError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| CtpError::Config(format!("read {}: {e}", path.display())))?;
        Self::from_toml_str(&raw)
    }

    pub fn from_toml_str(raw: &str) -> Result<Self, CtpError> {
        let config: CtpConfig =
            toml::from_str(raw).map_err(|e| CtpError::Config(format!("parse: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), CtpError> {
        let g = &self.guard;
        if g.timeout_ms == 0 {
            return Err(CtpError::Config("guard.timeout_ms must be > 0".into()));
        }
        if !(64..=65536).contains(&g.max_window_bytes) {
            return Err(CtpError::Config(
                "guard.max_window_bytes must be within 64..=65536".into(),
            ));
        }
        if g.window_overlap_bytes >= g.max_window_bytes {
            return Err(CtpError::Config(
                "guard.window_overlap_bytes must be smaller than guard.max_window_bytes".into(),
            ));
        }
        if g.backend == GuardBackendKind::Llama && g.model_path.is_none() {
            return Err(CtpError::Config(
                "guard.model_path is required for backend = \"llama\"".into(),
            ));
        }
        if self.challenge.max_payload_bytes == 0 {
            return Err(CtpError::Config(
                "challenge.max_payload_bytes must be > 0".into(),
            ));
        }
        let k = &self.kernel;
        if k.anomaly_threshold <= 0.0 {
            return Err(CtpError::Config(
                "kernel.anomaly_threshold must be > 0".into(),
            ));
        }
        if !(k.anomaly_decay > 0.0 && k.anomaly_decay <= 1.0) {
            return Err(CtpError::Config(
                "kernel.anomaly_decay must be within (0, 1]".into(),
            ));
        }
        if k.flag_weight < 0.0 {
            return Err(CtpError::Config("kernel.flag_weight must be >= 0".into()));
        }
        if !(k.anomaly_floor >= 0.0 && k.anomaly_floor < k.anomaly_threshold) {
            return Err(CtpError::Config(
                "kernel.anomaly_floor must be within [0, anomaly_threshold)".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeConfig {
    /// Hard cap before any rule runs; oversize payloads are blocked outright.
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
    /// Data-driven pattern rules, loaded at startup — no recompile needed.
    #[serde(default)]
    pub rules: Vec<RegexRuleSpec>,
}

/// A pattern rule defined in configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegexRuleSpec {
    /// Stable identifier, e.g. `"instruction_override_en"`.
    pub id: String,
    /// Rust `regex` syntax; compiled (and thus validated) at startup.
    pub pattern: String,
    pub action: RuleAction,
    #[serde(default = "default_rule_severity")]
    pub severity: Severity,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Block,
    Flag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardBackendKind {
    /// Deterministic test backend. Performs NO real classification —
    /// loudly logged at startup; never run this in production.
    Mock,
    /// llama.cpp with GBNF-constrained decoding (requires the `llama`
    /// build feature of ctp-guard).
    Llama,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    /// Unix domain socket the guard listens on. The guard has no other
    /// reachable surface.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,
    /// REQUIRED, no default — choosing the backend is a conscious act.
    pub backend: GuardBackendKind,
    /// GGUF model weights; required iff `backend = "llama"`.
    #[serde(default)]
    pub model_path: Option<PathBuf>,
    /// Client-side budget per window. Authoritative and fail-closed: on
    /// expiry the verdict is BLOCK regardless of what arrives later.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Window size for chunked classification. Also enforced server-side:
    /// the guard blocks oversize windows without running inference.
    #[serde(default = "default_max_window_bytes")]
    pub max_window_bytes: usize,
    /// Overlap between consecutive windows so instructions split across a
    /// boundary are still seen whole by at least one window.
    #[serde(default = "default_window_overlap_bytes")]
    pub window_overlap_bytes: usize,
    /// Concurrent classify requests the guard serves; excess waits.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    /// Versioned system prompt asset to use.
    #[serde(default = "default_prompt_version")]
    pub prompt_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelConfig {
    /// Cumulative anomaly score at which a session is blocked.
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: f64,
    /// Multiplicative decay applied to a session's score each turn,
    /// within (0, 1]. Prevents long benign sessions from self-DoS.
    #[serde(default = "default_anomaly_decay")]
    pub anomaly_decay: f64,
    /// Residual-suspicion floor: once a session has ever raised an anomaly,
    /// decay cannot drive its score below this value. Without it, a long
    /// benign stretch decays the score to ~0 and a later attack starts from
    /// a clean slate — the decay becomes a self-bypass. Must be within
    /// `[0, anomaly_threshold)`.
    #[serde(default = "default_anomaly_floor")]
    pub anomaly_floor: f64,
    /// Score added per advisory flag (challenge flag or guard flag).
    #[serde(default = "default_flag_weight")]
    pub flag_weight: f64,
    /// Upper bound on tracked sessions; oldest entries are evicted.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Per-tool policies. A tool absent from this map is DENIED.
    #[serde(default)]
    pub tools: HashMap<String, ToolPolicy>,
}

impl KernelConfig {
    /// Deny-by-default lookup: unknown tools get the locked-down default
    /// policy (`enabled = false`).
    pub fn tool_policy(&self, tool_name: &str) -> ToolPolicy {
        self.tools.get(tool_name).cloned().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    /// Must be explicitly `true`. A `[kernel.tools.x]` section alone does
    /// not enable a tool.
    #[serde(default)]
    pub enabled: bool,
    /// Cap on tool result size accepted for inbound vetting.
    #[serde(default = "default_max_result_bytes")]
    pub max_result_bytes: usize,
}

impl Default for ToolPolicy {
    fn default() -> Self {
        ToolPolicy {
            enabled: false,
            max_result_bytes: default_max_result_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestratorConfig {
    /// External gRPC listener. Loopback by default — exposing CTP beyond
    /// the host is a conscious operator decision.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Prometheus exporter listener.
    #[serde(default = "default_metrics_listen")]
    pub metrics_listen: SocketAddr,
}

fn default_max_payload_bytes() -> usize {
    32 * 1024
}
fn default_rule_severity() -> Severity {
    Severity::Medium
}
fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/ctp/guard.sock")
}
fn default_timeout_ms() -> u64 {
    500
}
fn default_max_window_bytes() -> usize {
    2048
}
fn default_window_overlap_bytes() -> usize {
    256
}
fn default_max_concurrent() -> usize {
    4
}
fn default_prompt_version() -> String {
    "guard_system_v1".to_string()
}
fn default_anomaly_threshold() -> f64 {
    3.0
}
fn default_anomaly_decay() -> f64 {
    0.5
}
fn default_anomaly_floor() -> f64 {
    0.5
}
fn default_flag_weight() -> f64 {
    0.5
}
fn default_max_sessions() -> usize {
    10_000
}
fn default_max_result_bytes() -> usize {
    256 * 1024
}
fn default_listen() -> SocketAddr {
    #[allow(clippy::unwrap_used)] // constant literal, cannot fail
    "127.0.0.1:50051".parse().unwrap()
}
fn default_metrics_listen() -> SocketAddr {
    #[allow(clippy::unwrap_used)] // constant literal, cannot fail
    "127.0.0.1:9464".parse().unwrap()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [challenge]
        [guard]
        backend = "mock"
        [kernel]
        [orchestrator]
    "#;

    #[test]
    fn minimal_config_parses_with_safe_defaults() {
        let config = CtpConfig::from_toml_str(MINIMAL).unwrap();
        assert_eq!(config.guard.timeout_ms, 500);
        assert_eq!(config.guard.max_window_bytes, 2048);
        assert_eq!(config.orchestrator.listen.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn missing_backend_refuses_to_parse() {
        let toml = r#"
            [challenge]
            [guard]
            [kernel]
            [orchestrator]
        "#;
        let err = CtpConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, CtpError::Config(_)));
    }

    #[test]
    fn unknown_keys_refuse_to_parse() {
        // A typo'd security knob must not be silently ignored.
        let toml = r#"
            [challenge]
            [guard]
            backend = "mock"
            timeout_msec = 50
            [kernel]
            [orchestrator]
        "#;
        let err = CtpConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, CtpError::Config(_)));
    }

    #[test]
    fn llama_backend_requires_model_path() {
        let toml = r#"
            [challenge]
            [guard]
            backend = "llama"
            [kernel]
            [orchestrator]
        "#;
        let err = CtpConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, CtpError::Config(_)));
    }

    #[test]
    fn unknown_tool_is_denied_and_empty_section_stays_disabled() {
        let toml = r#"
            [challenge]
            [guard]
            backend = "mock"
            [kernel]
            [kernel.tools.listed_but_not_enabled]
            [kernel.tools.enabled_tool]
            enabled = true
            [orchestrator]
        "#;
        let config = CtpConfig::from_toml_str(toml).unwrap();
        assert!(!config.kernel.tool_policy("never_mentioned").enabled);
        assert!(!config.kernel.tool_policy("listed_but_not_enabled").enabled);
        assert!(config.kernel.tool_policy("enabled_tool").enabled);
    }

    #[test]
    fn overlap_must_be_smaller_than_window() {
        let toml = r#"
            [challenge]
            [guard]
            backend = "mock"
            max_window_bytes = 256
            window_overlap_bytes = 256
            [kernel]
            [orchestrator]
        "#;
        let err = CtpConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, CtpError::Config(_)));
    }

    #[test]
    fn shipped_example_config_is_valid() {
        let example = include_str!("../../ctp.toml.example");
        CtpConfig::from_toml_str(example).unwrap();
    }
}
