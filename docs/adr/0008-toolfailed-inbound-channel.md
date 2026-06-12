# 0008 — A tool's error text is an inbound injection channel

**Status:** Accepted

## Context

CTP vets tool *results* (ADR 0005). But a tool can also fail, and its error
message is attacker-influenceable — a malicious or compromised tool controls
the text of its own error. Agent runtimes routinely surface an error's
`Display` back into the model's context ("the tool failed: <message>"). That
makes the error message an inbound channel exactly like the result body, and
one that bypasses result vetting because it travels a different path.

This surfaced during the Step-3 error-model audit: of all `CtpError` variants,
`ToolFailed` was the one that was effectively fail-open against text injection.

## Decision

Split the tool failure into a structured, model-safe part and an
operator-only part. `CtpError::ToolFailed` carries a closed
`ToolFailureClass` enum (`Timeout`, `Crashed`, `InvalidArguments`,
`Unavailable`, `Other`) and the raw, attacker-influenceable text in a separate
`audit_detail` field. The `Display` impl interpolates only the closed class,
never the raw text; `audit_detail()` is reachable only by operator-facing audit
code. The same discipline governs `GuardUnavailable` / `GuardContractViolation`
strings (no raw guard output).

See `ctp-core/src/error.rs`;
`tool_failure_display_excludes_audit_detail` proves an injection string in the
inner error does not leak through `Display`.

## Consequences

- Only a fixed vocabulary (the class enum) can travel toward the model on the
  error path; free-form attacker text cannot.
- The raw detail is still preserved for operators in the audit log.
- **Negative:** the policy "no raw guard/tool text in `Display`" is a
  convention enforced by review and a few targeted tests, not by the type
  system. A future variant that interpolates raw text into its `#[error("…")]`
  would reopen the channel, and nothing mechanical prevents that.
- **Negative:** operators lose the inner error text from the default error
  surface; debugging a tool failure requires consulting the audit log, not just
  the returned error.
