# 0011 — Deny-by-default configuration

**Status:** Accepted

## Context

A security system's configuration is itself an attack surface. The dangerous
failure is not a rejected config — it is a config that *looks* applied but
isn't: a misspelled key silently ignored, a tool implicitly allowed, a listener
bound to the world by default.

## Decision

Deny-by-default in every dimension. Unknown TOML keys are rejected
(`#[serde(deny_unknown_fields)]` on every config struct), so a typo'd security
knob is a hard startup failure, not a silent no-op. Tools are denied unless a
policy lists them *and* sets `enabled = true` (`tool_policy` returns a
locked-down default for anything unlisted). The guard backend has no default —
an operator must consciously pick `mock` or `llama`. Network listeners default
to loopback. A process without a valid config refuses to serve.

See `ctp-core/src/config.rs`; covered by the config tests
(`unknown_keys_refuse_to_parse`, `unknown_tool_is_denied_*`, etc.) and a test
that parses the shipped `ctp.toml.example` so it cannot drift from the schema.

## Consequences

- The safe state is the absence of configuration: forgetting to enable a tool
  denies it; mistyping a hardening setting fails loud.
- The example config is schema-checked by a test, so docs and code stay aligned.
- **Negative:** strictness costs operator ergonomics. A forward-compatible
  config (a new key a newer binary understands) is rejected by an older binary,
  and every tool must be enumerated explicitly — there is no convenient
  "allow all" for development, by design.
- **Negative:** `deny_unknown_fields` makes config evolution a breaking-change
  exercise; removing or renaming a field can reject previously valid files.
