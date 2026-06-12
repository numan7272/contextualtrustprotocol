# 0004 — Guard receives the raw windowed payload, not extracted intents

**Status:** Accepted (revises the original spec)

## Context

The initial design had the guard receive `extracted_intents: Vec<String>` —
a summary of the payload — rather than the payload itself. The Step-1 review
found this inverts the trust model. Whoever extracts becomes an unverified
trust anchor: if the main (untrusted) model extracts, it curates the evidence
for its own judge; if a second model extracts, that is a new un-constrained
model contact with raw bytes *before* the guard; if a static extractor does
it, it sees only surface patterns — and a hidden intent shift is exactly what
a static extractor cannot surface, blinding Layer 2 to its only job.

## Decision

The guard receives the **raw payload**, split into overlapping windows
(`GuardRequest.payload_window` + index/count), framed between per-request nonce
markers as inert data. Metadata (`anomaly_flags` from Layer 1, `tool_name`)
travels alongside as *additive context only* — it never replaces the bytes.
This is safe precisely because the guard is maximally contained (ADR 0003) and
its output is grammar-bounded (ADR 0002).

See `proto/guard.proto`, `ctp-kernel`'s `GuardFanout`.

## Consequences

- The verifier sees what actually arrived, not a lossy summary an attacker (or
  a well-meaning extractor) could shape. Nothing curates the evidence.
- Windowing with overlap means an instruction split across a boundary is still
  seen whole by at least one window.
- **Negative:** the guard runs over more data (every window of every payload),
  which is more model invocations and more latency than judging one short
  summary would be — directly in tension with the latency budget.
- **Negative:** raw bytes mean the guard must itself withstand hostile input
  (oversize, malformed UTF-8); the containment and the size caps carry weight
  the summary approach would have sidestepped.
