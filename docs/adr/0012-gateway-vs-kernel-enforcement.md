# 0012 — Gateway evaluates; kernel enforces (not yet unified)

**Status:** Accepted (records a current limitation, not a finished design)

## Context

CTP exposes two ways to use the pipeline, and — as the code stands after Step 7
— they are not the same path:

- The **gateway** (`ctp-orchestrator`'s gRPC `evaluate`) runs a payload through
  challenge → guard → ledger and returns a verdict. It is the metered,
  externally reachable surface. It does **not** execute tools.
- The **kernel** (`ctp-kernel`'s `KernelWrapper`) is the enforcement path: it
  wraps a tool executor and intercepts both directions of real tool I/O
  (ADR 0005). It is embedded as a library and is currently **unmetered** and
  **not wired into the gateway**.

## Decision

Record this as a known, deliberate limitation rather than paper over it. The
gateway and the kernel share the same layers (challenge scanner, guard fanout,
ledger) but are assembled separately. Unifying them — a transparent tool-proxy
mode in the gateway (the planned MCP interceptor), or instrumenting the kernel
path — is deferred, not done.

## Consequences

- The library (`KernelWrapper`) path is the one with real enforcement and the
  cross-process integration test; the gateway path is the one with metrics.
- Keeping them separate kept each step shippable and testable on its own.
- **Negative:** an operator who reaches for the gRPC gateway gets *evaluation
  without enforcement* — verdicts, but no interception of tool execution. One
  who embeds the `KernelWrapper` gets *enforcement without metrics*. Neither is
  the complete product, and the gap is easy to miss without this record.
- **Negative:** the "inference kernel that natively mediates all tool I/O"
  framing is not realized by the current code; there is no transparent MCP
  proxy. The pieces exist; the unifying surface does not.
- **Negative:** because the kernel path is unmetered, the post-Step-8 benchmark
  can measure the gateway's evaluation latency but not the enforcement path's
  end-to-end cost as an agent would experience it.
