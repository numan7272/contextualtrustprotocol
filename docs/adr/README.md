# Architecture Decision Records

These ADRs record the design decisions behind CTP, written against the code
as it actually exists — including where the code falls short of the intent.
Each record follows Status / Context / Decision / Consequences, and every one
states at least one negative consequence: a decision with no downside is
usually a decision not yet understood.

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-typestate-pipeline.md) | Typestate payload pipeline (`Tainted → Challenged → Vetted`) | Accepted |
| [0002](0002-gbnf-over-prompt-constraint.md) | GBNF-constrained decoding, not prompt-asked output | Accepted |
| [0003](0003-guard-process-isolation.md) | Guard runs as a separate, sandboxed process over UDS | Accepted |
| [0004](0004-raw-payload-over-extracted-intents.md) | Guard receives raw windowed payload, not extracted intents | Accepted |
| [0005](0005-bidirectional-vetting.md) | Vet both directions of tool I/O | Accepted |
| [0006](0006-anomaly-decay-and-floor.md) | Multi-turn anomaly score with decay and a floor | Accepted |
| [0007](0007-ctperror-fail-closed.md) | Total, fail-closed error model | Accepted |
| [0008](0008-toolfailed-inbound-channel.md) | Tool error text is an inbound channel | Accepted |
| [0009](0009-layerreport-encapsulation.md) | Crate-private report construction | Accepted |
| [0010](0010-rust-tonic-uds-stack.md) | Rust + Tokio + tonic over Unix domain sockets | Accepted |
| [0011](0011-deny-by-default-config.md) | Deny-by-default configuration | Accepted |
| [0012](0012-gateway-vs-kernel-enforcement.md) | Gateway evaluates; kernel enforces (not yet unified) | Accepted (limitation) |
| [0013](0013-flags-are-non-decisional.md) | Guard flags/confidence stay strictly non-decisional | Accepted |

## Known deviations from intent

Recorded here and in the relevant ADRs rather than smoothed over:

- The GBNF-applying llama backend (ADR 0002) is feature-gated and not in the
  default hermetic suite; the entire tested path uses a keyword-matching mock.
  It now **compiles against llama-cpp-2 0.1.146** (verified), which caught and
  fixed a real API mismatch, but the inference path has **not been run against
  a real model**. The grammar's exclusion property is proven against the
  deployed `.gbnf` by an in-tree acceptor; the model integration's runtime
  behavior is unverified.
- The systemd watchdog (ADR 0003) is wired via `sd_notify`, but has **not been
  exercised under real systemd** in this build.
- The gateway and the kernel enforcement path are **not the same code path**
  yet (ADR 0012). The metered gRPC `evaluate` endpoint judges payloads; it does
  not execute tools.
