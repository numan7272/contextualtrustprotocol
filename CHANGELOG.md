# Changelog

All notable changes to CTP. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/). The project is pre-release;
nothing here constitutes a stable API, and there is no published version yet.

This first development cycle was built in eight steps, each stopped at a manual
review checkpoint. The entries below map one-to-one to those steps. Several
steps revised the original specification where the review found it unsound;
those revisions are noted and recorded in full as ADRs (`docs/adr/`).

## [Unreleased]

### Fixed (post-Step-8, runtime)
- The GBNF grammar tripped a hard C++ abort in llama.cpp at inference time
  against a real model on CPU (`GGML_ASSERT(!stacks.empty())`). Two causes,
  read from the bundled llama.cpp source: (1) the decode loop accepted the
  end-of-generation token into the grammar sampler, which `GGML_ABORT`s when
  EOG is accepted in a non-terminal state — fixed by checking EOG before
  accept; (2) the grammar used `?`/`*`/`+`/`()` operators whose desugaring into
  synthesized rules is an init edge-case — rewritten in operator-free
  right-recursive form (identical language; the in-tree acceptor still
  validates it). The acceptor proves language membership, not llama.cpp runtime
  safety — a scope limit now stated in ADR 0002. Also raised the example
  config's guard `timeout_ms` to 10000 for CPU testing (production/GPU should
  lower it back toward ~500).

### Fixed (post-Step-8, compile)
- The `llama` guard backend (ADR 0002's documented deviation) now compiles
  against `llama-cpp-2 0.1.146`. The first real compile — on a host with
  libclang + cmake — caught a genuine API mismatch: `LlamaSampler::grammar`
  returns a `Result` that the inference loop chained as if infallible. Fixed
  fail-closed (a grammar that fails to install propagates an error the server
  maps to BLOCK), and moved off two deprecated decode APIs (`token_to_str` /
  `Special`) to `token_to_piece_bytes`. The inference path still has not been
  run against a real GGUF model; only compilation is verified.

### Step 1 — Architectural review of the specification
- Identified the spec's central flaw before any code: it verified the wrong
  artifact (a derived summary, and only the outbound direction) instead of the
  raw inbound bytes. Drove two revisions carried through the rest of the build:
  the guard receives the raw windowed payload, not extracted intents
  (ADR 0004), and vetting covers both directions of tool I/O (ADR 0005).
- Corrected the systemd hardening from the spec draft (which does not boot) to
  the working set delivered in Step 8 (ADR 0003).

### Step 2 — Workspace scaffold
- Five-crate Cargo workspace (`ctp-core`, `ctp-challenge`, `ctp-guard`,
  `ctp-kernel`, `ctp-orchestrator`), exact-pinned dependencies, committed
  lockfile, pinned toolchain, hermetic protobuf codegen via vendored `protoc`,
  `unsafe_code` denied workspace-wide (ADR 0010).
- `proto/guard.proto`: the orchestrator↔guard contract. Raw payload windows,
  stateless guard, every `UNSPECIFIED` enum value defined as fail-closed.

### Step 3 — `ctp-core` foundation
- Typestate payloads `Tainted → Challenged → Vetted`; only `Vetted` releases
  bytes (ADR 0001).
- Total, fail-closed error model: every `CtpError` collapses to BLOCK through an
  exhaustive, wildcard-free match (ADR 0007).
- Closed the tool-error inbound channel: `ToolFailed` keeps attacker-
  influenceable text out of `Display` (ADR 0008).
- Deny-by-default config schema with `deny_unknown_fields` (ADR 0011).

### Step 4 — `ctp-challenge` (Layer 1)
- Static sub-millisecond scanner with a runtime rule registry. Three rules:
  unicode homoglyph / zero-width / bidi detection, encoding-bypass detection
  with explicit fail-closed decode-bomb depth caps, and data-driven regex rules
  from config.
- Attack/benign corpus and a latency smoke over a realistic 32 KiB fixture
  (release p99 ~1.7 ms against a 2 ms target). The realistic fixture exposed
  and fixed two precision bugs (Japanese false-positive, a bulk-data
  over-block).

### Step 5 — `ctp-guard` (Layer 2)
- Air-gapped guard binary reachable only over a Unix socket. GBNF-constrained
  decoding so the model physically cannot emit prose (ADR 0002), re-validated
  by a strict fail-closed parser. Versioned system prompt with per-request
  nonce-framed inert data. Stateless across requests.
- Deterministic mock backend (default, tested) plus a feature-gated llama.cpp
  backend (not built by the suite — see the deviation note in ADR 0002).
- Real UDS gRPC roundtrip integration test.

### Step 6 — `ctp-kernel` (Layer 3)
- `KernelWrapper` vetting both directions; a block prevents execution outbound
  and discards a poisoned result inbound (ADR 0005), proven end-to-end.
- `GuardFanout`: windowed, parallel, time-bounded guard fan-out; ANY-BLOCK →
  BLOCK, race-free; hung guard → timeout → BLOCK (ADR 0007).
- `AnomalyLedger` with decay and a floor against the decay self-bypass
  (ADR 0006). Added `kernel.anomaly_floor` to the config.
- Closed the Step-3 `LayerReport` gap: report construction is crate-private,
  reachable only by running a real scanner (ADR 0009). This refactored Layer 1
  from `scan() -> Report` to a findings-returning trait.

### Step 7 — `ctp-orchestrator` (Layer 4)
- `Orchestrator::evaluate` composing the layers, exposed as a tonic gRPC
  gateway, with per-layer Prometheus metrics (latency by layer, decisions by
  verdict, guard timeout/unavailable/contract counters) and tracing at every
  boundary.
- `GuardClient`: the real Layer-2 client over UDS. Transport failure →
  `GuardUnavailable`, timeout → `GuardTimeout`, off-contract → contract
  violation, none embedding raw guard output (ADR 0007/0008).
- End-to-end test across the process boundary (payload → challenge → real guard
  over UDS → ledger → decision), including dead-socket fail-closed.
- Recorded a limitation: the gateway evaluates but does not enforce; the kernel
  enforcement path is not yet wired into it (ADR 0012).

### Step 8 — Deployment and documentation
- `deploy/ctp-guard.service`: the corrected hardening, every directive
  annotated with the attack it closes, verified by `systemd-analyze`
  (ADR 0003). The systemd watchdog is wired via `sd_notify` (not yet exercised
  under real systemd).
- README with an honest threat model: the scope boundary (compromised data, not
  compromised in-process code or host OS; TEE/TPM future work) and the four open
  gaps found during construction; an explicit AI-assistance provenance
  statement; no marketing language.
