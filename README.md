# Contextual Trust Protocol (CTP)

CTP is a zero-trust containment layer for autonomous agent systems. It treats
the main reasoning model as an untrusted CPU and sits between that model and
its tools, vetting every byte of tool I/O — in both directions — before it can
influence execution or re-enter the model's context.

The premise is deliberately pessimistic: a language model cannot reliably
separate instructions from data, so no amount of prompt engineering makes the
main model safe against injection. CTP does not try. It builds external,
programmatic walls around a model it assumes is already fooled, and it
separates the entity that *executes* actions (the main model) from the entity
that *judges* intent (a small, sandboxed guard model with no execution power).

This is defensive infrastructure. Every attack pattern in the codebase exists
as a detection target or a test fixture.

## Status

Early. The full pipeline is implemented and tested across the process
boundary, but the project has not been independently audited and is not yet
suitable for protecting a production system. See the Threat Model below for
what it does and does not defend against, and the gaps that remain open.

## Architecture

CTP is a Rust workspace of five crates, layered:

```
                 ┌─────────────────────────────────────────────┐
   tool call ──► │ ctp-orchestrator (L4)  gRPC gateway,         │
                 │   metrics, pipeline composition              │
                 └───────────────┬─────────────────────────────┘
                                 │
        ┌────────────────────────┼─────────────────────────┐
        ▼                        ▼                          ▼
 ┌─────────────┐        ┌─────────────────┐        ┌────────────────┐
 │ ctp-challenge│       │  ctp-kernel (L3) │       │   ctp-guard     │
 │   (L1)       │       │  tool I/O wrapper│       │   (L2) separate │
 │ static scan  │       │  both directions │──────►│   process, UDS  │
 └─────────────┘        └─────────────────┘  gRPC  │   only, no net  │
        ▲                        ▲           over   └────────────────┘
        │                        │           socket
        └──────── ctp-core: typestate payloads, fail-closed errors,
                            verdict model, shared traits ──────────┘
```

- **`ctp-core`** — shared types. A payload typestate (`Tainted → Challenged →
  Vetted`) makes pipeline order a compile-time invariant: only a `Vetted`
  payload can release its bytes, and the only public way to advance a payload
  is to run a real scanner. The error model is total and fail-closed — every
  variant maps to a BLOCK decision; there is no fallible path to PASS.

- **`ctp-challenge` (Layer 1)** — a static, sub-millisecond heuristic scanner
  that runs before any model is consulted. Detects encoding bypasses
  (nested base64/hex/percent, with explicit decode-bomb depth caps), unicode
  homoglyph and zero-width / bidi-control tricks, and configurable regex
  patterns loaded from TOML (new rules without a recompile).

- **`ctp-guard` (Layer 2)** — a separate OS process reachable only over a Unix
  domain socket, with no network access (enforced by its systemd unit, not by
  config). It runs a small local model whose only output channel is a verdict,
  constrained at the sampler by a GBNF grammar and re-validated by a strict
  fail-closed parser. It has zero execution power and holds no cross-request
  state. Ships with a deterministic mock backend (default, for tests) and a
  feature-gated llama.cpp backend.

- **`ctp-kernel` (Layer 3)** — middleware that wraps any tool executor and
  vets both the outbound arguments (before the tool runs) and the inbound
  result (before it returns to context). A multi-turn anomaly ledger with
  decay and a floor catches slow-burn attacks that no single turn would block.

- **`ctp-orchestrator` (Layer 4)** — composes the layers into one
  `evaluate` entry point, exposes a tonic gRPC gateway, dials the guard over
  the socket, and records per-layer Prometheus metrics.

## Build and test

Requires a recent stable Rust toolchain (pinned in `rust-toolchain.toml`).
The test suite is hermetic — it uses the mock guard backend, downloads no
model, and needs no network:

```sh
cargo test --workspace        # unit + cross-process integration tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

The real guard backend (`--features llama` on `ctp-guard`) builds llama.cpp
natively and is **not** exercised by the default suite; build it only on a host
with the native toolchain and a GGUF model.

## Running

```sh
# 1. The guard, sandboxed (see deploy/ctp-guard.service for the hardening):
ctp-guard /etc/ctp/ctp.toml

# 2. The orchestrator gateway:
ctp-orchestrator /etc/ctp/ctp.toml
```

Configuration is a single TOML file with deny-by-default semantics: unknown
keys are rejected, tools are denied unless explicitly enabled, the guard
backend must be chosen consciously, and listeners bind loopback. See
`ctp.toml.example`.

The guard is meant to run under the provided systemd unit, which enforces the
air gap (`PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`), a read-only
filesystem with a single writable runtime directory for the socket, a memory
ceiling, and a watchdog that restarts a wedged inference loop.

---

## Threat Model

### What CTP defends against

CTP defends the agent against **compromised data**: prompt injection and
context poisoning arriving through tool arguments and, especially, tool
results and external data streams that flow back into the model's context.
The inbound direction is the core case — the recursive poisoning vector where
a tool result carries an instruction that hijacks the next step.

Within that scope it provides: static detection of known obfuscation and
injection classes; a second, sandboxed model judging contextual integrity with
no power to act on its judgment; both-direction interception so a poisoned
result is blocked before it reaches the model even though the tool already
ran; deny-by-default tool access; and fail-closed behavior on every error,
timeout, or transport loss.

### Scope boundary — what CTP does NOT defend against

CTP protects against compromised **data**, not compromised **code** or a
compromised **host**.

- **Malicious code in the same address space.** CTP's in-process guarantees
  (the payload typestate, the encapsulated report construction) defend against
  *engineering mistakes* — skipping a layer, promoting an unvetted payload.
  They are not a defense against an attacker who already executes code inside
  the orchestrator process: such an attacker can reach the bytes directly,
  forge a report, or call the inner tool without the wrapper. The real boundary
  against a deliberate in-process bypass is the guard's separate, sandboxed
  process — not the type system.

- **A compromised host OS or kernel.** CTP trusts the operating system it runs
  on. If the kernel, the systemd sandbox, or the Unix socket layer is
  subverted, the air gap and the process isolation that make Layer 2
  trustworthy no longer hold. CTP has no hardware root of trust.

  **Hardware TEE / TPM is explicit future work, not present today**, for three
  reasons: (1) it changes the trust model from "trust the host OS" to "trust
  the silicon vendor and attestation chain," a decision an operator should make
  deliberately, not inherit; (2) confidential-computing enclaves for local
  model inference (sealed memory, remote attestation of the guard binary and
  weights) are an integration and performance project in their own right; and
  (3) shipping a TEE story before the software boundaries above are audited
  would be putting a vault door on a tent. The honest sequence is: harden and
  audit the OS-level containment first, then consider attestation.

### Known open gaps

These were found during construction and are stated plainly rather than
smoothed over. None are hypothetical; each is a real limitation of the current
code.

1. **Gateway evaluation and kernel enforcement are not yet the same path.**
   The orchestrator's gRPC `evaluate` endpoint runs the full pipeline and
   returns a verdict, but it does **not** execute tools — it judges a payload.
   The actual enforcement that intercepts tool I/O lives in `ctp-kernel`'s
   `KernelWrapper`, which is **not wired into the gateway** and is currently
   unmetered. An operator using the gateway gets evaluation without
   enforcement; one embedding the wrapper gets enforcement without metrics.
   Closing this — a transparent tool-proxy mode (the planned MCP interceptor)
   or instrumenting the wrapper path — is required before any production claim.

2. **The anomaly score is process-local and ephemeral.** The multi-turn ledger
   that catches slow-burn attacks lives in the orchestrator's memory. Its decay
   floor prevents a long benign stretch from erasing suspicion *within a
   session*, but it does not survive a restart and does not correlate *across*
   sessions. An attacker who spreads one borderline payload per session, or who
   can induce an orchestrator restart, resets the cumulative score and bypasses
   multi-turn detection entirely. Durable, cross-session correlation (e.g. a
   shared store) is needed before this holds against a patient attacker.

3. **The guard is a small model; GBNF guarantees form, not judgment.** Layer 2
   is intended to run a lightweight (~0.5B-class) local model. The GBNF grammar
   guarantees the *shape* of its output — a binary verdict, never prose — but
   it cannot make the *judgment* correct. A small model is itself fallible and
   can be talked past. And Layer 1, by design, must let through grammatically
   clean prose that contains a semantic intent-shift with no encoding,
   homoglyph, or known phrase — otherwise it would block ordinary tool output.
   So the system's detection ceiling is bounded by the guard model's quality,
   and a sufficiently subtle, well-formed injection can pass both layers. CTP
   narrows the attack surface sharply; it does not eliminate it. "AI will never
   be secure" applies to the guard too.

4. **The report encapsulation prevents accidents, not intent.** Making
   `LayerReport` construction crate-private and routing it through real
   scanners stops a developer from *accidentally* promoting an unvetted payload.
   It does not stop code that deliberately wants to bypass a layer from within
   the same process — see the scope boundary above. It is a guardrail, not a
   wall.

### Failure posture

Everywhere ambiguity meets a decision, CTP blocks: guard unreachable, guard
timeout, off-contract guard output, oversize payload, config missing, parse
failure, an unknown enum on the wire. A block costs a retry; a wrong pass costs
a compromise. The guard process is built to crash hard (`panic=abort`) and be
restarted by systemd rather than limp on in an undefined state.

---

## Provenance

CTP was built with AI assistance. The architecture and the security
decisions — the layering, the trust boundaries, the fail-closed posture, and
the specific trade-offs recorded above — are the author's. The implementation
was carried out agentically, step by step, with each step stopped at a manual
checkpoint and reviewed before the next began; the open gaps in the Threat
Model came out of those reviews.

AI assistance does not substitute for a security audit. An independent review
is recommended before CTP is relied on to protect anything that matters.

## License

To be determined. Until a license is added, no rights are granted; the code is
readable but not yet licensed for use, modification, or redistribution.
