# 0005 — Vet both directions of tool I/O

**Status:** Accepted (revises the original spec)

## Context

The original Layer-3 design intercepted only "before execution" — the outbound
tool arguments. The Step-1 review found this misses the primary vector. The
recursive context-poisoning attack CTP exists to stop lives on the **inbound**
side: a tool *result* (a fetched web page, a file, an API response) carries an
instruction that hijacks the agent's next step. Vetting only outbound arguments
leaves that wide open.

## Decision

`KernelWrapper::execute` vets both directions. Outbound: the arguments are run
through Layer 1 + Layer 2 *before* the inner tool is called — a block means the
tool never runs. Inbound: the result is run through Layer 1 + Layer 2 *before*
it is returned — a block discards the poisoned result even though the tool
already executed. Both directions are fail-closed.

See `ctp-kernel/src/lib.rs`; proven by `ctp-kernel/tests/pipeline.rs`.

## Consequences

- The inbound vector — CTP's reason to exist — is actually covered, with a test
  that shows a poisoned result blocked after the tool ran but before the bytes
  reach the caller.
- Outbound blocking additionally prevents a poisoned argument from ever
  reaching the tool.
- **Negative:** the tool's *side effects* are outside CTP's reach. On the
  inbound path the tool has already executed (the HTTP GET happened, the file
  was written); CTP only stops the *result* from re-entering context. CTP
  cannot un-ring that bell, and the design does not claim to.
- **Negative:** every tool call now incurs two full pipeline passes (outbound
  and inbound), roughly doubling the vetting cost per call.
