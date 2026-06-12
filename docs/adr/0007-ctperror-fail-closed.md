# 0007 — Total, fail-closed error model

**Status:** Accepted

## Context

A security pipeline must never default to "allow" when something goes wrong.
Guard unreachable, timeout, parse failure, config missing, an unknown enum on
the wire — every one of these is a moment where a permissive default would be a
silent hole. The failure posture must be a property of the type system, not of
remembering to handle each case.

## Decision

`CtpError`'s disposition is total and fail-closed. `to_block_decision` maps
*every* variant to a BLOCK decision through an exhaustive match with no
wildcard, so a new error variant cannot be added without deciding its
provenance — the compiler refuses. Guard timeouts map to BLOCK at the
client-authoritative boundary (`GuardTimeout`), transport failures to
`GuardUnavailable`, off-contract output to `GuardContractViolation`. The
gateway's `evaluate` never returns `Result`: every failure becomes a BLOCK
`Decision`. Release of bytes is gated on `Ok(Payload<Vetted>)` (ADR 0001), so
there is structurally no fallible path to PASS.

See `ctp-core/src/error.rs`; `every_variant_collapses_to_block` proves it over
all variants.

## Consequences

- Ambiguity always resolves to BLOCK. A wrong block costs a retry; a wrong pass
  costs a compromise.
- Adding an error variant forces a fail-closed classification at compile time.
- **Negative:** fail-closed plus a flaky or slow guard becomes a self-inflicted
  outage — every call blocks while the guard is down. Availability is
  deliberately sacrificed to safety, which an operator must plan for (the guard
  restart policy in ADR 0003 mitigates but does not remove this).
- **Negative:** distinguishing "security block" from "operational failure" is a
  second axis (`is_security_block`) that callers must respect; collapsing both
  to BLOCK is safe but can mask an operational problem as an attack in metrics.
