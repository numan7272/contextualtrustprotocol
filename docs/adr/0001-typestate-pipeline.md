# 0001 — Typestate payload pipeline

**Status:** Accepted

## Context

The central risk in CTP is that unvetted data reaches execution or model
context — a skipped layer, a reordered call, a report applied to the wrong
payload under concurrency. These are engineering mistakes, and convention
("always call the guard after the challenge") does not prevent them.

## Decision

Model the verification state in the type system. `Payload<S>` is parameterized
by a sealed `TrustState`: `Tainted → Challenged → Vetted`. The bytes can only
be released by `Payload::<Vetted>::release`, which exists on no other state.
Advancing a payload requires running the real scanner (`challenge`, `guard`);
each promotion binds to the payload's `PayloadId` so a report for a different
payload is rejected. `Payload` is not `Clone`; ownership moves forward once.

See `ctp-core/src/payload.rs`.

## Consequences

- Pipeline order and completeness become compile-time invariants: code that
  tries to release unvetted bytes does not compile, and a report/payload
  mismatch is a typed `TrustViolation`.
- The intent is legible in the signatures: `challenge` returns `Challenged`,
  `guard` returns `Vetted`.
- **Negative:** it only defends against accident, not intent. Code in the same
  process can read `Payload::bytes()` directly or call the inner tool without
  the wrapper, bypassing the typestate entirely (see ADR 0009). The guarantee
  is real but narrow, and easy to overstate.
- **Negative:** it adds friction. Embedding code must thread the typed payloads
  through, and the encapsulation that makes it sound (ADR 0009) removed the
  more convenient `scan() -> Report` API, forcing a refactor of Layer 1.
