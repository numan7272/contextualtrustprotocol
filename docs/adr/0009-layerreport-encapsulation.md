# 0009 — Crate-private report construction

**Status:** Accepted

## Context

The typestate (ADR 0001) promotes a payload by presenting a passing
`LayerReport`. In the original design `LayerReport::new` was public, which left
a hole: any code could construct an empty-findings (= PASS) report and promote
an unscanned payload, skipping a layer. The Step-3 audit flagged this; Step 6
was the point to close it.

The constraint is a cross-crate one: a type can only be made unconstructible
outside the crate that defines it, but the challenge layer lives in a different
crate (`ctp-challenge`) from the report (`ctp-core`).

## Decision

Move report construction into `ctp-core` and drive it from scanner traits the
layers implement. `LayerReport::new` and the `into_challenged` / `into_vetted`
promotions are `pub(crate)`. The only public paths to a `Challenged` / `Vetted`
payload are `Payload::challenge(&dyn ChallengeScanner)` and
`Payload::guard(&dyn GuardScanner)`, which run the real scanner and build the
bound report internally. The layers (e.g. `ChallengeLayer`) now return *findings*
via a trait, never a report.

See `ctp-core/src/payload.rs`, `ctp-core/src/verdict.rs`,
`ctp-core/src/traits.rs`.

## Consequences

- A `LayerReport` cannot be fabricated to forge a passing verdict; promotion
  necessarily runs a scanner.
- Report construction is centralized and consistent across layers.
- **Negative:** this prevents *accidental* miswiring, not *deliberate* bypass.
  Code in the same process can still read the bytes directly or call the inner
  tool without the wrapper. The honest boundary against intent is the guard's
  process isolation (ADR 0003), not this encapsulation. Documented as such in
  the code.
- **Negative:** it forced an API change — `ChallengeLayer::scan() -> LayerReport`
  became `challenge_findings() -> Vec<Finding>` — and a refactor of Layer 1's
  tests and the latency harness. Embedders lose the convenient direct-scan API.
