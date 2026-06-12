# 0006 — Multi-turn anomaly score with decay and a floor

**Status:** Accepted

## Context

Some attacks never trip a single turn: one borderline-but-passing payload per
turn, accumulating influence. A per-turn check cannot see them. A cumulative
score across turns can — but a naive cumulative score punishes long, benign
sessions for ancient history, so it needs decay. And decay, on its own, is a
self-bypass: raise one flag, wait out the decay until the score is ~0, then
attack from a clean slate.

## Decision

`AnomalyLedger` keeps a per-session score. Each turn: decay first
(`score *= decay`), then add this turn's advisory-flag contribution. Crossing a
threshold blocks the session. Critically, once a session has *ever* raised a
flag, decay cannot push the score below a configured **floor**
(`score = (score * decay).max(floor)`). The floor is residual suspicion: a
later attack resumes from a non-zero base instead of zero. `anomaly_floor` is
config-validated to `[0, threshold)`.

See `ctp-kernel/src/ledger.rs`; the self-bypass is proven by
`floor_prevents_decay_self_bypass`, which contrasts a floored and a floor-less
ledger.

## Consequences

- Slow-burn attacks that no single turn would block are caught.
- The floor closes the decay-as-self-bypass hole; a benign session that never
  flags is never penalized (the floor arms only after the first flag).
- **Negative:** the score is process-local and ephemeral. It does not survive a
  restart and does not correlate across sessions. An attacker who spreads one
  payload per session, or induces a restart, resets the score and bypasses
  multi-turn detection. The floor protects *within* a session, not across them.
- **Negative:** the floor and threshold are blunt scalar knobs with no
  principled calibration; set wrong, they either never fire or block too eagerly.
- **Negative:** under concurrent same-session tool calls the per-call decay is
  order-dependent (the mutex prevents lost updates, but the decay timing fuzzes).
