//! Per-session anomaly ledger: multi-turn context-poisoning defense.
//!
//! A session accumulates an anomaly score from the advisory flags raised on
//! each turn. The score crossing a threshold blocks the session even when no
//! single turn blocked on its own — the slow-burn attack that drips one
//! borderline payload per turn.
//!
//! Two forces shape the score:
//! * **Decay** — each turn multiplies the score by `decay ∈ (0, 1]`, so old
//!   anomalies fade and a long benign session is not punished for ancient
//!   history.
//! * **Floor** — once a session has *ever* raised an anomaly, decay cannot
//!   push its score below `floor`. Without the floor, an attacker raises one
//!   borderline flag, waits out a long benign stretch until decay erases it,
//!   and then attacks from a clean slate: the decay becomes a self-bypass.
//!   The floor leaves residual suspicion so a later attack resumes from a
//!   non-zero base. The floor is therefore not optional.

use std::collections::HashMap;
use std::sync::Mutex;

use ctp_core::KernelConfig;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct LedgerParams {
    /// Per-turn multiplicative decay, within `(0, 1]`.
    pub decay: f64,
    /// Lower bound decay cannot cross once a session is tainted.
    pub floor: f64,
    /// Score added per advisory flag.
    pub flag_weight: f64,
    /// Cumulative score at or above which the session is blocked.
    pub threshold: f64,
    /// Upper bound on tracked sessions; the least-recently-updated is evicted.
    pub max_sessions: usize,
}

impl LedgerParams {
    pub fn from_config(c: &KernelConfig) -> Self {
        LedgerParams {
            decay: c.anomaly_decay,
            floor: c.anomaly_floor,
            flag_weight: c.flag_weight,
            threshold: c.anomaly_threshold,
            max_sessions: c.max_sessions,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SessionState {
    score: f64,
    /// Whether this session has ever raised an anomaly. The floor only
    /// applies after the first flag — a wholly benign session stays at 0.
    tainted: bool,
    last_tick: u64,
}

/// Result of recording a turn.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LedgerOutcome {
    pub score: f64,
    pub blocked: bool,
}

struct Inner {
    sessions: HashMap<Uuid, SessionState>,
    tick: u64,
}

pub struct AnomalyLedger {
    params: LedgerParams,
    inner: Mutex<Inner>,
}

impl AnomalyLedger {
    pub fn new(params: LedgerParams) -> Self {
        AnomalyLedger {
            params,
            inner: Mutex::new(Inner {
                sessions: HashMap::new(),
                tick: 0,
            }),
        }
    }

    pub fn from_config(c: &KernelConfig) -> Self {
        Self::new(LedgerParams::from_config(c))
    }

    pub fn params(&self) -> LedgerParams {
        self.params
    }

    /// Record one turn's advisory-flag count for a session and return the
    /// updated cumulative score plus whether it crosses the block threshold.
    ///
    /// Order per turn: decay first (with floor if tainted), then add this
    /// turn's contribution. A turn that raises its first flag taints the
    /// session; the floor takes effect from the next turn on.
    pub fn record(&self, session_id: Uuid, new_flags: usize) -> LedgerOutcome {
        let p = self.params;
        // Recover from poisoning rather than propagate: a poisoned ledger
        // must still fail closed, and the contained state is just scores.
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.tick += 1;
        let tick = inner.tick;

        // Evict the least-recently-updated session if full and this is new.
        if !inner.sessions.contains_key(&session_id)
            && inner.sessions.len() >= p.max_sessions
            && let Some(oldest) = inner
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.last_tick)
                .map(|(id, _)| *id)
        {
            inner.sessions.remove(&oldest);
        }

        let state = inner.sessions.entry(session_id).or_insert(SessionState {
            score: 0.0,
            tainted: false,
            last_tick: tick,
        });

        // Decay. The floor applies only once the session is tainted.
        if state.tainted {
            state.score = (state.score * p.decay).max(p.floor);
        } else {
            state.score *= p.decay;
        }

        // This turn's contribution.
        if new_flags > 0 {
            state.score += new_flags as f64 * p.flag_weight;
            state.tainted = true;
        }
        state.last_tick = tick;

        LedgerOutcome {
            score: state.score,
            blocked: state.score >= p.threshold,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn params() -> LedgerParams {
        LedgerParams {
            decay: 0.5,
            floor: 0.5,
            flag_weight: 1.0,
            threshold: 1.2,
            max_sessions: 1000,
        }
    }

    #[test]
    fn benign_session_never_taints_or_blocks() {
        let ledger = AnomalyLedger::new(params());
        let sid = Uuid::new_v4();
        for _ in 0..100 {
            let out = ledger.record(sid, 0);
            assert_eq!(out.score, 0.0);
            assert!(!out.blocked);
        }
    }

    /// Auflage 2: the floor stops a long benign stretch from erasing
    /// residual suspicion, so a later attack still trips the threshold —
    /// proven by contrast with a floor-less ledger where the same attack
    /// slips through.
    #[test]
    fn floor_prevents_decay_self_bypass() {
        let sid = Uuid::new_v4();

        let with_floor = AnomalyLedger::new(params());
        let without_floor = AnomalyLedger::new(LedgerParams {
            floor: 0.0,
            ..params()
        });

        // Turn 1: a single borderline flag taints both sessions equally.
        assert_eq!(with_floor.record(sid, 1).score, 1.0);
        assert_eq!(without_floor.record(sid, 1).score, 1.0);

        // 50 benign turns. The floor holds the score at 0.5; without it the
        // score decays toward zero.
        for _ in 0..50 {
            with_floor.record(sid, 0);
            without_floor.record(sid, 0);
        }
        let held = with_floor.record(sid, 0);
        let decayed = without_floor.record(sid, 0);
        assert_eq!(held.score, 0.5, "floor must hold the score at the floor");
        assert!(
            decayed.score < 1e-6,
            "without a floor the score decays to ~0 ({})",
            decayed.score
        );

        // The later attack: one flag. WITH the floor it resumes from 0.5,
        // decays to 0.25, adds 1.0 → 1.25 ≥ 1.2 threshold → BLOCK. WITHOUT
        // the floor it starts from ~0, adds 1.0 → 1.0 < 1.2 → slips through.
        let blocked = with_floor.record(sid, 1);
        let bypassed = without_floor.record(sid, 1);
        assert!(
            blocked.blocked,
            "with floor the late attack must block (score {})",
            blocked.score
        );
        assert!(
            !bypassed.blocked,
            "without floor the late attack self-bypasses (score {})",
            bypassed.score
        );
    }

    #[test]
    fn accumulation_blocks_slow_burn() {
        let ledger = AnomalyLedger::new(params());
        let sid = Uuid::new_v4();
        // Two flags in one turn: 0 decayed + 2*1.0 = 2.0 ≥ 1.2 → block.
        let out = ledger.record(sid, 2);
        assert!(out.blocked);
    }

    #[test]
    fn sessions_are_independent() {
        let ledger = AnomalyLedger::new(params());
        let attacker = Uuid::new_v4();
        let bystander = Uuid::new_v4();
        ledger.record(attacker, 2);
        let other = ledger.record(bystander, 0);
        assert_eq!(other.score, 0.0);
        assert!(!other.blocked);
    }

    #[test]
    fn eviction_bounds_memory() {
        let ledger = AnomalyLedger::new(LedgerParams {
            max_sessions: 4,
            ..params()
        });
        for _ in 0..100 {
            ledger.record(Uuid::new_v4(), 1);
        }
        let inner = ledger.inner.lock().unwrap();
        assert!(
            inner.sessions.len() <= 4,
            "ledger must bound tracked sessions"
        );
    }
}
