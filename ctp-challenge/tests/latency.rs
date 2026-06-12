#![allow(clippy::expect_used)] // test harness: a failed setup should panic
//! Latency smoke for the <2ms p99 @ 32KiB target.
//!
//! The fixture is deliberately heterogeneous — prose, JSON, URLs, hex
//! digests, UUIDs, multilingual text, emoji (ZWJ), and a decodable base64
//! chunk — so the measurement exercises the expensive code paths
//! (candidate extraction, one level of real decoding, per-char unicode
//! analysis, word segmentation) instead of skating over a homogeneous
//! happy path.
//!
//! The 2ms SLO is asserted in release builds (`cargo test --release`).
//! Debug builds are ~15x slower (unoptimized regex internals) and are NOT
//! the SLO target; they assert only a loose catastrophic-regression ceiling
//! so the default `cargo test` stays fast and non-flaky while still tripping
//! on a gross blowup.

use std::time::{Duration, Instant};

use ctp_challenge::ChallengeLayer;
use ctp_core::{
    ChallengeConfig, ChallengeScanner, FindingDisposition, RegexRuleSpec, RuleAction, Severity,
};

fn layer() -> ChallengeLayer {
    let config = ChallengeConfig {
        max_payload_bytes: 32 * 1024,
        rules: vec![
            RegexRuleSpec {
                id: "instruction_override_en".into(),
                pattern: r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions".into(),
                action: RuleAction::Block,
                severity: Severity::High,
                description: None,
            },
            RegexRuleSpec {
                id: "role_marker_forgery".into(),
                pattern: r"(?im)^\s*(system|assistant|developer)\s*:".into(),
                action: RuleAction::Flag,
                severity: Severity::Medium,
                description: None,
            },
        ],
    };
    ChallengeLayer::from_config(&config).expect("layer assembles")
}

/// Deterministic, realistic ~32KiB inbound tool result.
fn realistic_32kib() -> Vec<u8> {
    use base64::Engine;
    let encoded_attachment = base64::engine::general_purpose::STANDARD.encode(
        "attachment preview: quarterly figures attached as discussed, regards from the reporting team",
    );

    let mut out = String::new();
    let mut i = 0usize;
    while out.len() < 32 * 1024 {
        i += 1;
        out.push_str(&format!(
            "Entry {i}: The deployment completed without incident and the on-call engineer \
             confirmed dashboards stayed green throughout the rollout window.\n\
             {{\"id\":\"550e8400-e29b-41d4-a716-44665544{i:04}\",\
             \"sha256\":\"9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca1\",\
             \"url\":\"https://example.com/build/{i}/artifacts?page=2&per_page=50\"}}\n\
             Übersetzung verfügbar (仕様書を参照) — статус: одобрено.\n\
             Team reaction: 🎉 👨‍👩‍👧‍👦 shipped!\n\
             attachment: {encoded_attachment}\n\n"
        ));
    }
    out.truncate(32 * 1024);
    out.into_bytes()
}

#[test]
fn p99_latency_within_budget_at_32kib() {
    let layer = layer();
    let fixture = realistic_32kib();
    assert_eq!(fixture.len(), 32 * 1024, "fixture must actually be 32KiB");

    // The fixture must be representative of *scanned* traffic: it has to
    // survive scanning without blocking, or we are measuring the cost of
    // the wrong outcome.
    let probe = layer.challenge_findings(&fixture);
    assert!(
        !probe
            .iter()
            .any(|f| f.disposition == FindingDisposition::Blocking),
        "latency fixture must scan clean"
    );

    // The real SLO gate runs in release; debug just needs enough samples
    // for a stable tripwire without dominating `cargo test`.
    let (warmup, runs, budget) = if cfg!(debug_assertions) {
        (10usize, 80usize, Duration::from_millis(100))
    } else {
        (20usize, 300usize, Duration::from_millis(2))
    };

    for _ in 0..warmup {
        std::hint::black_box(layer.challenge_findings(&fixture));
    }

    let mut samples: Vec<Duration> = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        std::hint::black_box(layer.challenge_findings(&fixture));
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    let p99 = samples[(runs * 99).div_ceil(100) - 1];
    let p50 = samples[runs / 2];

    assert!(
        p99 <= budget,
        "challenge layer p99 {p99:?} exceeds {budget:?} (p50 {p50:?}, {runs} runs @ 32KiB)"
    );
    eprintln!(
        "challenge layer @32KiB: p50 {p50:?}, p99 {p99:?} (budget {budget:?}, {} build)",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
}
