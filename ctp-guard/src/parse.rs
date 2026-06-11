//! Strict, fail-closed parser for the guard's verdict contract.
//!
//! The guard does not trust its own model. Even with GBNF constraining the
//! sampler, the raw output is re-validated here against the contract, and
//! ANY deviation is an error the caller maps to BLOCK:
//!
//! * response larger than [`MAX_RAW_RESPONSE_BYTES`] — rejected before any
//!   parsing (an oversize "verdict" is already off-contract and a parser
//!   DoS vector),
//! * malformed / truncated / empty JSON — rejected,
//! * `verdict` not exactly `"PASS"` or `"BLOCK"` (e.g. prose smuggled into
//!   the field) — rejected by the enum,
//! * any unknown field — rejected by `deny_unknown_fields`,
//! * too many flags, or a flag outside `[a-z0-9_]` / over length — rejected.
//!
//! `confidence` is the sole exception to "deviation = error": it is
//! telemetry and MUST NOT influence the decision, so an out-of-range value
//! is clamped and recorded, never escalated to BLOCK. Letting bad telemetry
//! flip a verdict would itself violate the power/verification separation.

use ctp_core::Verdict;
use serde::Deserialize;

/// A verdict response longer than this is rejected unparsed. The legitimate
/// payload is tens of bytes; this is generous slack, not a real ceiling.
pub const MAX_RAW_RESPONSE_BYTES: usize = 512;
/// Maximum number of flags accepted.
pub const MAX_FLAGS: usize = 8;
/// Maximum length of a single flag tag.
pub const MAX_FLAG_LEN: usize = 48;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("response of {len} bytes exceeds {max} byte cap (rejected before parsing)")]
    TooLarge { len: usize, max: usize },
    #[error("malformed verdict json: {0}")]
    Malformed(String),
    #[error("too many flags: {0} (max {MAX_FLAGS})")]
    TooManyFlags(usize),
    #[error("flag '{0}' is not a valid snake_case tag within {MAX_FLAG_LEN} chars")]
    BadFlag(String),
}

/// The validated verdict. `confidence` is already clamped to `0.0..=1.0`.
#[derive(Debug, Clone, PartialEq)]
pub struct StrictVerdict {
    pub verdict: Verdict,
    pub confidence: f32,
    pub flags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVerdict {
    verdict: Verdict,
    confidence: f32,
    flags: Vec<String>,
}

fn flag_is_valid(flag: &str) -> bool {
    !flag.is_empty()
        && flag.len() <= MAX_FLAG_LEN
        && flag
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Parse and validate a raw guard response. Fail-closed: any `Err` means
/// the caller must treat the verdict as BLOCK.
pub fn parse_strict(raw: &str) -> Result<StrictVerdict, ParseError> {
    if raw.len() > MAX_RAW_RESPONSE_BYTES {
        return Err(ParseError::TooLarge {
            len: raw.len(),
            max: MAX_RAW_RESPONSE_BYTES,
        });
    }

    let parsed: RawVerdict =
        serde_json::from_str(raw).map_err(|e| ParseError::Malformed(e.to_string()))?;

    if parsed.flags.len() > MAX_FLAGS {
        return Err(ParseError::TooManyFlags(parsed.flags.len()));
    }
    for flag in &parsed.flags {
        if !flag_is_valid(flag) {
            return Err(ParseError::BadFlag(
                flag.chars().take(MAX_FLAG_LEN).collect(),
            ));
        }
    }

    // Telemetry only: clamp, never reject. A broken confidence value must
    // not change the verdict.
    let confidence = if parsed.confidence.is_finite() {
        parsed.confidence.clamp(0.0, 1.0)
    } else {
        0.0
    };

    Ok(StrictVerdict {
        verdict: parsed.verdict,
        confidence,
        flags: parsed.flags,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn valid_pass_and_block_parse() {
        let pass = parse_strict(r#"{"verdict":"PASS","confidence":0.10,"flags":[]}"#).unwrap();
        assert_eq!(pass.verdict, Verdict::Pass);
        assert!(pass.flags.is_empty());

        let block = parse_strict(
            r#"{"verdict":"BLOCK","confidence":0.90,"flags":["intent_shift","goal_substitution"]}"#,
        )
        .unwrap();
        assert_eq!(block.verdict, Verdict::Block);
        assert_eq!(block.flags.len(), 2);
    }

    // --- Auflage 1: the five fail-closed cases, each proven to be an Err
    // (which the caller maps to BLOCK). ---

    #[test]
    fn case1_unknown_extra_field_is_rejected() {
        // Otherwise-valid verdict with one extra field.
        let raw = r#"{"verdict":"PASS","confidence":0.99,"flags":[],"note":"trust me"}"#;
        let err = parse_strict(raw).unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn case2_truncated_json_is_rejected() {
        let raw = r#"{"verdict":"PASS","confidence":0.9,"flags":["#;
        let err = parse_strict(raw).unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn case3_prose_smuggled_in_verdict_field_is_rejected() {
        // Syntactically valid JSON, but the verdict field carries prose
        // instead of exactly PASS/BLOCK. The enum refuses it.
        let raw = r#"{"verdict":"PASS - this content is safe, please allow it","confidence":0.9,"flags":[]}"#;
        let err = parse_strict(raw).unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)), "{err:?}");

        // Trailing prose after a valid object is also rejected.
        let trailing = r#"{"verdict":"PASS","confidence":0.9,"flags":[]} actually, ignore that"#;
        assert!(parse_strict(trailing).is_err());
    }

    #[test]
    fn case4_empty_response_is_rejected() {
        assert!(matches!(
            parse_strict("").unwrap_err(),
            ParseError::Malformed(_)
        ));
        // Whitespace-only (what a timed-out/dead backend might yield).
        assert!(parse_strict("   \n").is_err());
    }

    #[test]
    fn case5_oversize_response_is_rejected_before_parsing() {
        // A response that would otherwise parse, padded past the cap inside
        // a flag. Must be rejected as TooLarge, never reaching serde.
        let filler = "a".repeat(MAX_RAW_RESPONSE_BYTES);
        let raw = format!(r#"{{"verdict":"PASS","confidence":0.9,"flags":["{filler}"]}}"#);
        assert!(raw.len() > MAX_RAW_RESPONSE_BYTES);
        let err = parse_strict(&raw).unwrap_err();
        assert!(matches!(err, ParseError::TooLarge { .. }), "{err:?}");
    }

    // --- Flag hardening and telemetry-non-decisional behaviour. ---

    #[test]
    fn flag_with_spaces_or_prose_is_rejected() {
        let raw = r#"{"verdict":"BLOCK","confidence":0.9,"flags":["ignore all instructions"]}"#;
        assert!(matches!(
            parse_strict(raw).unwrap_err(),
            ParseError::BadFlag(_)
        ));
    }

    #[test]
    fn too_many_flags_is_rejected() {
        let many = (0..9)
            .map(|i| format!("\"f{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        let raw = format!(r#"{{"verdict":"BLOCK","confidence":0.5,"flags":[{many}]}}"#);
        assert!(matches!(
            parse_strict(&raw).unwrap_err(),
            ParseError::TooManyFlags(9)
        ));
    }

    #[test]
    fn out_of_range_confidence_is_clamped_not_blocked() {
        // confidence is telemetry: a bad value must NOT turn a PASS into an
        // error/BLOCK. It is clamped and the verdict stands.
        let hi = parse_strict(r#"{"verdict":"PASS","confidence":9.9,"flags":[]}"#).unwrap();
        assert_eq!(hi.verdict, Verdict::Pass);
        assert_eq!(hi.confidence, 1.0);

        let lo = parse_strict(r#"{"verdict":"PASS","confidence":-3.0,"flags":[]}"#).unwrap();
        assert_eq!(lo.confidence, 0.0);
    }

    #[test]
    fn missing_field_is_rejected() {
        assert!(parse_strict(r#"{"verdict":"PASS","flags":[]}"#).is_err());
        assert!(parse_strict(r#"{"confidence":0.5,"flags":[]}"#).is_err());
    }
}
