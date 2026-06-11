//! # ctp-challenge
//!
//! CTP Layer 1: static heuristic scanner. Runs on every payload BEFORE any
//! LLM contact. Pure CPU, no I/O, no async; target <2ms p99 for payloads
//! up to 32 KiB.
//!
//! Rules are small, independent units behind the `ctp_core::traits::Rule`
//! trait, composed at runtime into a [`registry::ChallengeLayer`]. New
//! pattern rules are added via configuration (data-driven), not recompiles.

pub mod registry;
pub mod rules;

pub use registry::ChallengeLayer;
pub use rules::data_driven::DataDrivenRegexRule;
pub use rules::encoding::{EncodingBypassRule, EncodingLimits};
pub use rules::homoglyph::UnicodeHomoglyphRule;
