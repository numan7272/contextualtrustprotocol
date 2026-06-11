//! # ctp-core
//!
//! Foundation crate of the Contextual Trust Protocol (CTP): shared types,
//! traits and errors that every layer builds on.
//!
//! CTP treats the main reasoning LLM as an untrusted CPU. This crate encodes
//! the protocol's two structural invariants at the type level:
//!
//! 1. **Fail-closed by construction** — every error path in [`error`]
//!    collapses to a BLOCK decision; there is no fallible path to PASS.
//! 2. **Pipeline order as a compile-time invariant** — [`payload`] uses a
//!    typestate (`Tainted` → `Challenged` → `Vetted`) so that data which has
//!    not passed both verification layers cannot reach execution or model
//!    context. This is enforced by the type system, not by convention.

pub mod config;
pub mod error;
pub mod payload;
pub mod traits;
pub mod verdict;
