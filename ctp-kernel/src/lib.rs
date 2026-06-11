//! # ctp-kernel
//!
//! CTP Layer 3: the kernel wrapper. Wraps every tool executor and vets BOTH
//! directions of tool I/O — outbound arguments before execution, inbound
//! results before they re-enter model context. Blocking is proactive: a
//! BLOCK from any layer prevents execution / context release entirely.
//!
//! Multi-turn context poisoning is tracked per session in [`ledger`]: an
//! anomaly score accumulates across turns (with decay) and blocks the
//! session once it crosses the configured threshold.

pub mod ledger;
