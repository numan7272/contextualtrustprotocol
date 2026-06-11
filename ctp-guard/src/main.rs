//! # ctp-guard
//!
//! CTP Layer 2: the guard process. A separate OS binary, reachable only via
//! a Unix domain socket, with no network access (enforced by its systemd
//! unit). It holds classification power and ZERO execution power: its only
//! output channel is a GBNF-constrained verdict.

mod grammar;
mod inference;
mod parse;
mod server;

/// Generated gRPC bindings for `proto/guard.proto`.
#[allow(unused, clippy::all, clippy::pedantic, unsafe_code)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/ctp.guard.v1.rs"));
}

fn main() {
    // Wired up in Step 5: config load, backend init, UDS server.
}
