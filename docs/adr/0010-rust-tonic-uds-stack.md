# 0010 — Rust + Tokio + tonic over Unix domain sockets

**Status:** Accepted

## Context

CTP sits in the per-tool-call hot path and aspires to act as an inference
kernel mediating all tool I/O. That demands memory safety without GC pauses,
strong compile-time guarantees (the typestate of ADR 0001 needs an expressive
type system), and a transport for the guard process boundary (ADR 0003).

## Decision

Rust, with Tokio for async and tonic (gRPC) for the inter-process contract,
carried over Unix domain sockets rather than TCP. Five-crate workspace:
`ctp-core` (types/traits), `ctp-challenge`, `ctp-guard`, `ctp-kernel`,
`ctp-orchestrator`. Dependencies are exact-pinned (`=`), the lockfile is
committed, the toolchain is pinned, and protobuf codegen is hermetic via a
vendored `protoc`. `unsafe_code` is denied workspace-wide.

UDS over TCP: the guard never needs the network (ADR 0003), a filesystem socket
can be permission-locked to the owner (0600), and it keeps Layer 2 off any
listening port.

## Consequences

- Memory safety with no GC, typestate enforcement, and a clean process boundary
  with an established RPC stack.
- Reproducible builds; `cargo test` runs hermetically with no network or model.
- **Negative:** Rust's strictness and the typestate impose real development
  friction and a steeper contribution barrier than a dynamic language would.
- **Negative:** UDS ties deployment to a single host — the guard and
  orchestrator must share a filesystem. A distributed deployment (guard on a
  separate node) would need a different, re-secured transport.
- **Negative:** the gRPC/tonic stack pulls a large dependency tree (hyper,
  tower, prost) into a security-sensitive component, enlarging the supply-chain
  surface that would need auditing.
