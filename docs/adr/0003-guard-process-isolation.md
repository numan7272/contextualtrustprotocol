# 0003 — Guard runs as a separate, sandboxed process over UDS

**Status:** Accepted

## Context

The guard parses attacker-influenced payloads with a language model — a real
attack surface. If the guard is compromised through it, the blast radius must
be contained. An in-process guard (a library call) would share the
orchestrator's memory, network, and privileges: a compromised guard would be a
compromised agent.

## Decision

The guard is a standalone binary (`ctp-guard`) reachable only over a Unix
domain socket, run under a systemd unit (`deploy/ctp-guard.service`) that
enforces the containment: `PrivateNetwork=yes` and
`RestrictAddressFamilies=AF_UNIX` (the "air gap" — no network namespace, so a
compromised guard cannot exfiltrate), `ReadOnlyPaths=/` with a single writable
`RuntimeDirectory` for the socket, `MemoryMax`/`TasksMax` against
payload-driven DoS, `DynamicUser`, `NoNewPrivileges`, `MemoryDenyWriteExecute`,
and a watchdog. The socket is `chmod 0600`. The guard holds no execution power
and no cross-request state.

This is also the *real* boundary against a deliberate in-process bypass that
the typestate (ADR 0001) cannot provide.

## Consequences

- A compromised guard owns nothing on disk, has no network to phone home, and
  is killed and restarted if it wedges. This is why Layer 2 can be trusted with
  raw bytes (ADR 0004).
- The isolation is enforced by systemd, not by config or by the guard's own
  code, so it holds even if the guard is fully subverted.
- **Negative:** it trusts the host OS and kernel completely. If the kernel, the
  systemd sandbox, or the UDS layer is subverted, the air gap is gone. There is
  no hardware root of trust; TEE/TPM is future work.
- **Negative:** a per-request gRPC round trip over a socket is slower than an
  in-process call, which matters against the guard's latency budget.
- **Negative (deviation):** the watchdog requires the guard to send `sd_notify`
  pings, now wired, but **not exercised under real systemd** in this build. The
  watchdog is also coarse — it detects a wedged *process*, not a single hung
  request (that is the client timeout's job, ADR 0007).
