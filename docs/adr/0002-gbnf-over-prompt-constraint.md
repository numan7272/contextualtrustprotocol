# 0002 — GBNF-constrained decoding, not prompt-asked output

**Status:** Accepted

## Context

The guard model must return a binary verdict and nothing else. Asking for that
in the system prompt ("reply only with JSON") is exactly the kind of
instruction a model can be talked out of — the same weakness CTP assumes about
the main model. If the guard can be induced to emit prose, an attacker can
smuggle an instruction or a fake "PASS" through Layer 2's output channel.

## Decision

Constrain the decoder, not the prompt. A GBNF grammar (`ctp-guard/grammar/
verdict.gbnf`) masks the sampler each step so only tokens that keep the output
on a path to a complete verdict JSON are reachable. Prose is not a sampleable
sequence. The guard additionally re-validates the output with a strict parser
(ADR 0007 / `parse.rs`): it does not even trust its own constrained model.

The grammar's exclusion property is tested against the *shipped* `.gbnf` by an
in-tree NFA acceptor that proves prose, markdown, and off-contract JSON are not
in the language.

## Consequences

- The output channel is bounded physically, not by request. A verdict cannot
  carry an explanation, an injected instruction, or "PASS, trust me."
- The grammar file is a security artifact: the same file feeds the decoder and
  the acceptor, so the test and the runtime cannot drift.
- **Negative:** GBNF guarantees the *form* of the output, never the
  *correctness* of the judgment. A constrained small model can still emit a
  confidently wrong `PASS`. Constrained decoding solves smuggling, not accuracy.
- **Negative (deviation):** the backend that actually applies the grammar
  (`llama-cpp-2`, feature `llama`) is **never compiled or run by the test
  suite** — it builds llama.cpp natively. The grammar-application code is
  written against the documented API and is unverified against a real model.
  Every tested path uses a deterministic keyword-matching mock.
