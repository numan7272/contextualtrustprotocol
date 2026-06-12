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
  (`llama-cpp-2`, feature `llama`) builds llama.cpp natively and is not part of
  the default hermetic suite. Exercising it surfaced two classes of defect that
  the mock and the in-tree acceptor could not:
  - *Compile-time:* `LlamaSampler::grammar` returns a `Result` that was chained
    as if infallible (the first real compile caught it); fixed fail-closed.
  - *Run-time:* against a real model on CPU, the guard hard-aborted inside
    llama.cpp — `GGML_ASSERT(!stacks.empty())`. The real cause was an
    integration bug, **not** the grammar: in this llama.cpp, `llama_sampler_
    sample` accepts the token internally (it calls `llama_sampler_accept`), so
    the decode loop's *additional* explicit `accept` advanced the grammar twice
    per token, ran its parse stacks off the end, and the next apply asserted.
    Fixed by removing the redundant accept. The grammar file itself is valid —
    verified standalone in `llama-cli` with the same model.
  - *Two wrong diagnoses first.* Before finding the double-accept, the crash
    was misattributed (from reading the source) to EOG-into-grammar and to
    `?`/`*`/`+`/`()` operator desugaring; neither was the cause. The grammar was
    rewritten to operator-free right-recursive form anyway (same language, kept
    because it is the form since verified in `llama-cli`). The lesson is in the
    next bullet.
- **Negative (scope of the acceptor, and of source-reading):** the in-tree NFA
  acceptor proves *language membership* — prose is not a sentence of the
  grammar. It does **not** model llama.cpp's stateful sampler, and reading the
  library source produced two confident-but-wrong root causes. What actually
  located the bug was empirical isolation (the same grammar in `llama-cli`).
  "The acceptor passed" and "I traced the source" are both weaker than "it ran";
  only the offline acceptor is in the suite, and it cannot catch integration
  bugs like this one.
- The double-accept fix is confirmed against the symptom mechanistically and
  compile-verified, but has **not** itself been re-run against a real model in
  this repository — that re-test is the project owner's.
