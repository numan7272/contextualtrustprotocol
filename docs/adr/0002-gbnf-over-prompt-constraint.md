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
  - *Run-time:* against a real model on CPU, the grammar tripped a hard C++
    abort inside llama.cpp — `GGML_ASSERT(!stacks.empty())`. Root causes, read
    from the bundled llama.cpp source: the decode loop fed the end-of-generation
    token to the grammar sampler (`accept_impl` `GGML_ABORT`s on EOG in a
    non-terminal state), and the grammar used `?`/`*`/`+`/`()` operators whose
    desugaring into synthesized rules is an init edge-case. Fixed by checking
    EOG before accept and rewriting the grammar in operator-free right-recursive
    form (same language).
- **Negative (scope of the acceptor):** the in-tree NFA acceptor proves
  *language membership* — that prose is not a sentence of the grammar. It does
  **not** model llama.cpp's stateful sampler (EOG handling, operator
  desugaring, tokenizer interaction), so it cannot catch a runtime abort like
  the one above. "The acceptor passed" and "llama.cpp runs it safely" are
  different claims; only the former is covered by the offline suite.
- Full runtime behavior against a real GGUF model is still being validated by
  the project owner; the fixes above are reasoned from the llama.cpp source and
  compile-verified, not yet proven crash-free end-to-end in this repository.
