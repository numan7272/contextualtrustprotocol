# Benchmark: 2026-06, GPU (Vulkan), Qwen2.5-3B-Instruct guard

Companion to [`2026-06-cpu-qwen.md`](2026-06-cpu-qwen.md). Real-model
measurements of the guard (Layer 2) on a GPU via the Vulkan backend, taken
through CTP's actual prompt path. Recorded verbatim; the analysis says what it
means without softening it.

## Setup

| | |
|---|---|
| GPU | AMD Radeon RX 7800 XT |
| Backend | llama.cpp Vulkan, AMD proprietary Windows driver, `KHR_coopmat` active |
| Model | Qwen2.5-3B-Instruct Q4_K_M |
| llama.cpp | b9620 |
| Sampling | greedy (`--temp 0`), `-c 4096`, fresh context per run, with warmup |
| Harness | `llama-completion -no-cnv` with the real `guard_system_v1.txt` and `verdict.gbnf` |

The harness matters. This is not a generic prompt. It feeds the guard the same
raw system prompt and GBNF grammar CTP uses in production, with `AddBos` and no
chat template, so the numbers are CTP's real Layer-2 path, not a friendlier
approximation.

## Measurements

Two data points, guard in isolation (the model's own verdict).

| Payload | Verdict | flags | conf | Prompt tok | Prompt eval | Gen eval | Sampling | Total |
|---|---|---|---:|---:|---:|---:|---:|---:|
| Injection (DAN, instruction override) | BLOCK | `intent_shift` | 0.99 | 774 | 285 ms (2714 t/s) | 147 ms / 18 tok (122 t/s) | 47 ms | **497 ms** |
| Benign ("Please summarize this document for me") | PASS | (none) | 0.00 | 767 | 305 ms (2515 t/s) | 140 ms / 17 tok (121 t/s) | 67 ms | **529 ms** |

## Analysis

**1. Both verdicts are correct, with the real prompt.** The injection is
blocked, the benign request passes, and there is no false positive. This is the
3B reading CTP's actual system prompt and grammar, not a toy setup, so it is
direct evidence that the Layer-2 path produces the right call on these two
cases.

**2. Latency is about 500 ms per verdict, right at the inline budget.** On CPU
the same class of verdict took several seconds (see the companion file); the GPU
brings the 3B down to roughly half a second. That is the difference between
"not viable inline" and "viable, but tight." The kernel checks both directions
of a tool call, so a full round trip is closer to 1 s of added latency, which an
integrator must still budget for. The GPU makes the 3B usable inline; it does
not make the guard free.

**3. Prompt eval dominates (~57%).** Of the 497 ms injection run, 285 ms is
prompt evaluation and only 147 ms is generation. The cause is structural: the
static system prompt is about 750 tokens, and with a fresh context per request
and no KV reuse it is prefilled from scratch every single call. The model is
spending more than half its time re-reading the same instructions it read last
time.

**4. The obvious optimization: prefix-cache the static system prompt.** The
system prompt never changes between requests; only the ~20 payload tokens do. If
the prompt's KV cache is kept and reused, prompt eval drops from ~290 ms to on
the order of 10 ms (just the new payload tokens), which would put total latency
around 230 ms instead of ~500 ms. This is future work and the single highest-
value latency lever after moving to GPU. It needs a persistent context or a
saved KV state in the guard rather than a fresh context per `infer`.

**5. Grammar overhead is visible in sampling.** Sampling was 47 ms over 18
tokens (about 2.6 ms/token) on the injection run and 67 ms over 17 tokens
(about 3.9 ms/token) on the benign run. The GBNF mask applied at each decode
step is a real, non-trivial per-token cost. It is the price of guaranteeing the
output is a valid verdict and not prose, and at these token counts it is small
in absolute terms, but it is not zero.

**6. Confidence is noise; rely only on the verdict.** The two correct verdicts
came back with confidence 0.00 (benign) and 0.99 (injection). That spread looks
meaningful but is not: the value swings with prompt framing and is not
calibrated. This is exactly why the architecture keeps `flags` and `confidence`
out of the decision path. Only `verdict` decides. See
[ADR-0013](../adr/0013-flags-are-non-decisional.md).

**7. Caveat on the CPU-vs-GPU comparison.** There is no exact total-time
speedup factor here, because the CPU measurement used a shorter prompt than this
GPU run, so the totals are not directly comparable. The clean comparison is
generation throughput, which is prompt-length independent: roughly 23 tokens/s
on CPU versus about 122 tokens/s here, close to a 5x improvement.

## Why this ran on native Windows

WSL2 does not pass the AMD GPU through to Vulkan. Inside WSL2 the only Vulkan
device is `llvmpipe` (software rasterization on the CPU), because Mesa 23.2 is
present without the Dozen (Vulkan-on-D3D12) layer. Getting real GPU inference
therefore requires native Windows Vulkan or a bare-metal Linux install with the
AMD driver. The CTP code is unchanged across these; only the host and driver
differ.
