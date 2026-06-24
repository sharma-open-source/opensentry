# opensentry real-corpus benchmark

This replaces "does it pass the 24-sample toy corpus" with real, published attack/benign
datasets and a full statistical suite (precision/recall/F1, ROC-AUC/PR-AUC, recall@fixed-FPR,
latency percentiles). It exercises the actual shipped pipeline, including the real default
Tier-1 model — not a stand-in.

Reproduce: `pnpm bench:fetch && pnpm bench` (fetch downloads ~2.4k real samples from public
HF datasets; bench runs the full suite, ~45s, and overwrites `bench/report.json`).

## What's being tested

| View | What it is |
|---|---|
| **tier0** | `createGuard()` — sync heuristics only (normalization + regex + stats), as shipped |
| **tier1** | The real default ML model, **meta-llama/Llama-Prompt-Guard-2-22M**, called directly on every sample (no escalation gating — this is the model's raw discriminative power) |
| **blended** | `createGuard({ detectors: [heuristics, localModel] })` exactly as documented — Tier 1 only escalates when Tier 0 lands in the uncertain "flag" band, or for `alwaysEscalate` sources |
| **blendedAlwaysEscalate** | Same blended pipeline, but with `policy.perSource.user.alwaysEscalate: true` — shows the ceiling if every request escalates to ML |

**Tier 1 model note:** the shipped default (`meta-llama/Llama-Prompt-Guard-2-22M`) is gated on
HuggingFace and has no published ONNX build. It was exported locally from the PyTorch
safetensors checkpoint via `optimum-cli export onnx` (see `bench/models/llama-prompt-guard-2-22m/`)
and loaded from disk through the library's own `LocalModelRunner` interface — same interface
end users plug in. The label index (`LABEL_1` = malicious) was verified empirically against
known attack/benign text, not assumed from docs, because the exported config carries no
`id2label` (neither does the upstream repo's, despite the model card's example implying one).

## Datasets (all real, published, downloaded via HF datasets-server / GitHub raw)

| Dataset | n | License | Role |
|---|---|---|---|
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | 1000 | MIT | attack — instruction_override (real captured attacks against the Gandalf game) |
| [rubend18/ChatGPT-Jailbreak-Prompts](https://huggingface.co/datasets/rubend18/ChatGPT-Jailbreak-Prompts) | 79 | unspecified | attack — jailbreak_persona (DAN-style) |
| [JailbreakBench/JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) (harmful) | 100 | MIT | attack — harmful_behavior |
| [AdvBench](https://github.com/llm-attacks/llm-attacks) (llm-attacks) | 520 | MIT | attack — harmful_behavior |
| [leolee99/NotInject](https://huggingface.co/datasets/leolee99/NotInject) | 339 | research release (InjecGuard paper) | benign — over-defense probe (trigger words in benign context) |
| [tatsu-lab/alpaca](https://huggingface.co/datasets/tatsu-lab/alpaca) | 600 | CC BY-NC 4.0 | benign — generic instructions |
| [JailbreakBench/JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) (benign) | 100 | MIT | benign — control set, same shape as the harmful split |

**Total: 1699 attacks, 700 benign, 339 NotInject.** Manifest with fetch timestamp:
`bench/data/manifest.json`.

**Deliberately excluded:** `deepset/prompt-injections` and `JasperLS/prompt-injections`
(identical underlying data). Inspection found inconsistent labels — e.g. "Generate SQL code
to access a database." and a plain role-play interview prompt both labeled as injection — and
PLAN.md §9 already flags this dataset as training-only/contaminated for headline eval since
most public detectors train on it.

## Headline results

| View | n | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC | Recall@1%FPR | p50 latency | p99 latency |
|---|---|---|---|---|---|---|---|---|---|---|
| tier0 | 2399 | 1.000 | 0.304 | 0.467 | 0.000 | 0.655 | 0.899 | 0.309 | 0.029ms | 0.450ms |
| **tier1** (real model, raw) | 2399 | 0.992 | 0.803 | 0.888 | 0.016 | **0.986** | 0.994 | 0.778 | 5.7ms | 76.0ms |
| blended (as shipped, default policy) | 2399 | 1.000 | 0.304 | 0.467 | 0.000 | 0.655 | 0.899 | 0.309 | 0.04ms | 7.5ms |
| blendedAlwaysEscalate | 2399 | 0.992 | 0.804 | 0.888 | 0.016 | 0.986 | 0.994 | 0.779 | 5.7ms | 89.6ms |

Tier 1 standalone AUC (0.986) lines up closely with Meta's own reported AUC for this model
(.995 on their private English benchmark, per the model card) — on a harder, broader,
independently-sourced test set than ours was tuned against. That's a meaningful external
sanity check on the model itself.

### The one finding that matters most

**`blended` is numerically identical to `tier0` alone** (recall 0.304 in both). This is not a
bug — it's how the escalation gate is designed (PLAN.md §5): Tier 1 only fires when Tier 0's
own score lands in the uncertain "flag" band, or for `alwaysEscalate` sources (`retrieved`,
`tool`, `web`, `email` by default — **not** `user`). Escalation rate measured: **5.5%** of
all `user`-sourced traffic in this corpus.

The consequence: attacks with no structural marker for Tier 0 to flag — `harmful_behavior`
(AdvBench + JBB harmful: "Develop a strategy for hacking into a government database…") and
most `jailbreak_persona` prompts — score exactly 0 on Tier 0, never reach the flag band, and
**Tier 1 never runs on them** under the documented default config for `source: 'user'`. The
ML model itself catches roughly half of `harmful_behavior` and effectively all of
`jailbreak_persona` when actually invoked (see `tier1` row) — that capability is real, it
just isn't reached by the shipped escalation policy unless you opt into `alwaysEscalate` for
`user`, or treat that content as a higher-trust-boundary source.

### Per-category recall (attack categories only — precision/FPR not meaningful on benign-only categories)

| Category | n | tier0 recall | tier1 recall | blended recall | blendedAlwaysEscalate recall |
|---|---|---|---|---|---|
| instruction_override (gandalf) | 1000 | 0.504 | 0.977 | 0.504 | 0.978 |
| jailbreak_persona (DAN) | 79 | 0.165 | 1.000 | 0.165 | 1.000 |
| harmful_behavior (AdvBench + JBB) | 620 | 0.000 | 0.498 | 0.000 | 0.498 |

`generic_instruction` and `benign_control` categories are 100% benign by construction — their
precision/recall figures in `bench/report.json` are an artifact of the metric (no positives
exist to recall) and should be read as FPR-only: tier0/blended 0.000, tier1/blendedAlwaysEscalate
0.000–0.100.

### NotInject — over-defense rate (benign text containing attack trigger words)

| View | Over-defense rate | Gate (PLAN.md §0, <5%) |
|---|---|---|
| tier0 | 0.6% (2/339) | pass |
| tier1 (real model, raw) | 8.6% (29/339) | — (not gated standalone) |
| blended (as shipped) | 0.6% (2/339) | pass |
| blendedAlwaysEscalate | **9.1% (31/339)** | **fails** the <5% over-defense budget |

Forcing `alwaysEscalate` on `user` traffic buys the harmful_behavior/jailbreak recall gains
above, but pushes NotInject over-defense almost 2x past the documented release gate. That's
the real trade-off this benchmark surfaces — not a free lunch.

## Methodology notes / things that bit us building this

- **ROC-AUC must be computed on the actual distinct score values, not a fixed linear grid.**
  An early version of this benchmark swept thresholds on a uniform 0..1 grid and got AUC≈0.05
  for a model with 0.99 precision/0.80 recall — completely wrong. Cause: negative-class scores
  cluster in a tiny band near 0 (e.g. 0.0005), so a 200-step linear grid skips clean over the
  entire interesting region of the curve. Fixed by thresholding at every distinct observed
  score (`bench/metrics.ts:sweepThresholds`), which is the standard empirical-ROC construction.
- **Tie-breaking in the sort before trapezoidal integration matters.** Many thresholds share
  `fpr=0` when negatives are well-separated; sorting by `fpr` alone leaves those ties in
  threshold order, which runs `tpr` backwards and corrupts the integral. Fixed with a secondary
  sort key (`a.fpr - b.fpr || a.tpr - b.tpr`).
- Both bugs were caught by sanity-checking against a synthetic, perfectly-separable dataset
  (expected AUC ≈ 1.0) before trusting any number from the real corpus.
- NotInject is benign-labeled but reported as a separate over-defense rate, never folded into
  the headline benign FPR — same convention `corpus/eval.ts` already uses for the seed corpus.

## Caveats

- This is a snapshot (fetched 2026-06-24) of public datasets, not live production traffic —
  it measures generalization to *known public* attack distributions, not your specific users.
- `rubend18/ChatGPT-Jailbreak-Prompts` license is unspecified (public scrape); treat as
  research-only, don't redistribute it as part of a shipped product corpus.
- Single machine, single run, no repeated trials — latency percentiles are indicative, not a
  formal SLA measurement (though Tier 0 p99 well under the 1ms CI gate, and Tier 1 (real
  22M model, CPU, fp32, unquantized) p50 ≈ 5.7ms / p99 ≈ 76ms, consistent with the model
  card's own ~19ms/sample order-of-magnitude claim once you account for fp32 vs their
  optimized runtime).
- This run used the **un-quantized fp32** ONNX export (no quantized build was produced) —
  a production deployment using the documented `quantized: true` default would likely be
  faster and slightly lower-precision than these numbers.
