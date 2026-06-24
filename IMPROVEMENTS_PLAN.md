# Plan: close the benchmark-identified gaps in opensentry's tiered pipeline

## Context

`bench/REPORT.md` (real-corpus benchmark, 1699 attacks / 700 benign / 339 NotInject, real
shipped Tier-1 model) found that the documented "Tier 0 fast-path, Tier 1 escalates for
semantic attacks" design doesn't hold for `source: 'user'` traffic: the blended pipeline
scores identically to Tier 0 alone (30% recall) because Tier 1 only fires when Tier 0's own
score already lands in the uncertain "flag" band, and `user` is the one source that doesn't
default to `alwaysEscalate`. Harmful-intent/jailbreak text (AdvBench, JBB-harmful, DAN-style
prompts) scores exactly 0 on Tier 0 — no structural marker to flag — so it never reaches the
model that could catch ~50–100% of it. Forcing escalation recovers that recall but pushes
NotInject over-defense to 9.1%, above the project's own <5% gate, because the global flag/block
thresholds aren't calibrated for ML-only evidence. Four concrete, benchmark-backed fixes:

## 1. Fix the user-source escalation gap (default change)

**Change:** `src/config.ts` `DEFAULT_PER_SOURCE.user` from `{ alwaysEscalate: false }` to
`{ alwaysEscalate: true }` — matching every other non-system source. This only changes
behavior once a `localModel`/`remoteGuard`/`embeddingCorpus` detector is configured (Tier
0-only zero-config path is untouched, since `maybeEscalateToMl`/etc. are only invoked when
those detectors exist — see `src/guard.ts:544-563`).

**Also touch:**
- `README.md` — update the "How it works" escalation-gate bullet list (Tier 1 + Tier 2
  sections) to reflect the new default, and the zero-config vs. Tier-1 example blocks.
- Add a short note to a new `CHANGELOG.md` (or top of README if no changelog exists yet)
  flagging this as a deliberate, benchmark-backed default behavior change: existing
  integrators who configured Tier 1 expecting rare escalation on `user` will see escalation
  rate jump from ~5% to ~100% of `user` traffic. Document the latency consequence (Tier-1
  p50 ~5ms unquantized per bench/REPORT.md) and how to opt back out
  (`policy.perSource.user.alwaysEscalate: false`).

**Verification:** re-run `pnpm bench` — `blended` row should match `blendedAlwaysEscalate`
row going forward (since that's now the default path). Re-run `pnpm test` + `pnpm eval` to
confirm the seed-corpus CI gates still pass (they should — Tier 0 behavior is unchanged,
this only affects whether Tier 1 is configured, which the seed eval doesn't do).

## 2. Calibrate Tier-1 evidence against its own score distribution

**Problem:** `aggregateScore` (`src/scoring.ts`) folds the ML score into noisy-OR using the
*same* global `thresholds.flag`/`thresholds.block` (0.4/0.85) that Tier 0's structural score
was tuned against. The benchmark's `recallAtFpr1pct` for the real model lands at threshold
≈0.59 — well above the 0.4 flag bar — meaning the model's own moderate-confidence scores
(0.4–0.59) are good enough to pass Tier 0's bar but aren't yet reliable for *this* model on
NotInject-style hard negatives. Globally raising `thresholds.flag` would also blunt Tier 0's
own (currently precise) decisions, so the fix needs to be per-detector, not global.

**Change:** add an optional `minConfidence?: number` (default `0`, fully backward compatible)
to `LocalModelDetector` in `src/types.ts`. In `src/guard.ts` `maybeEscalateToMl`, before
building the `ml_classifier` Reason, zero out scores below the configured floor:
`const effectiveScore = mlResult.score < (detector.minConfidence ?? 0) ? 0 : mlResult.score;`
— so an operator can raise the bar for what counts as ML evidence without touching Tier 0's
semantics. Mirror the same knob shape for `EmbeddingCorpusDetector` if the embedding-ensemble
ships a similar over-defense pattern (check, don't assume — not yet benchmarked).

**Explicitly do not hardcode a "recommended" value in the library** — 0.59 is specific to
*this run's* fp32, unquantized, locally-exported model; a different export, a quantized
build, or a fine-tuned model will calibrate differently. Instead: document in
`bench/REPORT.md` and the README how to derive `minConfidence` from your own
`recallAtFpr1pct` (or whatever budget you're targeting) using `bench/metrics.ts`'s existing
`recallAtFpr` sweep.

**Verification:** add a unit test in `tests/l3.test.ts` or a new `tests/ml-confidence.test.ts`
using a stub `LocalModelRunner` (pattern already used in `tests/ml.test.ts`) asserting a
sub-threshold ML score doesn't move the verdict. Re-run `pnpm bench` with `minConfidence`
set to the measured 0.59 calibration point and confirm NotInject over-defense drops back
toward the Tier-0-only baseline (0.6%) while `harmful_behavior`/`jailbreak_persona` recall
stays close to the uncalibrated numbers (since real attacks mostly score well above 0.59).

## 3. Verify/fix the quantized model path, re-benchmark

**Problem:** `src/onnx/index.ts` defaults `quantized: true` and asks transformers.js for a
quantized variant — but for a manually-exported gated model (no upstream quantized build),
this may silently fail to find one or fall back to fp32 without the consumer knowing.
Currently unverified; this run only used the fp32 export (`bench/models/llama-prompt-guard-2-22m/`).

**Change:**
1. Produce an int8 quantized export alongside the existing fp32 one — either
   `optimum-cli export onnx ... --optimize O3` or `onnxruntime.quantization.quantize_dynamic`
   on the existing `model.onnx`, saved as `model_quantized.onnx` in the same `onnx/`
   subdirectory (the filename transformers.js looks for when `quantized: true`/`dtype: 'q8'`
   is requested).
2. Add a `dtype: 'q8'` option to `bench/real-runner.ts`'s pipeline call (transformers.js v3+
   convention; `quantized` boolean is deprecated) and add a second bench view —
   `tier1Quantized` — alongside the existing `tier0`/`tier1`/`blended` views in
   `bench/run.bench-test.ts`.
3. If `src/onnx/index.ts`'s `quantized` option turns out not to resolve correctly against a
   locally-exported model layout, file it as a documented limitation (custom-runner escape
   hatch already exists) rather than papering over it.

**Verification:** re-run `pnpm bench`, compare `tier1` vs `tier1Quantized` rows for
precision/recall/F1/AUC delta and p50/p99 latency delta. Update `bench/REPORT.md` and the
README's Performance section with both numbers — don't overwrite the fp32 numbers, show both
so the accuracy/latency trade-off is visible.

## 4. Recurring, slightly-broader benchmark coverage

Lower-cost, mostly process + corpus additions rather than library code changes:

- **Multilingual slice, no new fetch needed:** `leolee99/NotInject` (already fetched into
  `bench/data/notinject.json`) carries a `category` field including `"Multilingual"` —
  `bench/run.bench-test.ts` already groups NotInject results by category
  (`notinjectViews` → could add the same `groupBy` treatment already used for `perCategory`
  on attacks/benign). Surface a `notInjectOverDefense` breakdown by category in the report so
  the Multilingual slice's over-defense rate is visible on its own, not averaged in.
- **86M model comparison (optional, higher cost):** repeat the `optimum-cli export onnx`
  step for `meta-llama/Llama-Prompt-Guard-2-86M` (same gated-access token, same export
  command, different model id) and add it as a `tier1_86m` view, to quantify whether the
  86M model's claimed multilingual AUC advantage (per its model card) shows up on our
  NotInject Multilingual slice specifically.
- **Process, not code:** document a recommended cadence (e.g. re-run `pnpm bench` before
  each release, or on a schedule) and snapshot `bench/report.json` into a
  `bench/history/<date>.json` on each run so regressions are visible over time — a simple
  `cp bench/report.json bench/history/$(date +%F).json` step is enough, no new tooling needed.

**Verification:** re-run `pnpm bench`, confirm the new per-category NotInject breakdown
appears in `bench/report.json` and is reflected in `bench/REPORT.md`'s over-defense table.

## Suggested order

1 (escalation default) and 2 (confidence floor) are paired — shipping 1 alone without 2 is
what already measured as a regression (9.1% NotInject over-defense) in this session's
benchmark, so they should land together. 3 (quantization) and 4 (broader coverage) are
independent follow-ups that can land separately.

## Out of scope (flagged, not silently dropped)

- A dedicated "harmful intent without injection framing" heuristic detector was considered
  and rejected for the plan: per PLAN.md's own threat model, jailbreak/harmful-content
  detection without structural injection markers is explicitly Tier 1's job, not Tier 0's —
  adding broad harmful-keyword regex to Tier 0 would reintroduce exactly the NotInject
  over-defense risk the project's design principles (PLAN.md §4) were written to avoid.
