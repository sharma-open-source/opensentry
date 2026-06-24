# Changelog

## Unreleased

### Changed — breaking default behavior

- **`user` source now defaults to `alwaysEscalate: true`** (was `false`), matching every
  other non-`system` source (`retrieved`/`tool`/`web`/`email`). Only affects behavior when a
  `localModel`, `remoteGuard`, or `embeddingCorpus` detector is configured — the zero-config
  Tier-0-only path is unchanged.

  **Why:** [bench/REPORT.md](bench/REPORT.md) (real-corpus benchmark, 1699 real attacks)
  found that harmful-intent/jailbreak text with no structural marker (AdvBench, JBB-harmful,
  DAN-style prompts) scores exactly 0 on Tier 0 and never reached the uncertain "flag" band —
  so under the old default, Tier 1 never saw the dominant real-world attack channel
  (`user`) for that content, even though the model itself catches ~50–100% of it when
  actually invoked.

  **Impact if you have a `localModel`/`remoteGuard`/`embeddingCorpus` detector configured:**
  escalation rate on `user` traffic jumps from whatever your Tier-0 flag rate was to ~100%.
  Tier 1 (real `Llama-Prompt-Guard-2-22M`, unquantized) measured at p50 ≈5.5ms / p99 ≈76ms
  per request in our benchmark — factor that into your latency budget.

  **To opt back out:** `policy: { perSource: { user: { alwaysEscalate: false } } }`.

### Fixed

- **`LocalModelDetector.quantized` had no effect at all.** `src/onnx/index.ts` and
  `src/wasm/index.ts` passed a `quantized: boolean` option to `@huggingface/transformers`'s
  `pipeline()` call — a transformers.js v2 option that v3+ replaced with `dtype`. Unrecognized
  options are silently ignored, so the Node runtime always loaded fp32 regardless of the
  `quantized` setting (the WASM runtime happened to hardcode `dtype: 'q8'` separately, so it
  worked there by accident, but couldn't be disabled via `quantized: false`). Now maps
  `quantized` to `dtype: 'q8' | 'fp32'` explicitly in both runtimes. No behavior change if
  you never set `quantized` explicitly *and* your model repo only ships one dtype — but if
  you were relying on `quantized: true` (the default) to load a smaller/faster build, it
  wasn't happening. See [bench/REPORT.md](bench/REPORT.md) "Quantization" section.

### Evaluated and rejected

- **Switching the default Tier-1 model to an ungated alternative.** `meta-llama/Llama-Prompt-Guard-2`
  is gated and carries real adoption friction (access-request wait, manual ONNX export, unreviewed
  redistribution terms). Benchmarked `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0,
  ungated, ONNX published in-repo) as a candidate replacement before considering the swap. Result:
  recall 0.630 (vs. ~0.80), ROC-AUC 0.916 (vs. 0.986), NotInject over-defense 43.1% (vs. 8.6%) —
  uniformly worse across every category. Not adopted. See
  [bench/REPORT.md](bench/REPORT.md#open-model-candidate-protectaideberta-v3-base-prompt-injection-v2).

### Documented (no code/default change)

- **Ungated mirror option for the default model.** `gravitee-io/Llama-Prompt-Guard-2-22M-onnx`
  and `...-86M-onnx` are third-party ONNX mirrors of the exact same gated `meta-llama` weights —
  verified by running both side-by-side and matching scores to 4 decimal places, and they
  correctly carry the Llama 4 Community License + attribution `NOTICE`. Documented in the
  README ("Skipping the gated-model wait") as a custom-runner recipe, deliberately **not**
  wired in as a default — it's a third-party-maintained supply-chain choice each adopter
  should make explicitly. See
  [bench/REPORT.md](bench/REPORT.md#ungated-mirror-of-the-actual-default-model-not-a-different-model).

### Added

- `LocalModelDetector.minConfidence?: number` (default `0`, fully backward compatible) —
  floors ML scores below a threshold to 0 before they fold into the noisy-OR aggregate.
  Added alongside the `alwaysEscalate` default change above because forcing escalation on
  `user` without it pushed NotInject over-defense to 9.1% (above the project's own <5%
  gate) — see [bench/REPORT.md](bench/REPORT.md) and the README's "Calibrating ML confidence"
  section. There's no universal recommended value; derive one from your own corpus via
  `bench/metrics.ts`'s `recallAtFpr` sweep — and recalibrate per dtype (fp32 vs quantized),
  since quantization shifts the model's score distribution (see "Quantization" in the report).
- `bench/` — real-corpus benchmark harness (separate from the CI-gated seed corpus in
  `corpus/`). See `bench/REPORT.md` for methodology, datasets, and results. Now also
  benchmarks `Llama-Prompt-Guard-2-86M` alongside the default 22M model, breaks NotInject
  over-defense down per category (surfaced a bigger problem on "Technique Queries" than on
  "Multilingual"), and adds `pnpm bench:snapshot` to track results across runs in
  `bench/history/`.
