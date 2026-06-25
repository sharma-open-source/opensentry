# Evaluation & benchmarks

`opensentry` ships two evaluation layers: a **CI-enforced seed corpus** (fast
tripwire) and a **real-corpus benchmark** (measured performance against public
datasets).

---

## Hard gates (CI-enforced)

Every change runs the seed corpus against these gates in CI (`pnpm ci`):

| Gate | Threshold | What it protects |
|---|---|---|
| Benign FPR | < 1% | Release blocker — don't hurt product quality |
| NotInject over-defense | < 5% | "Looks like injection but isn't" hard-negatives |
| Attack recall (in-scope) | ≥ 90% | Tier 0 catches the deterministic vectors |
| Hard-block recall | 100% | The deterministic hard-block set always blocks |
| Tier 0 p99 | < 1ms | The hot-path SLA (microseconds) |

Defined in `corpus/gates.ts`:

```ts
export const GATES = {
  benignFprMax: 0.01,
  notinjectOverDefenseMax: 0.05,
  attackRecallMin: 0.9,
  hardBlockRecallMin: 1.0,
  tier0P99Us: 1000,
} as const;
```

Run the gates:

```bash
pnpm eval
```

Output:

```
EVAL OK {"attackRecall":"1.000","hardBlockRecall":"1.000","benignFpr":"0.000","notInjectRate":"0.000"}
```

A regression in benign quality blocks a merge **even if recall improves**.

---

## Seed corpora

Three hand-written corpora shipped in `corpus/`:

| Corpus | Count | Purpose |
|---|---|---|
| `corpus/attacks.json` | 24 + 4 outOfScope | Attack recall ≥ 90%, hard-block 100% |
| `corpus/benign.json` | 20 | False-positive rate < 1% |
| `corpus/notinject.json` | 25 | Over-defense rate < 5% |

The `outOfScope` attacks are documented known limitations (semantic paraphrase,
multilingual, ROT13 pure-text, ArtPrompt) — they require Tier 1 ML and are excluded
from the Tier-0 recall calculation.

### Schema

```json
[
  {
    "id": "atk-025",
    "text": "Your actual attack text here",
    "label": "attack",
    "outOfScope": false,
    "hardBlock": false,
    "source": "user"
  }
]
```

Fields:
- `id` (string, required): unique identifier
- `text` (string, required): the sample text
- `label` (string, required): `"attack"`, `"benign"`, or `"notinject"`
- `outOfScope` (boolean, optional): excludes from recall calculation (documents known limitations)
- `hardBlock` (boolean, optional): expects a `block` verdict (hard-block recall gate)
- `source` (string, optional): the `GuardContext.source` to use when scoring

The eval loader (`corpus/loader.ts`) auto-discovers all `*.json` files in `corpus/`.

### Adding real datasets

Drop JSON files into `corpus/` with the schema above. For multi-turn fixtures, see the
session guard tests (`tests/session.test.ts`). Every confirmed prod false-positive or
false-negative should become a regression case.

---

## Real-corpus benchmark

The seed corpus is a CI tripwire, not a measure of real-world performance. `bench/`
runs the full pipeline against **1,699 real attacks + 700 real benign samples** from
public datasets (Lakera/Gandalf, JailbreakBench, AdvBench, NotInject, Alpaca), using
the actual shipped default Tier-1 model. Full methodology, dataset provenance, and
caveats: **[`../bench/REPORT.md`](../bench/REPORT.md)**.

```bash
pnpm bench:fetch   # downloads the real corpora (~2.4k samples) from public HF datasets
pnpm bench         # runs the full suite, ~65s, writes bench/report.json
pnpm bench:snapshot # track results across runs in bench/history/
```

### Headline results

| View | Precision | Recall | F1 | FPR | ROC-AUC | p50 latency | p99 latency |
|---|---|---|---|---|---|---|---|
| Tier 0 only | 1.000 | 0.304 | 0.467 | 0.000 | 0.655 | 0.03ms | 0.44ms |
| Tier 1 (real model, called directly) | 0.992 | 0.803 | 0.888 | 0.016 | 0.986 | 5.6ms | 73ms |
| **Blended, current default** | 0.992 | 0.804 | 0.888 | 0.016 | 0.986 | 5.6ms | 97ms |
| Blended, old default (`alwaysEscalate:false` on `user`) | 1.000 | 0.304 | 0.467 | 0.000 | 0.655 | 0.03ms | 7.2ms |
| **Blended, calibrated (`minConfidence:0.87`)** | 0.997 | 0.719 | 0.836 | 0.006 | 0.859 | 5.5ms | 96ms |

### What the benchmark drove

The first run showed the blended pipeline performing *identically* to Tier 0 alone —
Tier 1 only escalated when Tier 0's own score landed in the flag band, and `user` was
the one source that defaulted to `alwaysEscalate: false`. Harmful-intent/jailbreak
attacks with no structural marker scored 0 on Tier 0 and never reached the model.
`DEFAULT_PER_SOURCE.user.alwaysEscalate` is now `true` (see
[CHANGELOG.md](../CHANGELOG.md)), recovering that recall — but on its own that pushed
NotInject over-defense to 9.1%, over the <5% gate. Pairing it with `minConfidence:
0.87` brings over-defense back to 4.7% while keeping recall at 0.719 (vs. 0.304 for
Tier 0 alone).

The benchmark also caught a real bug: `quantized: true` (the documented default) had
**zero effect** — `src/onnx/index.ts`/`src/wasm/index.ts` passed it as an option that
`@huggingface/transformers` v3+ no longer accepts (replaced by `dtype`). Now fixed and
benchmarked. See [`../bench/REPORT.md`](../bench/REPORT.md) "Quantization".

### Evaluated and rejected

- **Switching the default to an ungated alternative** (`protectai/deberta-v3-base-prompt-injection-v2`):
  recall 0.630 (vs. ~0.80), ROC-AUC 0.916 (vs. 0.986), NotInject over-defense 43.1%
  (vs. 8.6%) — uniformly worse. Not adopted. See [`../bench/REPORT.md`](../bench/REPORT.md).

---

## Calibrating ML confidence

The global `thresholds.flag`/`block` are tuned against Tier 0's structural evidence.
A given ML model's moderate-confidence scores may not be reliable enough to clear that
same bar without raising false positives. `LocalModelDetector.minConfidence` floors out
ML scores below a threshold *before* they fold into the noisy-OR aggregate, without
touching Tier 0's thresholds:

```ts
const guard = createGuard({
  detectors: [
    { kind: 'heuristics' },
    { kind: 'localModel', runtime: 'node', minConfidence: 0.6 }, // calibrate per your model/export
  ],
});
```

There's **no universal default** — a different model, a quantized export, or a
fine-tuned checkpoint will calibrate differently. Derive your own value from
`bench/metrics.ts`'s `recallAtFpr` sweep against your own traffic or corpus: pick the
threshold that hits your FPR budget, then set `minConfidence` there. **Recalibrate per
dtype** (fp32 vs quantized) — quantization shifts the model's score distribution.

The benchmark's `0.87` figure is illustrative for the default 22M model on the bundled
corpora, not a recommendation for your deployment.

---

## Red-team & adaptive testing

Prompt injection cannot be "patched once." PLAN.md §9 recommends:

- **Scheduled + pre-release `garak`** plus adaptive attackers (GCG/AutoDAN, TAP,
  Crescendo/multi-turn, encoding, translation, indirect-via-document)
- Rotate in attacks from new papers/CVEs
- Threshold tuning by recall-at-fixed-FPR on a held-out calibration set; recalibrate
  per surface/locale
- **Shadow → soft → enforce** deployment (see [Recipes](./recipes.md#6-shadow-soft-enforce-rollout))
- Monitoring + drift dashboards (flag rate, FPR/FNR, latency percentiles, per-locale/
  surface slices, score-distribution drift) — see [Troubleshooting → Monitoring](./troubleshooting.md#monitoring)
