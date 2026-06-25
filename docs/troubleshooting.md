# Troubleshooting

## Common errors

### `checkSync: configured detectors include async tiers`

```
opensentry checkSync: configured detectors include async tiers (localModel/remoteGuard/
embeddingCorpus). Use check() for the full tiered pipeline, or remove async detectors
for sync-only Tier 0.
```

`checkSync` is Tier-0-only and sync. If you configured a `localModel`, `remoteGuard`,
or `embeddingCorpus` detector, use `await guard.check(...)` instead. To keep the sync
sub-ms path, remove the async detectors (zero-config `createGuard()` is Tier 0 only).

### `failed to load opensentry/onnx` / `failed to load opensentry/wasm`

The ML subpath couldn't import its peer dependency:

- **Node (`opensentry/onnx`):** install `pnpm add @huggingface/transformers onnxruntime-node`
- **Edge (`opensentry/wasm`):** install `pnpm add @huggingface/transformers`
- Or pass a custom `runner` to the `localModel` detector (no lazy import) — see
  [Deployment → Custom runner](./deployment.md#custom-runner).

On failure, the guard falls back to the Tier 0 verdict with a `degraded` flag (circuit
breaker opens after 5 consecutive failures).

### `opensentry/remote: global fetch is not available`

`opensentry/remote` adapters use `globalThis.fetch`. In environments without a global
`fetch` (old Node), pass `fetchImpl` explicitly:

```ts
createHttpGuardProvider({ ..., fetchImpl: myFetch });
```

### `opensentry spotlight: untrusted input already contains the delimiter/marker`

Spotlight throws when the input already contains the chosen delimiter/marker — a
forgery-prevention guarantee. This means the untrusted input is trying to forge the
channel boundary; treat it as a block. If you hit this on benign input, you chose a
marker that legitimately appears in your data — pick a different `marker` or use
`mode: 'encode'`.

---

## Degraded mode

When a higher tier fails (circuit breaker open, timeout, provider error), the guard
returns the **prior-tier verdict** plus a `degraded` flag — **surfaced, never silent**:

```ts
result.degraded // { tier: 1, reason: 'degraded_mode' }
```

- Circuit breakers open after **5 consecutive failures**, short-circuiting that tier for
  **30s** (half-open probe after cooldown). Each tier (ML, remote, embedding) has its
  own breaker.
- Tier 1 timeout: default `5000ms`. Tier 2 timeout: default `500ms`. Embedding timeout:
  default `2000ms`. All overridable per-detector.
- `failMode: 'closed'` (per-source or per-detector) escalates `flag` → `block` on
  degradation — use it when you can't verify safety without that tier (e.g.
  `highRiskAction`). Default is `failMode: 'open'` so an outage can't take down the
  product; the hard-block floor still fires.

Check `result.degraded` and `GuardMetric.degraded` in your telemetry to alert on tier
health. See [Configuration → failMode](./configuration.md#policyfailmode).

---

## Fail-open vs fail-closed

| | `failMode: 'open'` (default) | `failMode: 'closed'` |
|---|---|---|
| Tier fails | Fall back to prior verdict | Escalate `flag` → `block` |
| Hard-block floor | Still fires | Still fires |
| Use when | Outage shouldn't take down product | Can't verify safety without the tier (high-risk) |

Configurable globally (`policy.failMode`), per-source (`policy.perSource.<source>.failMode`),
and per-Tier-2-detector (`RemoteGuardDetector.failMode`). `highRiskAction: true` forces
fail-closed for that call regardless. See [Configuration](./configuration.md).

---

## Latency higher than expected

- **Tier 0 should be sub-ms.** If it isn't, check `maxScanBytes` (default 64KB) — very
  large inputs are truncated-with-flag but the scan itself is bounded. The p99 SLA is
  CI-enforced (`pnpm test:perf`).
- **Tier 1 (ML) adds 15–200ms** and fires on the uncertain band + `alwaysEscalate`
  sources. With the default `alwaysEscalate: true` on `user`, escalation rate on `user`
  traffic is ~100% when an async detector is configured. To keep ML off the common path
  for `user`: `policy.perSource.user.alwaysEscalate: false` (trades recall for cost —
  see [Evaluation](./evaluation.md#real-corpus-benchmark)).
- **Cold start:** ML adds 50–300ms the first time. Use `warmOnBoot: true` to fire-and-
  forget load + warm inference at startup.
- **SmoothLLM (`smoothing`)** runs n× copies — gated to `highRiskAction` only so it
  stays off the common path.
- **Quantization** shrinks the model ~3.3x but latency barely moves on CPU for a model
  this small — don't assume `quantized: true` speeds up your deployment. See
  [`../bench/REPORT.md`](../bench/REPORT.md).

---

## False positives / over-defense

If benign traffic is being flagged or blocked:

1. **Check `wouldVerdict` vs `verdict`** in shadow mode to measure the real FPR before
   enforcing. Run `mode: 'shadow'` and log both.
2. **Don't ship a naive 0.5 threshold.** The defaults (flag `0.4` / block `0.85`) were
   chosen by recall-at-fixed-FPR. Tune per-source: `policy.perSource.user.thresholds`.
3. **ML over-defense:** if `alwaysEscalate: true` is pushing NotInject-style hard
   negatives over the gate, raise `LocalModelDetector.minConfidence` to floor out
   low-confidence ML scores before they fold in. Derive a value from
   `bench/metrics.ts`'s `recallAtFpr` sweep (see [Evaluation](./evaluation.md#calibrating-ml-confidence)).
4. **Keyword-only matches are low-weight by design** (protects NotInject "system:
   status" benign). If you're seeing FP from a specific reason code, check its weight
   in the [tier model](./tiers.md#l3-structural-heuristic-regex) — only
   `template_forgery` / `exfil_markdown_image` / `unicode_tag_smuggling` are hard-block.
5. **The two-copy invariant protects non-Latin content.** Confusable folding never
   touches the model copy, so CJK/Arabic/emoji is never corrupted. If you see
   legitimate non-Latin content being *scored* as `script_mixing`, note it only fires
   for Latin+Cyrillic/Greek (look-alike scripts), NOT Latin+CJK/Arabic (legit bilingual).
6. **Add the case to the corpus.** Every confirmed false positive should become a
   regression case in `corpus/benign.json` or `corpus/notinject.json` so the gates
   catch it in future.

---

## False negatives (missed attacks)

- **Semantic attacks** (paraphrase, multilingual, fictional framing, ROT13 pure-text,
  ArtPrompt) are out of Tier 0's scope by design — add a `localModel` detector (Tier 1).
- **Multi-turn / many-shot / Crescendo** — no single turn is flaggable; use
  [`opensentry/session`](./companions.md#session-opensentrysession).
- **Indirect injection** (untrusted text reaching a privileged tool) — wire a
  [`taint` tracker](./companions.md#taint-opensentrytaint) into `checkToolCall`.
- **Optimizer (GCG) suffixes** — enable `normalize.scanAdversarialSuffix` (routes to
  Tier 1) and consider `smoothing` on high-risk paths.
- **Encoded payloads that decode-and-obey** — enable `normalize.neutralizeEncoded:
  'strip'` to close the detect→model gap.
- Add the case to `corpus/attacks.json` (mark `outOfScope: true` if it's a known
  structural limitation, so it's documented but excluded from the Tier-0 recall gate).

---

## Monitoring

Wire `onMetric` to your dashboard — it emits per-check telemetry:

```ts
const guard = createGuard({
  onMetric: (m) => metrics.record({
    requestId: m.requestId,
    source: m.source,
    tier: m.tier,
    latencyMs: m.latencyMs,
    verdict: m.verdict,
    wouldVerdict: m.wouldVerdict,  // shadow-mode real decision
    score: m.score,
    escalated: m.escalated,        // a higher tier was invoked
    cached: m.cached,
    degraded: m.degraded,          // tier health
    reasons: m.reasons,
  }),
});
```

Track, at minimum:
- **Per-tier latency histograms** (p50/p95/p99)
- **Escalation rate** (what % of traffic hits Tier 1/2) — drives cost
- **Tier-agreement** (when Tier 1/2 disagrees with Tier 0) — drift signal
- **Flag/block rates** per source/locale
- **`degraded` rate** — tier health
- **FPR on a benign golden corpus** as the hard release gate
- **Score-distribution drift** over time

See [`GuardMetric`](./api.md#guardmetric) for the full shape.

---

## Edge-safety violations

`src/` must never import `node:*`, use `Buffer`, `process`, `__dirname`, or
`setImmediate` — enforced by `tests/no-node-builtins.test.ts`. Applies to ALL subpaths
including companions and middleware. Web globals (`btoa`, `TextEncoder`,
`crypto.getRandomValues`, `Response`, `fetch`) are allowed.

**Exception:** `src/onnx/` is a Node-only subpath (uses `onnxruntime-node`) and is
excluded from the edge-safety check. Edge users import `opensentry/wasm` instead.

If you hit this test failing after an edit, you've accidentally pulled a Node builtin
into edge-safe code — rework it to use the web-global equivalent, or move the code into
`src/onnx/` if it genuinely needs Node.
