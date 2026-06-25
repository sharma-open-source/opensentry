# Configuration

All options on `createGuard(config?)` with their defaults. Config is optional —
zero-config gives you sub-ms Tier 0 tuned for a low false-positive rate.

```ts
const guard = createGuard({
  mode: 'enforce',
  thresholds: { flag: 0.4, block: 0.85 },
  policy: { failMode: 'open', hardBlockRules: [...], perSource: { ... } },
  normalize: { nfkc: true, foldConfusables: true, ... },
  detectors: [{ kind: 'heuristics' }],
  cache: { max: 1024 },
  onMetric: (m) => metrics.record(m),
});
```

## `mode`

```ts
mode?: 'shadow' | 'soft' | 'enforce'  // default 'enforce'
```

| Mode | Behavior |
|---|---|
| `enforce` (default) | Block when thresholds are crossed |
| `soft` | Downgrade `block` → `flag` (graduated rollout) |
| `shadow` | Compute verdicts but never block — `result.verdict` is always `allow`, `result.wouldVerdict` shows the real decision (dry-run / migration) |

## `thresholds`

```ts
thresholds?: { flag?: number; block?: number }  // default { flag: 0.4, block: 0.85 }
```

- `flag` (default `0.4`): score at which to flag for review
- `block` (default `0.85`): score at which to block

Scores use **noisy-OR** aggregation: `score = 1 - ∏(1 - w_i)`. A single weight of 1.0
yields score 1.0; multiple mid-confidence signals combine upward. The operating point
was chosen by recall-at-fixed-FPR on PR/ROC sweeps — **never a naive 0.5**.

## `policy`

### `policy.failMode`

```ts
policy.failMode?: 'open' | 'closed'  // default 'open'
```

- `open` (default): if a higher tier fails (circuit breaker / timeout), fall back to
  the prior verdict — an outage can't take down the product. The hard-block floor still
  fires.
- `closed`: a failed tier escalates `flag` → `block` (can't verify safety without it).

Overridable per-source (below) and per-detector (Tier 2 `RemoteGuardDetector.failMode`).

### `policy.hardBlockRules`

```ts
policy.hardBlockRules?: ReasonCode[] | true  // default ['unicode_tag_smuggling', 'exfil_markdown_image', 'template_forgery']
```

Deterministic high-confidence rules that fire **even in fail-open mode**. The default
set is tiny by design — it protects benign quality:

- `unicode_tag_smuggling` — U+E0000–E007F Tag block, zero legitimate use
- `exfil_markdown_image` — markdown-image / `javascript:` exfil lure
- `template_forgery` — forged chat-template / role delimiters

Pass `true` to treat *every* `hardBlock` reason as a hard-block (not recommended —
widens the block surface). See [hard-block rules](#hard-block-rules) below.

### `policy.perSource`

```ts
policy.perSource?: Partial<Record<Source, {
  thresholds?: Partial<Thresholds>;
  alwaysEscalate?: boolean;
  skip?: boolean;
  failMode?: 'open' | 'closed';
}>>
```

Per-source defaults (from `config.ts`):

| Source | `skip` | `alwaysEscalate` | Notes |
|---|---|---|---|
| `system` | `true` | — | Never scored as an attack (trusted) |
| `user` | `false` | `true` | Direct user input |
| `retrieved` | `false` | `true` | RAG context |
| `tool` | `false` | `true` | Tool output |
| `web` | `false` | `true` | Web content |
| `email` | `false` | `true` | Email content |

**Every source except `system` defaults to `alwaysEscalate: true`**, including `user`.
This only affects behavior when a `localModel`, `remoteGuard`, or `embeddingCorpus`
detector is configured — the zero-config Tier-0-only path is unchanged. The
[real-corpus benchmark](./evaluation.md#real-corpus-benchmark) found that
harmful-intent/jailbreak text with no structural marker scores exactly 0 on Tier 0 and
never reached the flag band, so under the old default Tier 1 never saw the dominant
attack channel.

Set `false` explicitly to opt a source out (e.g. to keep Tier 1 off the common path
for `user` and rely on Tier 0's flag-band escalation only — trading recall for lower
cost):

```ts
const guard = createGuard({
  policy: { perSource: { user: { alwaysEscalate: false } } },
});
```

Examples:

```ts
const guard = createGuard({
  policy: {
    perSource: {
      system:    { skip: true },                 // never scored (default)
      user:      { thresholds: { block: 0.9 } }, // stricter for direct user input
      retrieved: { alwaysEscalate: true },       // RAG context — escalate (default)
    },
  },
});
```

## `normalize`

```ts
normalize?: {
  nfkc?: boolean;                 // default true — Unicode NFKC (skipped for pure-ASCII)
  stripInvisible?: boolean;       // default true — zero-width, VS, C0-C1, Tag, bidi
  foldConfusables?: boolean;      // default true — Cyrillic/Greek → ASCII (MATCHING copy only)
  handleBidi?: 'strip' | 'isolate' | 'off';  // default 'strip' (RTL locale → 'isolate')
  decodeEncoded?: boolean;        // default true — base64/hex/URL/HTML-entity decode-rescan
  decodeDepth?: number;           // default 2 — recursion depth for nested encodings
  maxScanBytes?: number;          // default 65536 — truncate-with-flag above this
  rtlLocales?: string[];          // default ar/he/fa/ur/... — locales that get 'isolate' bidi
  // ── Security hardening (all default-off, see security.md) ──
  neutralizeEncoded?: 'off' | 'strip' | 'spotlight';  // default 'off'
  specialTokens?: string[];       // default Llama/Qwen/GPT/Mistral/Gemma list
  scanAdversarialSuffix?: boolean; // default false
}
```

### `normalize.neutralizeEncoded` — close the detect→model gap

Default `'off'`. Today a decoded blob is *detected* but the original encoded blob still
ships in `sanitized` — a downstream model decodes and obeys it. Set to:

- `'strip'` — remove the blob from the model copy
- `'spotlight'` — datamark it as inert data

Only fires on blobs that *themselves* re-scan as injection; benign base64 (images,
hashes) is untouched. Emits `encoded_payload_neutralized` and sets
`GuardResult.neutralized = true`. See [Security hardening](./security.md).

### `normalize.specialTokens`

A list of tokenizer control tokens scanned on the matching copy →
`special_token_injection`. Defaults to a common Llama/Qwen/GPT/Mistral/Gemma list
(`<|im_start|>`, `[INST]`, `<<SYS>>`, `<start_of_turn>`, `<|eot_id|>`, etc.). Control
tokens have essentially zero legitimate use in untrusted user data. A `<`/`[`
pre-check keeps the always-on path cheap. See [Security hardening](./security.md).

### `normalize.scanAdversarialSuffix`

Default `false` (opt-in). A cheap zero-LM proxy for GCG/token-salad → low-weight
`adversarial_suffix`. Calibrated to **0 benign FP** on code/base64/hashes/JSON.
Escalation signal only — routes to Tier 1, never blocks on its own. See
[Security hardening](./security.md).

### R4 — the two-copy invariant

Confusable folding touches the **matching copy** only (used by detectors). The **model
copy** (`result.sanitized`, passed downstream) is never folded — folding would corrupt
legitimate CJK, Arabic, emoji, and other non-ASCII content. The one deliberate exception
is `neutralizeEncoded`, which rewrites the model copy only to *remove* an attack payload,
never to alter legitimate content.

## `detectors`

```ts
detectors?: Detector[]  // default [{ kind: 'heuristics' }]
```

Pluggable + lazily loaded from subpath exports. At most one of each kind is supported.

| Kind | Tier | Sync? | Notes |
|---|---|---|---|
| `heuristics` | 0 | sync | Always edge-safe, zero-dep. Always on. |
| `localModel` | 1 | async | Llama-Prompt-Guard-2-22M/86M via ONNX/WASM. [Setup](./deployment.md#tier-1-local-ml) |
| `embeddingCorpus` | 2 | async | BYO `embed`, cosine-similarity against an attack corpus. [Setup](./deployment.md#embedding-corpus-ensemble) |
| `remoteGuard` | 2 | async | BYO `RemoteGuardProvider`. [Setup](./deployment.md#tier-2-remote-guard) |

Full detector option shapes are in [Deployment](./deployment.md).

## `cache`

```ts
cache?: { max?: number }  // default { max: 1024 }
```

LRU of verdicts keyed by `hash(normalized + source + highRisk)`. Repeat inputs
(system prompts, tool schemas) short-circuit after L1 — saves the decode-rescan + regex
on repeats. Cached results include any tier that ran.

## `onMetric`

```ts
onMetric?: (m: GuardMetric) => void
```

Called after every `check`/`checkSync` with per-tier latency, escalation rate, score,
verdict, and degraded status. See [`GuardMetric`](./api.md#guardmetric) in the API
reference. Wire this to your metrics dashboard for [tier-agreement
telemetry](./troubleshooting.md#monitoring).

---

## Hard-block rules

The default hard-block set is intentionally tiny and high-confidence. To customize:

```ts
const guard = createGuard({
  policy: {
    hardBlockRules: [
      'unicode_tag_smuggling',   // U+E0000–E007F — zero legitimate use
      'exfil_markdown_image',    // markdown-image exfil lure
      'template_forgery',        // forged chat-template markers
      // add your own ReasonCode values to widen the hard-block surface
    ],
  },
});
```

Only reasons marked `hardBlock: true` in their `Reason` definition are candidates, and
only the codes listed here actually fire as hard-blocks. Pass `true` to make every
`hardBlock` reason fire (not recommended).
