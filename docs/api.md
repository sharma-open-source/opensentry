# API reference

The entire public surface is exported from `opensentry`. Types are exported alongside
the runtime (`export type * from './types.js'`).

```ts
import { createGuard, GuardBlockError } from 'opensentry';
import type { Guard, GuardConfig, GuardResult, GuardContext, Reason, RemoteGuardProvider } from 'opensentry';
```

---

## `createGuard(config?): Guard`

Creates a guard instance. Config is optional — defaults are tuned for low
false-positive rate (flag `0.4`, block `0.85`).

```ts
const guard = createGuard({
  mode: 'enforce',
  thresholds: { flag: 0.4, block: 0.85 },
  policy: {
    failMode: 'open',
    hardBlockRules: ['unicode_tag_smuggling', 'exfil_markdown_image', 'template_forgery'],
    perSource: {
      retrieved: { alwaysEscalate: true },
      web:       { alwaysEscalate: true },
    },
  },
  normalize: {
    nfkc: true,
    foldConfusables: true,
    handleBidi: 'strip',
    decodeEncoded: true,
    maxScanBytes: 65536,
  },
  cache: { max: 1024 },
  onMetric: (m) => console.log(m.verdict, m.latencyMs),
});
```

See [Configuration](./configuration.md) for every option and its default.

---

## `guard.checkSync(input, ctx?): GuardResult`

Sync, **Tier 0 only**. No I/O, edge-safe. Throws if async detectors (`localModel`,
`remoteGuard`, `embeddingCorpus`) are configured — use `check()` for the full pipeline.

```ts
const result = guard.checkSync(userInput, {
  source: 'user',         // 'system' | 'user' | 'retrieved' | 'tool' | 'web' | 'email'
  locale: 'en',           // enables RTL-aware bidi handling
  highRiskAction: true,   // fail-closed: flag→block escalation
});
```

Returns a [`GuardResult`](#guardresult). Repeat inputs (same normalized hash + source +
high-risk flag) are served from an LRU cache after L1.

---

## `guard.check(input, ctx?): Promise<GuardResult>`

Full tiered pipeline: Tier 0 → conditional Tier 1 (local ML) → conditional embedding
ensemble → conditional Tier 2 (remote guard). Each tier's score is folded into the
aggregate via noisy-OR; the verdict is re-decided with all evidence at every step.

```ts
const result = await guard.check(userInput, { source: 'user' });
// result.tier === 0  → Tier 0 only (clean or hard-block)
// result.tier === 1  → Tier 1 ML was invoked and its score folded in
// result.tier === 2  → Tier 2 remote guard / embedding was invoked
// result.degraded    → { tier, reason: 'degraded_mode' } if that tier failed (circuit breaker / timeout)
```

If no async detector is configured, `check()` runs the same sync Tier-0 path as
`checkSync()`. See [Tier model](./tiers.md) for the escalation gates.

### `GuardContext`

| Field | Type | Default | Purpose |
|---|---|---|---|
| `source` | `Source` | `'user'` | Drives per-source policy + thresholds |
| `locale` | `string` | — | Enables RTL-aware bidi + locale-aware script/lang gates (e.g. `'ar'`, `'en-US'`) |
| `highRiskAction` | `boolean` | `false` | Forces escalation + fail-closed (pre-tool-call gating) |
| `conversationId` | `string` | — | Multi-turn / cache keying (stateless in core; used by [`opensentry/session`](./companions.md#session-opensentrysession)) |
| `requestId` | `string` | — | Surfaces in `GuardMetric` |

---

## `guard.checkMessages(messages): Promise<GuardResult[]>`

Scores each message per its source role. Trusted `system` messages are skipped
(per-source `skip` policy → verdict `allow`, but still sanitized).

```ts
const results = await guard.checkMessages([
  { role: 'system', content: 'You are a helpful assistant.' },
  { role: 'user', content: userInput },
  { role: 'retrieved', content: ragChunk },
]);
```

Uses `guard.check` per message, so async tiers (ML/remote) are automatically engaged.

---

## `guard.createStreamScanner(ctx?): { push, end }`

Streaming / chunked scan. Buffers across chunk boundaries so split injection tokens
(e.g. `"<|im_st" + "art|>"`) are caught. Supports early-abort.

```ts
const scanner = guard.createStreamScanner({ source: 'tool' });
for (const chunk of stream) {
  const { partial, abort } = scanner.push(chunk);
  if (abort) break;  // block detected — stop the stream
}
const final = scanner.end();  // full GuardResult
```

- `push(chunk)` returns `{ partial, abort }` where `partial` is the worst verdict seen
  so far and `abort` is `true` when the enforced verdict reaches `block`.
- `end()` runs the full pipeline (with cache + metrics) on the accumulated buffer.

Incremental `push` calls use the uncached Tier-0 path to avoid polluting the LRU with
partial buffers.

---

## `guard.wrap(fn, opts?): (...args) => Promise<R>`

Drop-in wrapper that guards the first string argument before passing it to `fn`:

```ts
const safeComplete = guard.wrap(llm.complete, {
  onBlock: (result) => fallbackResponse(result),
  replaceWithSanitized: true,  // pass sanitized text downstream (default)
});
```

| Option | Default | Behavior |
|---|---|---|
| `inputSelector` | first string arg | Pick which arg(s) to scan: `(...args) => { text, ctx? }` |
| `onFlag` | — | Called on `flag`; sanitized text still passes through |
| `onBlock` | — | Called on `block`; if it returns a value, that becomes the result. Otherwise throws `GuardBlockError` |
| `replaceWithSanitized` | `true` | Replace the scanned arg with `result.sanitized` before calling `fn` |

On `block` with no `onBlock`, throws `GuardBlockError` (carries `.result`).

---

## `guard.checkToolCall(call, policy, opts?): Promise<GuardResult>`

Least-privilege assist for agentic tool calls — scans the call's args through the full
pipeline and enforces a name allowlist **before execution**. `highRiskAction` is
forced, so the uncertain band fails closed.

```ts
const result = await guard.checkToolCall(
  { name: 'sendEmail', args: { to: 'user@example.com', body: emailBody } },
  { allow: { sendEmail: {}, readFile: {} } },
);
if (result.verdict === 'block') return refuse(result.reasons);
// proceed with the tool call
```

- A tool name **outside** `policy.allow` always blocks (`agentic_tool_hijack`).
- A name **inside** the allowlist still has its `args` scanned for injection.
- The privilege model itself (what a tool is actually allowed to do) stays in your
  runtime — this only gates against running an injected/disallowed call.

### Indirect-injection defense via taint tracking

Pass an optional `opts.tracker` (a `TaintTracker` from
[`opensentry/taint`](./companions.md#taint-opensentrytaint)) to also catch
**indirect injection** — untrusted-origin text (retrieved/tool/web/email) reaching a
privileged tool call emits `tainted_data_flow` and fails closed. This is policy, not a
classifier, so it's low false-positive:

```ts
import { createTaintTracker } from 'opensentry/taint';
const tracker = createTaintTracker();
tracker.mark(retrievedDoc, 'retrieved'); // register untrusted-origin spans
const result = await guard.checkToolCall(
  { name: 'sendEmail', args: { body: maybePastedContent } },
  { allow: { sendEmail: {} } },
  { tracker },
);
```

See the [agentic gating recipe](./recipes.md#3-agentic-tool-call-gating).

---

## `GuardResult`

```ts
interface GuardResult {
  verdict: 'allow' | 'flag' | 'block';        // ENFORCED decision (respects shadow/soft)
  wouldVerdict: 'allow' | 'flag' | 'block';   // decision BEFORE shadow override — for logging
  score: number;                              // 0..1, noisy-OR aggregation
  reasons: Reason[];                          // evidence with code, weight, span
  sanitized: string;                          // MODEL copy — pass downstream
  normalized: string;                         // MATCHING copy — audit/debug
  truncated: boolean;                         // input hit maxScanBytes
  tier: 0 | 1 | 2;                            // highest tier that actually executed
  source: Source;
  shadow: boolean;                            // true => verdict was NOT enforced
  mode?: 'shadow' | 'soft' | 'enforce';       // resolved mode (lets wrappers re-decide)
  degraded?: { tier: 0|1|2; reason: ReasonCode }; // a tier failed open — surfaced, never silent
  neutralized?: boolean;                      // an encoded payload in the model copy was stripped/spotlighted
  latencyMs: number;
}
```

### `Reason`

```ts
interface Reason {
  code: ReasonCode;       // see below
  category: 'obfuscation' | 'structural' | 'semantic' | 'exfil' | 'resource';
  weight: number;         // contribution to score [0..1]
  span?: [start: number, end: number];  // offsets into the matching (normalized) copy
  message: string;        // human-readable, for appeals/debug
  hardBlock?: boolean;    // deterministic hard rule (blocks even in fail-open)
}
```

### `ReasonCode`

All reason codes emitted across every tier and companion:

| Code | Category | Tier | Origin |
|---|---|---|---|
| `unicode_tag_smuggling` | obfuscation | 0 | L1 — U+E0000–E007F Tag block (hard-block) |
| `bidi_override` | obfuscation | 0 | L1 — bidi embedding/override controls |
| `zero_width_chars` | obfuscation | 0 | L1 — zero-width/invisible chars |
| `invisible_density` | obfuscation | 0 | L1 — high density of invisible/control chars |
| `confusable_run` | obfuscation | 0 | L1 — UTS-39 look-alike chars folded |
| `script_mixing` | obfuscation | 0 | L2 — mixed Latin+Cyrillic/Greek |
| `encoded_payload` | obfuscation | 0 | L2 — decoded blob re-scanned as injection |
| `encoded_payload_neutralized` | obfuscation | 0 | neutralization — model copy rewritten |
| `entropy_anomaly` | obfuscation | 0 | L2 — high Shannon entropy |
| `adversarial_suffix` | obfuscation | 0 | L2 — GCG/token-salad signal (opt-in) |
| `special_token_injection` | structural | 0 | L2 — tokenizer control tokens |
| `role_tag_spoof` | structural | 0 | L3 — role-colon marker spoofing |
| `template_forgery` | structural | 0 | L3 — forged chat-template markers (hard-block) |
| `instruction_override` | semantic | 0 | L3 — "ignore previous instructions" family |
| `policy_puppetry` | structural | 0 | L3 — `<policy>`/`<override>`/`{"role":"system"}` |
| `exfil_markdown_image` | exfil | 0 | L3 — markdown-image / `javascript:` lure (hard-block) |
| `refusal_suppression` | semantic | 0 | L3 — "don't say you can't" priming |
| `agentic_tool_hijack` | semantic | 0 | L3 / `checkToolCall` — tool-call hijack |
| `indirect_marker` | semantic | 0 | L3 — system-prompt extraction marker |
| `length_cap` | resource | 0 | L0 — input truncated / flooding |
| `lang_divergence` | semantic | 0 | L2 — text language diverges from channel locale |
| `ml_classifier` | semantic | 1 | Tier 1 local ML |
| `embedding_match` | semantic | 2 | embedding-corpus ensemble |
| `remote_guard` | semantic | 2 | Tier 2 remote guard |
| `degraded_mode` | resource | * | a tier failed open (in `result.degraded`) |
| `session_escalation` | semantic | session | [`opensentry/session`](./companions.md#session-opensentrysession) — Crescendo gradient |
| `manyshot_density` | structural | session | [`opensentry/session`](./companions.md#session-opensentrysession) — many-shot role pairs |
| `cumulative_risk` | semantic | session | [`opensentry/session`](./companions.md#session-opensentrysession) — decaying sum |
| `tainted_data_flow` | semantic | tool | [`checkToolCall`](#guardchecktoolcallcall-policy-opts-promiseguardresult) + taint tracker |
| `canary_leak` | exfil | egress | [`opensentry/canary`](./companions.md#canary-opensentrycanary) — system-prompt extraction (hard-block) |
| `secret_egress` | exfil | egress | [`opensentry/egress`](./companions.md#egress-filter-opensentryegress) — leaked secrets |
| `pii_egress` | exfil | egress | [`opensentry/egress`](./companions.md#egress-filter-opensentryegress) — leaked PII |

---

## `GuardBlockError`

Thrown by `guard.wrap` on a `block` verdict when no `onBlock` handler returns a value.

```ts
class GuardBlockError extends Error {
  readonly result: GuardResult;
}
```

---

## Detectors

Configured via `GuardConfig.detectors` (default `[{ kind: 'heuristics' }]`):

```ts
type Detector =
  | { kind: 'heuristics' }                         // Tier 0, sync, always edge-safe
  | { kind: 'localModel'; ... }                    // Tier 1 local ML (see deployment.md)
  | { kind: 'remoteGuard'; provider; ... }         // Tier 2 remote guard (see deployment.md)
  | { kind: 'embeddingCorpus'; embed; ... };       // Tier 2 embedding ensemble (see deployment.md)
```

Full detector option shapes are in [Deployment](./deployment.md).

## `RemoteGuardProvider`

Tier 2 is BYO-provider — `opensentry` ships no vendor SDKs. You implement the
interface; `opensentry/remote` ships thin [reference adapters](./deployment.md#tier-2-remote-guard).

```ts
interface RemoteGuardProvider {
  name: string;
  scan(text: string, ctx: GuardContext): Promise<{
    score: number;            // 0..1 malicious probability, folded into the score
    label?: 'benign' | 'injection' | 'jailbreak' | (string & {});
    categories?: string[];    // optional policy-category labels
    raw?: unknown;            // provider's raw payload, for logging
  }>;
}
```

## `GuardMetric`

Emitted via `GuardConfig.onMetric` after every `check`/`checkSync`:

```ts
interface GuardMetric {
  requestId?: string;
  conversationId?: string;
  source: Source;
  tier: 0 | 1 | 2;
  latencyMs: number;
  verdict: Verdict;
  wouldVerdict: Verdict;
  score: number;
  escalated: boolean;       // a higher tier was invoked
  cached: boolean;
  truncated: boolean;
  degraded?: { tier: Tier; reason: ReasonCode };
  reasons: ReasonCode[];
}
```
