# Security hardening

The gaps a stateless single-message filter *structurally cannot see* — each shipped
**default-off or behind a new subpath** so the zero-config Tier-0 path, the CI gates
(benign FPR < 1%, NotInject < 5%, attack recall ≥ 90%, hard-block 100%, Tier 0 p99 <
1ms), and the eval corpora are all unchanged.

For the companion-based hardening (canary, taint, session), see
[Companions](./companions.md). This page covers the Tier-0/Tier-1 detection upgrades.

---

## Neutralize encoded payloads

`normalize.neutralizeEncoded` (default `'off'`) closes the detect→model gap: today a
decoded blob is *detected* but the original encoded blob still ships in `sanitized` —
a downstream model decodes and obeys it. **Detection without mitigation.**

Set to:
- `'strip'` — remove the offending blob span from `sanitized` (the model copy)
- `'spotlight'` — wrap it with the datamark marker so it reads as inert data

```ts
const guard = createGuard({
  normalize: { neutralizeEncoded: 'strip' },
});
```

**FP discipline:** only fires on blobs that *themselves* re-scan as injection — benign
base64 (images, hashes) is untouched. Default `'off'`, fully backward compatible. Emits
`encoded_payload_neutralized` and sets `GuardResult.neutralized = true`.

The **matching copy** is never touched (R4 two-copy invariant preserved); only
`sanitized` (the model copy) is rewritten, and only to *remove* an attack payload, never
to alter legitimate content. The blob is located by literal substring match (exact for
ASCII base64/hex, the common case).

---

## Special-token detection (Tier 0, always on)

`normalize.specialTokens` (default: a Llama/Qwen/GPT/Mistral/Gemma control-token list)
scans the matching copy → `special_token_injection`. Control tokens (`<|im_start|>`,
`[INST]`, `<<SYS>>`, `<start_of_turn>`, `<|eot_id|>`, …) have essentially zero
legitimate use in untrusted user data — they're how an attacker forges chat-template
turns.

```ts
const guard = createGuard({
  normalize: {
    specialTokens: ['<|im_start|>', '<|im_end|>', '[INST]', '[/INST]', '<my-custom-token>'],
  },
});
```

- **Matching copy only** — the model copy is untouched (R4).
- A cheap `<`/`[` pre-check keeps the always-on Tier-0 path fast: if the input contains
  neither char and every configured token starts with one of them, the 20-branch
  alternation regex is skipped entirely.
- Weight is moderate (rises with match count) so it raises attacker cost without an
  FP-driven block on benign prose that happens to type `<|...|>`.

The default list is intentionally **full, unambiguous tokens only** — no partial
prefixes or model names that risk flagging benign mentions.

---

## GCG / token-salad signal (Tier 0, opt-in)

`normalize.scanAdversarialSuffix` (default `false`) → low-weight `adversarial_suffix`.
A **zero-LM proxy** for optimizer-generated (GCG) suffixes: optimizer suffixes read as
garbage to humans but flip models. The design deliberately excluded perplexity (no LM on
the hot path) — this is a near-free proxy instead.

```ts
const guard = createGuard({
  normalize: { scanAdversarialSuffix: true },
});
```

The signal is calibrated to **0 benign FP** on code blocks, base64, hashes, and JSON.
A "salad run" is a whitespace-free run that is mostly letters, contains an embedded
punctuation/symbol char (NOT a pure base64/hex blob), has no base64-length alnum
subrun, and whose letter-trigrams are mostly NOT common English. GCG suffixes stitch
several such word-fragment-with-punctuation tokens; a single one looks like a code
identifier, so the signal requires ≥ 3 salad runs in the same input — this is what
separates real token-salad from a normal `import { foo } from "bar"` line.

**Low weight, escalation signal only** — routes to Tier 1, never blocks on its own.

---

## SmoothLLM consensus (Tier 1, opt-in)

`LocalModelDetector.smoothing: { n, perturbation }` runs `n` lightly-perturbed copies
through the classifier and takes the mean score. Adversarial suffixes (GCG) are tuned to
an exact string and are **brittle to perturbation**; benign text is not. For a
classifier-evasion suffix (exact→benign, perturbed→injection) the mean reveals the
injection; for a brittle high-on-exact signal (perturbed→benign) the mean is robust and
avoids an over-flag.

```ts
const guard = createGuard({
  detectors: [
    { kind: 'heuristics' },
    { kind: 'localModel', runtime: 'node', smoothing: { n: 5, perturbation: 0.1 } },
  ],
});
```

| Option | Default | Notes |
|---|---|---|
| `n` | `5` | Number of perturbed copies |
| `perturbation` | `0.1` | Per-char drop/swap probability (capped at `0.5`) |

**Gated to `highRiskAction` only** so the n× latency/FP cost stays off the common
(non-high-risk) path. The label is decided by majority vote (`injection` if > n/2
copies score > 0.5), the score by mean.

---

## Canary, taint, session

These are [companion subpaths](./companions.md), repeated here for discoverability:

- **[Canary](./companions.md#canary-opensentrycanary)** — `opensentry/canary`:
  deterministic, near-zero-FP system-prompt-leak detection via a 128-bit nonce. A hit
  maps to `canary_leak` (hard-block) — a confirmed extraction, not a heuristic guess.
- **[Taint](./companions.md#taint-opensentrytaint)** — `opensentry/taint`:
  provenance-passing for indirect-injection defense. Wired into `checkToolCall` via
  `opts.tracker` → `tainted_data_flow` + fail-closed. Low-FP because it flags *data
  flow into privileged actions*, not content.
- **[Session](./companions.md#session-opensentrysession)** — `opensentry/session`:
  stateful multi-turn guard. Catches Crescendo / Bad Likert Judge / many-shot, which
  exceed ~70% success because no single turn is flaggable. Folds `cumulative_risk` /
  `session_escalation` / `manyshot_density` via noisy-OR; can only escalate, never
  de-escalate.

---

## Reason codes added by security hardening

`session_escalation`, `manyshot_density`, `cumulative_risk`,
`encoded_payload_neutralized`, `tainted_data_flow`, `canary_leak`, `secret_egress`,
`pii_egress`, `special_token_injection`, `adversarial_suffix`. See the full
[`ReasonCode` table](./api.md#reasoncode).

## Out of scope (flagged, not silently dropped)

These are structurally out of reach and documented honestly rather than pretended away:

- **True automatic taint propagation** — impossible in JS without language/runtime
  support; `opensentry/taint` ships explicit provenance-passing instead, and says so.
- **Full perplexity scoring** — excluded from the hot path (needs an LM, high latency,
  blind to fluent paraphrase); the adversarial-suffix signal is a zero-LM proxy, not a
  real LM.
- **Distributed session state** — `opensentry/session` ships an in-memory store + a
  `SessionStore` interface; the actual Redis/DB backend is the integrator's.
- **A harmful-content classifier in Tier 0** — rejected (re-introduces NotInject
  over-defense); harmful-intent detection stays Tier 1's job.
- **Multi-turn / many-shot at the single-message level** — structurally out of reach;
  the session guard addresses it.
