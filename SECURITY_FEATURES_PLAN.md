# Plan: input-security features to add to opensentry

## Context

opensentry today is a strong **single-message, stateless input filter** (Tier 0 heuristics +
optional Tier 1 ML + Tier 2 remote). This plan covers the features that the current
architecture *structurally cannot see* — the gaps a motivated attacker walks through — sequenced
by attacker-cost-raised per false-positive risk. Every item respects the project's existing
non-negotiables (PLAN.md §4): **benign FPR < 1% and NotInject over-defense < 5% stay release
gates**, Tier 0 stays sync/zero-dep/edge-safe, and new cost stays off the common path.

Grounding (verified against the code):
- `checkMessages` ([src/guard.ts:604](src/guard.ts#L604)) scores each message independently;
  `conversationId` ([src/guard.ts:150](src/guard.ts#L150)) is only a cache/metric key — **no
  session state exists**.
- `src/normalize/decode.ts` decodes base64/hex/ROT13 **for scanning the matching copy only** —
  the model copy (`result.sanitized`) still carries the original encoded blob, so a downstream
  model can decode and obey it.
- `src/egress/index.ts` blocks exfil **URLs** but never scans the **payload** (secrets/PII).
- No canary, taint/provenance, special-token, or adversarial-suffix detection exists anywhere
  in `src/` (grepped).

New `ReasonCode`s introduced across this plan (added to [src/types.ts:9](src/types.ts#L9)):
`session_escalation`, `manyshot_density`, `cumulative_risk`, `encoded_payload_neutralized`,
`tainted_data_flow`, `canary_leak`, `secret_egress`, `pii_egress`, `special_token_injection`,
`adversarial_suffix`.

---

## P0 — structural holes (highest value, mostly low-FP architectural additions)

### 1. Stateful multi-turn / session guard

**Problem.** Crescendo, Bad Likert Judge, and many-shot exceed ~70% success precisely because
*no single turn is flaggable*. PLAN.md §10 already names this the #1 deferred gap.

**Change.** New subpath **`opensentry/session`** (keeps the core stateless and edge-safe). A
`SessionGuard` wraps an existing `Guard` and maintains per-`conversationId` state in an LRU
(reuse `src/cache.ts`'s `LRU`), with a pluggable store interface for distributed deployments.

```ts
// opensentry/session
export interface SessionStore {            // default: in-memory LRU; BYO for Redis/etc.
  get(id: string): SessionState | undefined;
  set(id: string, s: SessionState): void;
  delete(id: string): void;
}
export interface SessionState {
  cumulativeScore: number;     // decaying sum of per-turn scores
  turns: { score: number; verdict: Verdict; categories: ReasonCategory[]; ts: number }[];
  refusedTopics: string[];     // normalized markers of content the assistant refused
}
export interface SessionGuardOptions {
  store?: SessionStore;
  decay?: number;              // per-turn multiplier on cumulativeScore, default 0.8
  escalationDelta?: number;    // turn-over-turn score rise that trips session_escalation
  manyShotTurnThreshold?: number; // synthetic role-pair count that trips manyshot_density
  ttlMs?: number;
}
export function createSessionGuard(guard: Guard, opts?: SessionGuardOptions): {
  check(input: string, ctx: GuardContext & { conversationId: string }): Promise<GuardResult>;
  reset(conversationId: string): void;
};
```

Per-turn the session guard runs the wrapped `guard.check`, then folds three **session-level**
signals into the result via the existing noisy-OR (`src/scoring.ts`):
- `cumulative_risk` — decaying sum crosses a threshold (slow escalation trips it even when each
  turn is individually benign),
- `session_escalation` — score gradient across turns exceeds `escalationDelta` (Crescendo),
- `manyshot_density` — a single turn injects many synthetic `user:`/`assistant:` example pairs.

**FP discipline.** Session signals are **flag-weighted, not hard-block**; `cumulativeScore`
decays so a single spike doesn't poison a long benign conversation. Gates measured on a
multi-turn corpus (below), not the single-message NotInject set.

**Verification.** New `tests/session.test.ts` with scripted Crescendo / many-shot / benign
long-conversation fixtures. Add a small multi-turn corpus (`corpus/multiturn.json`, schema
extended with `conversationId` + `turn`) and a session over-defense gate on benign
conversations.

---

### 2. Neutralize encoded payloads (close the detect→model gap)

**Problem.** `decode.ts` detects an `encoded_payload` but the **original encoded blob still
ships in `result.sanitized`**. `encoded_payload` is low-weight, so the verdict is often
`allow`/`flag` (passes through) — and the downstream model decodes and obeys the payload.
Detection without mitigation.

**Change.** Add `normalize.neutralizeEncoded?: 'off' | 'strip' | 'spotlight'` (default `'off'`,
fully backward compatible) to `GuardConfig.normalize` ([src/types.ts:177](src/types.ts#L177)).
When a decoded blob *re-scans* to ≥ `flag`, apply to the **model copy only** (preserve the R4
two-copy invariant):
- `strip` — remove the offending blob span from `sanitized`,
- `spotlight` — wrap it with the existing `spotlight` datamark marker so it reads as inert data.

Thread the decoded-blob spans + sub-verdict from `analyzeL2` (`src/tiers/l2.ts`) back into
`guard.ts`; add `neutralized: boolean` to `GuardResult` and an
`encoded_payload_neutralized` reason when it fires.

**FP discipline.** Only fires on blobs that *themselves* re-scan as malicious — benign
base64 (images, hashes) is untouched. Default off, so zero impact unless opted in.

**Verification.** `tests/l2.test.ts` cases: malicious base64 → `sanitized` no longer decodes
to the attack; benign base64 image → unchanged. Add a bench view comparing recall with/without
neutralization on the encoded-attack slice.

---

### 3. Taint / provenance tracking for indirect injection

**Problem.** PLAN.md calls indirect injection "the XSS of the AI-agent era" and ranks agent
goal-hijacking #1, but each `check()` is isolated — there is no notion that content which
entered as `retrieved`/`tool`/`web`/`email` must never gain instruction authority later in the
agent loop.

**Change.** New subpath **`opensentry/taint`**. JS can't do true taint propagation, so ship an
explicit **provenance-passing** API (honest about being heuristic, not magic):

```ts
// opensentry/taint
export interface TaintTracker {
  mark(text: string, source: Source): string;        // registers untrusted-origin spans
  originOf(text: string): Source | undefined;         // best-effort substring lookup
  containsTainted(text: string): { tainted: boolean; sources: Source[] };
}
export function createTaintTracker(): TaintTracker;
```

Extend `guard.checkToolCall` ([src/guard.ts](src/guard.ts), `checkToolCall`) and the egress
path to accept an optional tracker: if a tool's args (or an outbound action) contain
untrusted-origin text, emit `tainted_data_flow` and, under `highRiskAction`/`failMode:'closed'`,
fail closed. This is the single biggest agentic win and is **low-FP** (it's policy, not a
classifier).

**FP discipline.** Flags *data flow into privileged actions*, not content. No effect unless a
tracker is wired and a tool call is gated.

**Verification.** `tests/taint.test.ts`: retrieved content reaching `sendEmail` args →
`tainted_data_flow` + block under `highRiskAction`; trusted system text → allowed.

---

## P1 — high value, contained FP risk

### 4. Canary tokens for system-prompt-leak detection

**Problem.** System-prompt extraction is currently caught only heuristically (L3 regex,
[src/tiers/l3.ts:143](src/tiers/l3.ts#L143)). A canary makes leakage **deterministic and
zero-FP**.

**Change.** New subpath **`opensentry/canary`**:

```ts
export function createCanary(): string;                       // unique unguessable nonce
export function injectCanary(systemPrompt: string, canary: string): string;
export function detectCanaryLeak(output: string, canaries: string[]):
  { leaked: boolean; canary?: string; span?: [number, number] };
```

Wire `detectCanaryLeak` into the egress / output-scan path; on a hit emit `canary_leak`
(`hardBlock: true`) — a confirmed extraction, not a guess.

**FP discipline.** A random nonce appearing in output is, by construction, near-zero FP.
Deterministic hard-block is justified here (unlike content heuristics).

**Verification.** `tests/canary.test.ts`: output echoing the canary → `canary_leak` block;
benign output → allow. Document the assemble-time integration in
`opensentry/prompt` (`assemble` can auto-inject a canary into `system`).

### 5. Secret / PII egress scanning

**Problem.** `egress/index.ts` blocks exfil **URLs** but not the **payload** — an injection
that makes the model print an API key, JWT, or PII into a normal reply sails through.

**Change.** Extend `EgressPolicy` ([src/egress/index.ts:8](src/egress/index.ts#L8)):

```ts
export interface EgressPolicy {
  allowlist: (string | RegExp)[];
  stripDisallowed?: boolean;
  scanSecrets?: boolean;                 // key formats + high-entropy token runs
  scanPii?: boolean | RegExp[];          // emails/phones/cards/SSN; BYO patterns
}
```

Detectors: known key shapes (AWS, GitHub `ghp_`, OpenAI `sk-`, JWT, generic high-entropy
runs ≥ N chars) → `secret_egress`; PII patterns → `pii_egress`. Reuse the existing Shannon
entropy helper from L2 for the high-entropy-run signal (no new dep).

**FP discipline.** Output-side, so FP cost = blocking a response → **default flag-not-block**;
`scanPii` defaults off (locale/format-sensitive). Allowlist for known-safe tokens.

**Verification.** `tests/egress.test.ts` additions: leaked `sk-...`/JWT → `secret_egress`;
prose with the word "key" → no FP; an email under `scanPii:true` → `pii_egress`.

### 6. Tokenizer-aware special-token detection

**Problem.** Normalization is char-level, but the model reads **tokens**. L3
([src/tiers/l3.ts](src/tiers/l3.ts)) catches a handful of template markers via regex but not
the open-ended special-token vocabulary of arbitrary tokenizers (`<|endoftext|>`, `<|eot_id|>`,
`<|system|>`, reserved/added tokens) — and a regex list can't track every model's vocab.

**Change.**
- **Tier 0 (zero-dep):** add a configurable `normalize.specialTokens?: string[]` scanned on the
  matching copy → `special_token_injection`. Ship a sensible default list (common chat-template
  control tokens across Llama/Qwen/GPT/Mistral families).
- **Tier 1 (optional):** a pluggable tokenizer hook on `LocalModelDetector` that flags **any**
  special/added/reserved token id in untrusted input — the token-level analogue of char-level
  normalization. Stays in the Node/wasm ML subpaths (needs a tokenizer), never in core.

**FP discipline.** Control tokens have essentially zero legitimate use in untrusted user data;
high weight on `tool`/`retrieved`/`web` sources, lower on `user` prose to avoid flagging people
who legitimately type `<|...|>`.

**Verification.** `tests/l3.test.ts` cases for each default special token; bench slice on the
template-forgery attack category.

---

## P2 — robustness hardening (the detectors themselves are attackable)

### 7. SmoothLLM-style consensus for high-risk paths

**Problem.** The Tier-1 classifier is adversarially fragile — GCG suffixes are tuned to flip
exactly that kind of model.

**Change.** Add `smoothing?: { n?: number; perturbation?: number }` to `LocalModelDetector`
([src/types.ts:107](src/types.ts#L107)). When `highRiskAction` is set, run `n` lightly-perturbed
copies (char swap/drop) through `classify` and take the majority/mean — adversarial suffixes are
brittle to perturbation, benign text is not.

**FP discipline.** Gated to `highRiskAction` only → latency and FP cost stay off the common path.

**Verification.** `tests/ml.test.ts` with a stub runner: a fragile high-score-on-exact /
low-on-perturbed input is caught by consensus; benign stays benign. Bench the latency delta on
the high-risk slice.

### 8. Cheap GCG / token-salad signal (no LM in the hot path)

**Problem.** Optimizer-generated suffixes read as garbage to humans but flip models. PLAN.md
deliberately excluded perplexity (no LM on the hot path) — but a zero-LM proxy is nearly free.

**Change.** New L2 stat in `src/tiers/l2.ts`: non-word-character ratio + char-trigram
improbability (tiny static frequency table, zero-dep) + low compression-ratio estimate →
`adversarial_suffix`, **low weight, escalation signal only** (same discipline as the existing
entropy gate).

**FP discipline.** Low weight; routes to Tier 1 rather than blocking. Tuned so code blocks,
base64, and hashes (already common in benign traffic) don't over-trip — measured on the benign
corpus before merge.

**Verification.** `tests/l2.test.ts`: a known GCG suffix raises the signal; source code / JSON /
base64 image do not. Bench recall delta on the AdvBench/GCG slice vs. NotInject over-defense.

---

## Suggested sequencing

1. **#3 (taint) + #1 (session)** first — the difference between "good input filter" and
   "agentic-safe system"; both low-FP architectural additions, not fragile heuristics.
2. **#2 (neutralize) + #4 (canary)** — quick, near-zero-FP wins (a few days each).
3. **#5 (secret/PII egress) + #6 (special tokens)** — contained-FP detection upgrades.
4. **#7 (smoothing) + #8 (GCG signal)** — robustness polish; do last, behind the highRiskAction
   gate, once the corpus exists to measure them.

Each item ships behind a default-off flag or a new subpath, so none regresses the zero-config
Tier-0 path or the existing CI gates. Every detection-side item adds both an attack fixture
**and** a benign/over-defense fixture, and must clear the FPR < 1% / NotInject < 5% gates before
merge — same release discipline as the rest of the project.

## Out of scope (flagged, not silently dropped)

- **True automatic taint propagation** — impossible in JS without language/runtime support;
  #3 ships explicit provenance-passing instead, and says so.
- **Full perplexity scoring** — still excluded from the hot path (PLAN.md §10 rationale stands);
  #8 is a zero-LM proxy, not a real LM.
- **Distributed session state** — #1 ships an in-memory store + a `SessionStore` interface; the
  actual Redis/DB backend is the integrator's, not bundled.
- **A harmful-content classifier in Tier 0** — rejected again here for the same reason
  IMPROVEMENTS_PLAN.md rejected it: it re-introduces NotInject over-defense. Harmful-intent
  detection stays Tier 1's job.
```
