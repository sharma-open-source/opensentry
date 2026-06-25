# Deployment

Tier 0 is zero-dependency and runs identically everywhere. The ML and remote tiers are
**progressive enhancements** — add them via config, call sites never change. This page
covers the runtime choices, peer dependencies, and the optional tiers.

## Runtimes

Tier 0 core has **zero Node.js dependencies** — no `node:fs`, no `Buffer`, no `process`,
no `__dirname`. This is statically enforced by `tests/no-node-builtins.test.ts`. The
same code runs on:

- Node.js 18+
- Deno
- Bun
- Cloudflare Workers / Vercel Edge / Web Workers

```ts
// Works everywhere — no polyfills needed
import { createGuard } from 'opensentry';
const guard = createGuard();
guard.checkSync(input);
```

**Exception:** `opensentry/onnx` is a Node-only subpath (uses `onnxruntime-node` for
native ML) and is excluded from the edge-safety check. Edge users import
`opensentry/wasm` instead (uses `onnxruntime-web` / WASM SIMD).

---

## Tier 1 — local ML

Adds a local ML classifier (`Llama-Prompt-Guard-2-22M/86M`) that catches semantic
attacks regex can't — paraphrased injections, fictional framing, multilingual attacks.
See [Tier model](./tiers.md#tier-1-local-ml-optional) for when it fires.

### Installation

Tier 1 requires `@huggingface/transformers` as an optional peer dependency:

```bash
# Node (native ONNX runtime — faster)
pnpm add @huggingface/transformers onnxruntime-node

# Edge (WASM runtime — works in Workers/Vercel Edge)
pnpm add @huggingface/transformers
```

### Usage — Node

```ts
import { createGuard } from 'opensentry';

const guard = createGuard({
  detectors: [
    { kind: 'heuristics' },
    { kind: 'localModel', runtime: 'node', quantized: true, warmOnBoot: true },
  ],
});

const result = await guard.check(userInput);
// result.tier === 1 when ML was invoked
// result.reasons includes { code: 'ml_classifier', weight: <malicious probability> }
```

### Usage — Edge (Cloudflare Workers, Vercel Edge, Deno)

```ts
import { createGuard } from 'opensentry';

const guard = createGuard({
  detectors: [
    { kind: 'heuristics' },
    { kind: 'localModel', runtime: 'wasm', quantized: true, warmOnBoot: true },
  ],
});
```

### `LocalModelDetector` options

```ts
interface LocalModelDetector {
  kind: 'localModel';
  model?: 'llama-prompt-guard-2-22m' | 'llama-prompt-guard-2-86m';  // default 22m
  runtime?: 'node' | 'wasm';                 // default 'wasm'
  quantized?: boolean;                        // default true → dtype 'q8'
  warmOnBoot?: boolean;                       // fire-and-forget load + warm inference
  timeoutMs?: number;                         // default 5000
  minConfidence?: number;                     // default 0 — floor ML scores before folding
  smoothing?: { n?: number; perturbation?: number }; // SmoothLLM, highRiskAction only
  runner?: LocalModelRunner;                  // explicit runner — skips lazy import
}
```

| Option | Default | Notes |
|---|---|---|
| `model` | `llama-prompt-guard-2-22m` | The 86M variant is optional; see benchmark caveats |
| `runtime` | `wasm` | `node` uses `onnxruntime-node` (native); `wasm` uses `onnxruntime-web` |
| `quantized` | `true` | Maps to `dtype: 'q8'`; `false` → `dtype: 'fp32'`. Requires the model repo to ship a quantized build |
| `warmOnBoot` | `false` | Pre-loads the model + warms JIT caches fire-and-forget. First `check()` that needs ML awaits the same cached promise |
| `timeoutMs` | `5000` | On timeout, falls back to Tier 0 verdict + `degraded` |
| `minConfidence` | `0` | Floor ML scores below this to 0 before noisy-OR folding. See [calibration](./evaluation.md#calibrating-ml-confidence) |
| `smoothing` | off | SmoothLLM consensus — runs `n` perturbed copies on `highRiskAction` only. See [Security hardening](./security.md#smoothllm-consensus-tier-1-opt-in) |
| `runner` | — | Custom runner — skips the lazy import of `opensentry/onnx`/`opensentry/wasm` |

### Quantization note

`quantized: true` (the default) loads the model's `q8` build, which transformers.js
expects as a file named `model_quantized.onnx` alongside the regular `model.onnx` in
the model repo's `onnx/` directory. If a model repo only ships fp32 (no quantized
variant — true of `meta-llama/Llama-Prompt-Guard-2-22M/86M` themselves, which are
PyTorch-only and gated, with no published ONNX build), you need to produce one yourself,
e.g. via `onnxruntime.quantization.quantize_dynamic`. Quantization shrinks the model
~3.3x (284MB→87MB) with unchanged ROC-AUC, but latency barely moves on CPU for a model
this small — see [`../bench/REPORT.md`](../bench/REPORT.md) before assuming it speeds up your deployment.

### Custom runner

For testing or custom models, pass a `LocalModelRunner` directly — no lazy import:

```ts
const guard = createGuard({
  detectors: [
    { kind: 'heuristics' },
    {
      kind: 'localModel',
      runner: {
        loaded: true,
        async warm() { /* pre-load model */ },
        async classify(text) {
          return { score: 0.95, label: 'injection', latencyMs: 15 };
        },
        dispose() { /* release model */ },
      },
    },
  ],
});
```

This is the integration point for any model — fine-tuned, different family, or a
vendored ONNX export. The runner interface:

```ts
interface LocalModelRunner {
  readonly loaded: boolean;
  warm(): Promise<void>;
  classify(text: string): Promise<{ score: number; label: 'benign' | 'injection'; latencyMs: number }>;
  dispose(): void;
}
```

### Skipping the gated-model wait: an ungated mirror

The shipped default model (`meta-llama/Llama-Prompt-Guard-2-22M`/`86M`) is **gated** on
HuggingFace — every deployer must request access and wait for approval, and there's no
official ONNX build. The mirrors
[`gravitee-io/Llama-Prompt-Guard-2-22M-onnx`](https://huggingface.co/gravitee-io/Llama-Prompt-Guard-2-22M-onnx)
and [`...-86M-onnx`](https://huggingface.co/gravitee-io/Llama-Prompt-Guard-2-86M-onnx)
are **ungated** ONNX mirrors of the exact same weights (verified to match scores to 4
decimal places). They correctly carry the Llama 4 Community License + a `NOTICE` file.

This is **not** `opensentry`'s default — it's a third-party-maintained mirror outside
our supply chain. You still inherit the Llama 4 license's obligations (attribution,
"Built with Llama", the >700M-MAU clause). Wire it through the custom-runner interface
(the model files sit at the repo root, not the `onnx/` subfolder transformers.js expects
by default, so `subfolder` needs an override):

```ts
import { createGuard } from 'opensentry';
import { pipeline } from '@huggingface/transformers';

const classifier = await pipeline('text-classification', 'gravitee-io/Llama-Prompt-Guard-2-22M-onnx', {
  device: 'cpu',
  dtype: 'fp32',     // or 'q8' for their model.quant.onnx — confirm before relying on it in prod
  subfolder: '',     // files are at the repo root, not the conventional onnx/ subfolder
});

const guard = createGuard({
  detectors: [
    { kind: 'heuristics' },
    {
      kind: 'localModel',
      runner: {
        loaded: true,
        async warm() { await classifier('warmup', { top_k: 2 }); },
        async classify(text) {
          const t0 = performance.now();
          const out = await classifier(text, { top_k: 2 });
          const malicious = out.find((o) => o.label === 'MALICIOUS')?.score ?? 0;
          return { score: malicious, label: malicious > 0.5 ? 'injection' : 'benign', latencyMs: performance.now() - t0 };
        },
        dispose() { classifier.dispose?.(); },
      },
    },
  ],
});
```

### Licensing

The default `meta-llama/Llama-Prompt-Guard-2` model carries the **Llama 4 Community
License** — you inherit its obligations (attribution, "Built with Llama", the >700M-MAU
clause) regardless of whether you use the gated original or an ungated mirror. Decide
deliberately, not by default.

---

## Tier 2 — remote guard

Escalates to an external guard model or LLM-as-judge for the highest semantic ceiling.
`opensentry` ships **no vendor SDKs in core** — you supply a `RemoteGuardProvider` and
therefore decide if/when anything leaves the process. **Zero remote egress unless
explicitly wired.**

### BYO provider

```ts
import { createGuard } from 'opensentry';
import type { RemoteGuardProvider } from 'opensentry';

const provider: RemoteGuardProvider = {
  name: 'my-guard-service',
  async scan(text, ctx) {
    const res = await fetch('https://my-guard.internal/scan', {
      method: 'POST',
      body: JSON.stringify({ text }),
    });
    const json = await res.json();
    return { score: json.maliciousProbability, label: json.label };
  },
};

const guard = createGuard({
  detectors: [
    { kind: 'heuristics' },
    { kind: 'localModel', runtime: 'wasm' },
    { kind: 'remoteGuard', provider, timeoutMs: 500, circuitBreaker: true },
  ],
});

const result = await guard.check(userInput, { source: 'user' });
// result.tier === 2 when the remote guard was invoked
```

### `RemoteGuardDetector` options

```ts
interface RemoteGuardDetector {
  kind: 'remoteGuard';
  provider: RemoteGuardProvider;
  timeoutMs?: number;        // default 500
  circuitBreaker?: boolean;  // default true
  failMode?: 'open' | 'closed'; // default: per-source policy
}
```

The judge's own output is itself an LLM call (injectable, nondeterministic), so it
stays **one weighted signal in the score, never an unconditional block**. Untrusted
content is spotlight-delimited before being sent to the provider.

### Reference adapters — `opensentry/remote`

Thin, optional adapters for common provider shapes (no vendor SDKs bundled):

```ts
import { createHttpGuardProvider, createLlamaGuardChatProvider } from 'opensentry/remote';

// Generic JSON guard endpoint (Azure Prompt Shields, Lakera, Bedrock Guardrails, in-house)
const httpProvider = createHttpGuardProvider({
  name: 'lakera',
  url: 'https://api.lakera.ai/v2/guard',
  headers: { authorization: `Bearer ${process.env.LAKERA_API_KEY}` },
  parseResponse: (json) => ({ score: json.flagged ? 1 : 0, label: json.flagged ? 'injection' : 'benign' }),
});

// OpenAI-chat-compatible endpoint hosting a guard model (Llama-Guard / Prompt-Guard-2 on Groq/Together)
const judgeProvider = createLlamaGuardChatProvider({
  url: 'https://api.groq.com/openai/v1/chat/completions',
  apiKey: process.env.GROQ_API_KEY,
  model: 'meta-llama/llama-guard-4-12b',
});
```

`createHttpGuardProvider` options:

| Option | Default | Notes |
|---|---|---|
| `name` | required | Provider name (used in reasons/metrics) |
| `url` | required | Endpoint URL |
| `headers` | — | Request headers (auth, etc.) |
| `fetchImpl` | `globalThis.fetch` | Override for testing / non-browser envs |
| `buildRequest` | `(text) => ({ text })` | Customize the request body |
| `parseResponse` | required | Parse the provider's JSON into `{ score, label?, categories? }` |

`createLlamaGuardChatProvider` spotlight-delimits the untrusted text before embedding
it in the judge prompt and parses a strict-JSON `{ label, score }` response. Options:
`name`, `url`, `apiKey`, `model`, `headers`, `fetchImpl`, `spotlightMode` (default
`'delimit'`).

---

## Embedding-corpus ensemble

An additional, independent semantic signal: embed the input and compare it via cosine
similarity against a reference corpus of canonical attack phrases (or your own). BYO
`embed` — `opensentry` bundles no embedding model.

```ts
const guard = createGuard({
  detectors: [
    { kind: 'heuristics' },
    { kind: 'embeddingCorpus', embed: myEmbedFn, topK: 5, timeoutMs: 2000 },
    // corpus?: string[] to override the default reference attack corpus
  ],
});
```

### `EmbeddingCorpusDetector` options

| Option | Default | Notes |
|---|---|---|
| `embed` | required | `(s: string) => Promise<number[]>` — your embedding function |
| `topK` | `5` | Average similarity over the top-K corpus matches |
| `corpus` | bundled default | Override with your own `string[]` of reference attack phrases |
| `timeoutMs` | `2000` | On timeout, falls back to prior verdict + `degraded` |

Same shape as the other escalation tiers: fires only when still borderline (or
`alwaysEscalate` / `highRiskAction`), folds its top-K average similarity in as a
`Reason(code='embedding_match', category='semantic')` via noisy-OR, has its own circuit
breaker + timeout + degraded fallback (`degraded: { tier: 2, ... }`). Reported as
`tier: 2`. When chained with Tier 1/Tier 2, it runs **between** them — only after ML
still leaves the verdict borderline, and before the remote guard is invoked.

---

## Latency budgets

| Tier | p50 | p99 | When it runs |
|---|---|---|---|
| Tier 0 (L0–L3) | 5–30µs | **< 1ms** (few-KB input) | every request, sync |
| Tier 1 local ML | 15–60ms (WASM 22M @256tok) | 80–200ms (+50–300ms cold) | uncertain band / alwaysEscalate source |
| Tier 2 remote | 80–300ms | 300ms–1.5s+ | borderline-after-Tier-1 / `highRiskAction` |

With the default `alwaysEscalate: true` on `user`, escalation rate on `user` traffic
jumps to ~100% when an async detector is configured. Tier 1 (real
`Llama-Prompt-Guard-2-22M`, unquantized) measured at p50 ≈5.5ms / p99 ≈76ms per request
in the benchmark — factor that into your latency budget. To keep Tier 1 off the common
path for `user`, set `policy.perSource.user.alwaysEscalate: false` (trading recall for
cost — see [Evaluation](./evaluation.md#real-corpus-benchmark)).
