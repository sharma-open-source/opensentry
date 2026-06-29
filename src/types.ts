// Public type surface of opensentry.
// Pure types only; no runtime here so it is side-effect free and tree-shakeable.

export type Verdict = 'allow' | 'flag' | 'block';
export type Tier = 0 | 1 | 2; // 0=sync heuristics, 1=local ML, 2=remote
export type Source = 'system' | 'user' | 'retrieved' | 'tool' | 'web' | 'email';
export type Mode = 'shadow' | 'soft' | 'enforce';

export type ReasonCode =
  | 'unicode_tag_smuggling'
  | 'bidi_override'
  | 'invisible_density'
  | 'zero_width_chars'
  | 'confusable_run'
  | 'script_mixing'
  | 'encoded_payload'
  | 'encoded_payload_neutralized'
  | 'entropy_anomaly'
  | 'adversarial_suffix'
  | 'role_tag_spoof'
  | 'template_forgery'
  | 'special_token_injection'
  | 'instruction_override'
  | 'persona_jailbreak'
  | 'policy_puppetry'
  | 'exfil_markdown_image'
  | 'exfil_url_lure'
  | 'refusal_suppression'
  | 'agentic_tool_hijack'
  | 'indirect_marker'
  | 'length_cap'
  | 'lang_divergence'
  | 'ml_classifier'
  | 'remote_guard'
  | 'embedding_match'
  | 'degraded_mode'
  | 'session_escalation'
  | 'manyshot_density'
  | 'cumulative_risk'
  | 'tainted_data_flow'
  | 'canary_leak'
  | 'secret_egress'
  | 'pii_egress';

export type ReasonCategory = 'obfuscation' | 'structural' | 'semantic' | 'exfil' | 'resource';

export interface Reason {
  code: ReasonCode;
  category: ReasonCategory;
  weight: number; // contribution to score [0..1]
  span?: [start: number, end: number]; // offsets into the matching (normalized) copy
  message: string; // human-readable, for appeals/debug
  hardBlock?: boolean; // deterministic hard rule (blocks even in fail-open)
}

export interface GuardResult {
  verdict: Verdict; // ENFORCED decision (respects shadow/soft mode)
  wouldVerdict: Verdict; // decision BEFORE shadow override — for shadow-mode logging
  score: number; // 0..1 aggregated weighted evidence (max-aggregate)
  reasons: Reason[];
  sanitized: string; // MODEL copy: normalized, invisible-stripped — pass THIS downstream
  normalized: string; // MATCHING copy (folded/casefolded) — audit/debug
  truncated: boolean;
  tier: Tier; // highest tier that actually executed
  source: Source;
  shadow: boolean; // true => verdict was NOT enforced
  mode?: Mode; // the guard's resolved mode ('shadow'|'soft'|'enforce'); lets wrappers (session guard) re-decide without collapsing soft→enforce
  degraded?: { tier: Tier; reason: ReasonCode }; // a tier failed open — surfaced, never silent
  neutralized?: boolean; // an encoded payload in the model copy was stripped/spotlighted
  latencyMs: number;
}

export interface GuardContext {
  source?: Source; // default 'user'; drives per-source policy + thresholds
  locale?: string; // enables RTL-aware bidi + locale-aware script/lang gates
  highRiskAction?: boolean; // forces escalation + fail-closed (pre-tool-call gating)
  conversationId?: string; // multi-turn / cache keying
  requestId?: string;
}

export interface Thresholds {
  flag: number;
  block: number;
} // default { flag: 0.4, block: 0.85 }

// Tier 2 is BYO-provider. opensentry ships this interface + thin reference adapters; YOU decide
// if/when to enable it. Nothing is sent off-box unless you pass a provider here.
export interface RemoteGuardProvider {
  name: string;
  scan(
    text: string,
    ctx: GuardContext,
  ): Promise<{
    score: number; // 0..1 malicious probability, folded into the score
    label?: 'benign' | 'injection' | 'jailbreak' | (string & {});
    categories?: string[]; // optional policy-category labels
    raw?: unknown; // provider's raw payload, for logging
  }>;
}

export interface HeuristicsDetector {
  kind: 'heuristics';
} // Tier 0, sync, always edge-safe

// Tier 1 — local ML classifier result (Llama-Prompt-Guard-2-22M/86M).
export interface LocalModelResult {
  score: number; // 0..1 — probability the text is injection/malicious
  label: 'benign' | 'injection';
  latencyMs: number;
}

// Pluggable runner interface — implemented by opensentry/onnx (Node) and opensentry/wasm (edge).
// Users can also provide a custom runner via LocalModelDetector.runner for testing or custom models.
export interface LocalModelRunner {
  readonly loaded: boolean;
  warm(): Promise<void>; // pre-load model + warm JIT caches
  classify(text: string): Promise<LocalModelResult>;
  dispose(): void; // release model resources
}

export interface LocalModelDetector {
  kind: 'localModel';
  model?: 'llama-prompt-guard-2-22m' | 'llama-prompt-guard-2-86m';
  runtime?: 'node' | 'wasm';
  quantized?: boolean;
  warmOnBoot?: boolean;
  timeoutMs?: number;
  runner?: LocalModelRunner; // explicit runner — skips lazy import of opensentry/onnx or opensentry/wasm
  // Floor below which the ML score is treated as 0 before folding into the aggregate score
  // (default 0 — no change). The global flag/block thresholds are tuned against Tier 0's
  // structural evidence; a given model's moderate-confidence scores may not be reliable
  // enough to clear that bar without raising over-defense (see bench/REPORT.md). Derive a
  // value from your own corpus via bench/metrics.ts's recallAtFpr sweep — this is model- and
  // export-specific, there is no universal default.
  minConfidence?: number;
  // SmoothLLM-style consensus: when highRiskAction is set,
  // run `n` lightly-perturbed copies through the classifier and take the majority/mean.
  // Adversarial suffixes (GCG) are brittle to perturbation; benign text is not. Stays off
  // the common (non-high-risk) path. Default off.
  smoothing?: { n?: number; perturbation?: number };
}

export interface RemoteGuardDetector {
  kind: 'remoteGuard';
  provider: RemoteGuardProvider;
  timeoutMs?: number; // default 500
  circuitBreaker?: boolean;
  failMode?: 'open' | 'closed';
}

export interface EmbeddingCorpusDetector {
  kind: 'embeddingCorpus';
  embed: (s: string) => Promise<number[]>;
  topK?: number;
  timeoutMs?: number; // default 2000
  corpus?: string[]; // override the bundled reference attack corpus
}

export type Detector =
  | HeuristicsDetector
  | LocalModelDetector
  | RemoteGuardDetector
  | EmbeddingCorpusDetector;

export interface GuardMetric {
  requestId?: string;
  conversationId?: string;
  source: Source;
  tier: Tier; // highest tier that actually executed
  latencyMs: number;
  verdict: Verdict;
  wouldVerdict: Verdict;
  score: number;
  escalated: boolean; // a higher tier was invoked
  cached: boolean;
  truncated: boolean;
  degraded?: { tier: Tier; reason: ReasonCode };
  reasons: ReasonCode[];
}

export interface PerSourcePolicy {
  thresholds?: Partial<Thresholds>;
  alwaysEscalate?: boolean; // retrieved/tool/web/email default true
  skip?: boolean; // system default true (never scored as attack)
  failMode?: 'open' | 'closed';
}

export interface GuardConfig {
  mode?: Mode; // default 'enforce'; 'shadow' computes but never blocks
  thresholds?: Partial<Thresholds>; // ship low-FP profiles, never a naive 0.5
  policy?: {
    failMode?: 'open' | 'closed'; // default 'open'
    hardBlockRules?: ReasonCode[] | true; // fire even when failMode==='open'; default the det. set
    perSource?: Partial<Record<Source, PerSourcePolicy>>;
  };
  normalize?: {
    nfkc?: boolean;
    stripInvisible?: boolean;
    foldConfusables?: boolean; // matching copy only
    handleBidi?: 'strip' | 'isolate' | 'off';
    decodeEncoded?: boolean;
    decodeDepth?: number; // default 2
    maxScanBytes?: number; // default 65536, truncate-with-flag
    rtlLocales?: string[];
    neutralizeEncoded?: 'off' | 'strip' | 'spotlight'; // neutralize the MODEL copy when a decoded blob re-scans as malicious; default 'off'
    specialTokens?: string[]; // tokenizer control tokens scanned on the matching copy → special_token_injection
    scanAdversarialSuffix?: boolean; // enable the cheap GCG/token-salad L2 signal (adversarial_suffix); default false (off the Tier-0 hot path)
  };
  // Detectors are pluggable + lazily loaded from subpath exports.
  detectors?: Detector[]; // default [{ kind: 'heuristics' }]
  cache?: {
    max?: number;
  }; // LRU of verdicts by hash(normalized + source)
  onMetric?: (m: GuardMetric) => void; // per-tier latency, escalation rate, tier-agreement…
}

export interface WrapOptions<A extends unknown[], R = unknown> {
  inputSelector?: (...a: A) => { text: string; ctx?: GuardContext };
  onFlag?: (r: GuardResult, ...a: A) => void;
  onBlock?: (r: GuardResult, ...a: A) => R | Promise<R>;
  replaceWithSanitized?: boolean; // default true
}

export interface Guard {
  // Tier-0 ONLY, sync, edge-safe, no I/O. THROWS if any configured detector is async.
  checkSync(input: string, ctx?: GuardContext): GuardResult;

  // Full tiered pipeline (Tier 0 -> conditional Tier 1 -> conditional Tier 2), lazy-loads ML/remote.
  check(input: string, ctx?: GuardContext): Promise<GuardResult>;

  // Chat arrays: scores each message per its source role; skips the trusted system prompt.
  checkMessages(messages: { role: Source; content: string }[]): Promise<GuardResult[]>;

  // Streaming model-output / chunked tool content. Buffers across chunk boundaries so split
  // injection tokens are caught; supports early-abort.
  createStreamScanner(ctx?: GuardContext): {
    push(chunk: string): { partial: Verdict; abort: boolean };
    end(): GuardResult;
  };

  // Drop-in wrapper, quality-preserving by default: flag => passthrough sanitized (+log),
  // block => onBlock (throw GuardBlockError). Passes SANITIZED text downstream.
  wrap<A extends unknown[], R>(
    fn: (...a: A) => Promise<R>,
    opts?: WrapOptions<A, R>,
  ): (...a: A) => Promise<R>;

  // Tool-call guard (least-privilege assist): scan args through the pipeline + enforce an
  // allowlist of tools/arg-shapes BEFORE execution. (Phase 4)
  // The optional `opts.tracker` (opensentry/taint) emits `tainted_data_flow` and fails closed
  // when untrusted-origin text reaches a privileged tool call.
  checkToolCall(
    call: { name: string; args: unknown },
    policy: { allow: Record<string, unknown> },
    opts?: { tracker?: TaintTrackerLike },
  ): Promise<GuardResult>;
}

// Structural shape of a TaintTracker (from opensentry/taint) re-declared here so the core
// Guard interface can reference it WITHOUT a runtime import (type-only). keeps the core
// edge-safe and avoids a circular subpath dependency.
export interface TaintTrackerLike {
  containsTainted(text: string): { tainted: boolean; sources: Source[]; marks: unknown[] };
}
