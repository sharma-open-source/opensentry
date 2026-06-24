import { hashStr, LRU } from './cache.js';
import { resolveConfig, resolveSourcePolicy } from './config.js';
import { DEFAULT_ATTACK_CORPUS, embeddingMatchScore } from './embedding/index.js';
import { chunkText } from './ml/chunker.js';
import { CircuitBreaker } from './ml/circuit-breaker.js';
import { getRunner, warmRunner } from './ml/singleton.js';
import { normalizeInput } from './normalize/normalize.js';
import { mkReason } from './reason.js';
import { aggregateScore, decideVerdict } from './scoring.js';
import { spotlight } from './spotlight/index.js';
import { frontGate } from './tiers/l0.js';
import { analyzeL2 } from './tiers/l2.js';
import { scanRegex } from './tiers/l3.js';
import type {
  EmbeddingCorpusDetector,
  Guard,
  GuardConfig,
  GuardContext,
  GuardMetric,
  GuardResult,
  LocalModelDetector,
  LocalModelResult,
  Reason,
  RemoteGuardDetector,
  Source,
  Thresholds,
  Verdict,
  WrapOptions,
} from './types.js';

export class GuardBlockError extends Error {
  readonly result: GuardResult;
  constructor(result: GuardResult) {
    super('opensentry: input blocked by guard');
    this.name = 'GuardBlockError';
    this.result = result;
  }
}

const DEFAULT_SOURCE: Source = 'user';

// High-resolution timer via the Web-standard `performance` global (present on globalThis
// in Node 16+, Deno, Bun, and Web Workers). Accessed through globalThis so the core has
// zero dependency on @types/node and stays edge-portable.
const PERF: { now(): number } | undefined = (globalThis as { performance?: { now(): number } })
  .performance;
function nowMs(): number {
  return PERF ? PERF.now() : Date.now();
}

// Race a promise against a timeout. The timer is cleared on settlement so no
// dangling unhandled rejection leaks. setTimeout is a universal global (Node + edge).
function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} timeout after ${timeoutMs}ms`));
    }, timeoutMs);
    promise.then(
      (val) => {
        clearTimeout(timer);
        resolve(val);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

// Run ML classification on text, chunking if >512 tokens. Chunks run in parallel;
// the max malicious score across chunks is taken (most conservative — PLAN.md §5).
async function classifyChunked(
  runner: { classify(text: string): Promise<LocalModelResult> },
  text: string,
  timeoutMs: number,
): Promise<LocalModelResult> {
  const chunks = chunkText(text);
  if (chunks.length === 1) {
    return withTimeout(runner.classify(chunks[0]!), timeoutMs, 'ML classify');
  }
  const results = await Promise.all(
    chunks.map((c) => withTimeout(runner.classify(c), timeoutMs, 'ML classify')),
  );
  let max: LocalModelResult | undefined;
  let totalLatency = 0;
  for (const r of results) {
    totalLatency += r.latencyMs;
    if (!max || r.score > max.score) max = r;
  }
  if (!max) throw new Error('ML classify returned no results');
  return {
    score: max.score,
    label: max.label,
    latencyMs: totalLatency / results.length,
  };
}

export function createGuard(config?: GuardConfig): Guard {
  const cfg = resolveConfig(config);
  const cache = new LRU<string, GuardResult>(cfg.cacheMax);
  const hasAsyncDetector = cfg.detectors.some((d) => d.kind !== 'heuristics');

  // Find the localModel / remoteGuard detectors (if any). At most one of each is supported.
  const localModelDetector = cfg.detectors.find(
    (d): d is LocalModelDetector => d.kind === 'localModel',
  );
  const remoteGuardDetector = cfg.detectors.find(
    (d): d is RemoteGuardDetector => d.kind === 'remoteGuard',
  );
  const embeddingCorpusDetector = cfg.detectors.find(
    (d): d is EmbeddingCorpusDetector => d.kind === 'embeddingCorpus',
  );

  // Circuit breakers — per-guard instance, per-tier. Opens after 5 consecutive
  // failures, half-open probe after 30s cooldown.
  const mlCircuitBreaker = new CircuitBreaker();
  const remoteCircuitBreaker = new CircuitBreaker();
  const embeddingCircuitBreaker = new CircuitBreaker();

  // warmOnBoot: fire-and-forget runner loading + warm inference. The first check()
  // that needs ML will await getRunner() (same cached promise).
  if (localModelDetector?.warmOnBoot) {
    warmRunner(localModelDetector).catch(() => {
      // Swallow — the first check() will surface the error via degraded fallback.
    });
  }

  function emitMetric(
    result: GuardResult,
    ctx: GuardContext | undefined,
    cached: boolean,
    escalated: boolean,
  ): void {
    if (!cfg.onMetric) return;
    const reasons: Reason['code'][] = result.reasons.map((r) => r.code);
    const m: GuardMetric = {
      source: result.source,
      tier: result.tier,
      latencyMs: result.latencyMs,
      verdict: result.verdict,
      wouldVerdict: result.wouldVerdict,
      score: result.score,
      escalated,
      cached,
      truncated: result.truncated,
      reasons,
    };
    if (ctx?.requestId) m.requestId = ctx.requestId;
    if (ctx?.conversationId) m.conversationId = ctx.conversationId;
    if (result.degraded) m.degraded = result.degraded;
    cfg.onMetric(m);
  }

  // Run the full Tier 0 pipeline (L0→L1→L2→L3 + scoring). No cache, no I/O.
  function runTier0(input: string, ctx: GuardContext | undefined): GuardResult {
    const t0 = nowMs();
    const source: Source = ctx?.source ?? DEFAULT_SOURCE;
    const sp = resolveSourcePolicy(cfg, source);

    // Trusted system prompt: never scored as an attack, but still sanitized.
    if (sp.skip) {
      const l1 = normalizeInput(input, cfg.normalize, ctx?.locale);
      const latencyMs = nowMs() - t0;
      const result: GuardResult = {
        verdict: 'allow',
        wouldVerdict: 'allow',
        score: 0,
        reasons: [],
        sanitized: l1.modelCopy,
        normalized: l1.matchingCopy,
        truncated: false,
        tier: 0,
        source,
        shadow: cfg.mode === 'shadow',
        latencyMs,
      };
      return result;
    }

    const l0 = frontGate(input, cfg.normalize);
    const l1 = normalizeInput(l0.text, cfg.normalize, ctx?.locale);
    const l2 = analyzeL2(l1.matchingCopy, l1.decodeCopy, l1.modelCopy, cfg.normalize, ctx?.locale);
    const l3 = scanRegex(l1.matchingCopy);

    const reasons: Reason[] = [...l0.reasons, ...l1.reasons, ...l2.reasons, ...l3];
    const score = aggregateScore(reasons);
    const decision = decideVerdict(
      score,
      reasons,
      sp.thresholds,
      cfg.hardBlockRules,
      cfg.mode,
      ctx?.highRiskAction ?? false,
    );

    const latencyMs = nowMs() - t0;
    const result: GuardResult = {
      verdict: decision.verdict,
      wouldVerdict: decision.wouldVerdict,
      score,
      reasons,
      sanitized: l1.modelCopy,
      normalized: l1.matchingCopy,
      truncated: l0.truncated,
      tier: 0,
      source,
      shadow: decision.shadow,
      latencyMs,
    };
    return result;
  }

  function cacheKey(source: Source, highRisk: boolean, normalized: string): string {
    return `${source}:${highRisk ? '1' : '0'}:${hashStr(normalized)}`;
  }

  function checkSyncInternal(input: string, ctx: GuardContext | undefined): GuardResult {
    const source: Source = ctx?.source ?? DEFAULT_SOURCE;
    const sp = resolveSourcePolicy(cfg, source);

    // For skipped sources we don't cache (system prompts are stable but rare to re-check).
    if (sp.skip) {
      const res = runTier0(input, ctx);
      emitMetric(res, ctx, false, false);
      return res;
    }

    // Compute L0+L1 to derive the cache key (hash of normalized + source + highRisk),
    // then short-circuit L2/L3 on a hit — saves the decode-rescan + regex on repeats.
    const t0 = nowMs();
    const l0 = frontGate(input, cfg.normalize);
    const l1 = normalizeInput(l0.text, cfg.normalize, ctx?.locale);
    const key = cacheKey(source, ctx?.highRiskAction ?? false, l1.matchingCopy);
    const cached = cache.get(key);
    if (cached) {
      const res: GuardResult = { ...cached, latencyMs: nowMs() - t0 };
      emitMetric(res, ctx, true, false);
      return res;
    }

    const l2 = analyzeL2(l1.matchingCopy, l1.decodeCopy, l1.modelCopy, cfg.normalize, ctx?.locale);
    const l3 = scanRegex(l1.matchingCopy);
    const reasons: Reason[] = [...l0.reasons, ...l1.reasons, ...l2.reasons, ...l3];
    const score = aggregateScore(reasons);
    const decision = decideVerdict(
      score,
      reasons,
      sp.thresholds,
      cfg.hardBlockRules,
      cfg.mode,
      ctx?.highRiskAction ?? false,
    );
    const result: GuardResult = {
      verdict: decision.verdict,
      wouldVerdict: decision.wouldVerdict,
      score,
      reasons,
      sanitized: l1.modelCopy,
      normalized: l1.matchingCopy,
      truncated: l0.truncated,
      tier: 0,
      source,
      shadow: decision.shadow,
      latencyMs: nowMs() - t0,
    };
    cache.set(key, result);
    emitMetric(result, ctx, false, false);
    return result;
  }

  // Build a degraded result from the current verdict when a higher tier fails (circuit
  // open, timeout, provider error). PLAN.md §5: "on error/timeout fall back to [prior]
  // verdict + degraded flag (hard rules still fire)". If the source failMode is 'closed',
  // the flag band escalates to block (fail-closed — can't verify safety without that tier).
  function degradedResult(
    current: GuardResult,
    sp: { thresholds: Thresholds; failMode: 'open' | 'closed' },
    ctx: GuardContext | undefined,
    failedTier: 1 | 2,
  ): GuardResult {
    const failClosed = sp.failMode === 'closed';
    const highRisk = (ctx?.highRiskAction ?? false) || failClosed;
    const decision = decideVerdict(
      current.score,
      current.reasons,
      sp.thresholds,
      cfg.hardBlockRules,
      cfg.mode,
      highRisk,
    );
    const result: GuardResult = {
      verdict: decision.verdict,
      wouldVerdict: decision.wouldVerdict,
      score: current.score,
      reasons: current.reasons,
      sanitized: current.sanitized,
      normalized: current.normalized,
      truncated: current.truncated,
      tier: failedTier,
      source: current.source,
      shadow: decision.shadow,
      latencyMs: current.latencyMs,
    };
    result.degraded = { tier: failedTier, reason: 'degraded_mode' };
    return result;
  }

  // Tier 2 escalation (PLAN.md §5 Tier 2): fired only when still borderline after Tier 1
  // (or Tier 0 if no Tier 1 is configured) or when gating a highRiskAction (pre-tool-call /
  // pre-egress). Never synchronous on the common path. The judge's own output is itself
  // injectable/nondeterministic, so it is folded as ONE weighted signal, never an
  // unconditional block (PLAN.md §5 Tier 2 caveat). Untrusted content is spotlight-delimited
  // before being handed to the provider.
  async function escalateToRemote(
    current: GuardResult,
    ctx: GuardContext | undefined,
    detector: RemoteGuardDetector,
    sp: { thresholds: Thresholds; failMode: 'open' | 'closed' },
  ): Promise<GuardResult> {
    const timeoutMs = detector.timeoutMs ?? 500;
    const useBreaker = detector.circuitBreaker ?? true;
    const effectiveFailMode = detector.failMode ?? sp.failMode;
    const policy = { thresholds: sp.thresholds, failMode: effectiveFailMode };

    if (useBreaker && !remoteCircuitBreaker.canAttempt(nowMs())) {
      return degradedResult(current, policy, ctx, 2);
    }

    try {
      const spotlighted = spotlight(current.sanitized, { mode: 'delimit' });
      const remoteResult = await withTimeout(
        detector.provider.scan(spotlighted.text, ctx ?? {}),
        timeoutMs,
        `remote guard (${detector.provider.name})`,
      );
      if (useBreaker) remoteCircuitBreaker.recordSuccess();

      const remoteReason = mkReason(
        'remote_guard',
        'semantic',
        remoteResult.score,
        `Remote guard ${detector.provider.name}: ${remoteResult.label ?? 'unknown'} (p=${remoteResult.score.toFixed(3)})`,
      );
      const allReasons = [...current.reasons, remoteReason];
      const newScore = aggregateScore(allReasons);
      const decision = decideVerdict(
        newScore,
        allReasons,
        sp.thresholds,
        cfg.hardBlockRules,
        cfg.mode,
        ctx?.highRiskAction ?? false,
      );
      return {
        ...current,
        verdict: decision.verdict,
        wouldVerdict: decision.wouldVerdict,
        score: newScore,
        reasons: allReasons,
        tier: 2,
        shadow: decision.shadow,
      };
    } catch {
      if (useBreaker) remoteCircuitBreaker.recordFailure(nowMs());
      return degradedResult(current, policy, ctx, 2);
    }
  }

  // Run Tier 1 ML on the current result if escalation is warranted. Returns the (possibly
  // unchanged) result plus whether ML actually executed.
  async function maybeEscalateToMl(
    current: GuardResult,
    ctx: GuardContext | undefined,
    detector: LocalModelDetector,
    sp: ReturnType<typeof resolveSourcePolicy>,
  ): Promise<{ result: GuardResult; escalated: boolean }> {
    const isHighRisk = ctx?.highRiskAction === true;
    const needsEscalation =
      sp.alwaysEscalate ||
      current.wouldVerdict === 'flag' ||
      (isHighRisk && current.wouldVerdict !== 'allow');

    if (!needsEscalation) return { result: current, escalated: false };

    const timeoutMs = detector.timeoutMs ?? 5000;

    if (!mlCircuitBreaker.canAttempt(nowMs())) {
      return { result: degradedResult(current, sp, ctx, 1), escalated: true };
    }

    try {
      const runner = await getRunner(detector);
      const mlResult = await classifyChunked(runner, current.sanitized, timeoutMs);
      mlCircuitBreaker.recordSuccess();

      // Score folding: ML malicious probability → Reason → re-aggregate via noisy-OR →
      // re-decide verdict. The ML score is one weighted signal, never a replacement for
      // Tier 0 evidence (PLAN.md §5: "folded into the score, does not replace Tier-0 evidence").
      const mlReason: Reason = mkReason(
        'ml_classifier',
        'semantic',
        mlResult.score,
        `ML classifier: ${mlResult.label} (p=${mlResult.score.toFixed(3)}, latency=${mlResult.latencyMs.toFixed(1)}ms)`,
      );
      const allReasons = [...current.reasons, mlReason];
      const newScore = aggregateScore(allReasons);
      const decision = decideVerdict(
        newScore,
        allReasons,
        sp.thresholds,
        cfg.hardBlockRules,
        cfg.mode,
        ctx?.highRiskAction ?? false,
      );
      return {
        result: {
          ...current,
          verdict: decision.verdict,
          wouldVerdict: decision.wouldVerdict,
          score: newScore,
          reasons: allReasons,
          tier: 1,
          shadow: decision.shadow,
        },
        escalated: true,
      };
    } catch {
      // ML failure (timeout, model error, package missing) — degraded fallback.
      mlCircuitBreaker.recordFailure(nowMs());
      return { result: degradedResult(current, sp, ctx, 1), escalated: true };
    }
  }

  // Embedding-similarity ensemble (PLAN.md §5/§12 Phase 4 "optional embedding-similarity
  // ensemble"): compares the input against a reference corpus of canonical attack phrases via
  // BYO `embed`. Same escalation gate, score-folding, circuit breaker, and degraded-fallback
  // shape as the other tiers — folded as one weighted signal, never a replacement. Grouped with
  // Tier 2 in the plan, so it reports tier 2 when it fires.
  async function maybeEscalateToEmbedding(
    current: GuardResult,
    ctx: GuardContext | undefined,
    detector: EmbeddingCorpusDetector,
    sp: ReturnType<typeof resolveSourcePolicy>,
  ): Promise<{ result: GuardResult; escalated: boolean }> {
    const isHighRisk = ctx?.highRiskAction === true;
    const needsEscalation =
      sp.alwaysEscalate ||
      current.wouldVerdict === 'flag' ||
      (isHighRisk && current.wouldVerdict !== 'allow');

    if (!needsEscalation) return { result: current, escalated: false };

    const timeoutMs = detector.timeoutMs ?? 2000;
    const corpus = detector.corpus ?? DEFAULT_ATTACK_CORPUS;
    const topK = detector.topK ?? 5;

    if (!embeddingCircuitBreaker.canAttempt(nowMs())) {
      return { result: degradedResult(current, sp, ctx, 2), escalated: true };
    }

    try {
      const score = await withTimeout(
        embeddingMatchScore(detector.embed, current.sanitized, corpus, topK),
        timeoutMs,
        'embedding corpus match',
      );
      embeddingCircuitBreaker.recordSuccess();

      const reason = mkReason(
        'embedding_match',
        'semantic',
        score,
        `Embedding-corpus match: top-${topK} avg cosine similarity ${score.toFixed(3)} to known attacks`,
      );
      const allReasons = [...current.reasons, reason];
      const newScore = aggregateScore(allReasons);
      const decision = decideVerdict(
        newScore,
        allReasons,
        sp.thresholds,
        cfg.hardBlockRules,
        cfg.mode,
        ctx?.highRiskAction ?? false,
      );
      return {
        result: {
          ...current,
          verdict: decision.verdict,
          wouldVerdict: decision.wouldVerdict,
          score: newScore,
          reasons: allReasons,
          tier: 2,
          shadow: decision.shadow,
        },
        escalated: true,
      };
    } catch {
      embeddingCircuitBreaker.recordFailure(nowMs());
      return { result: degradedResult(current, sp, ctx, 2), escalated: true };
    }
  }

  // Full async pipeline chaining Tier 0 -> conditional Tier 1 (ML) -> conditional Tier 2
  // (remote guard). PLAN.md §5:
  // - Tier 1 fires on the uncertain band (flag) or alwaysEscalate sources, folds its
  //   probability into the score via noisy-OR (never replaces Tier 0 evidence).
  // - Tier 2 fires only when still borderline after Tier 1 (or after Tier 0 if no Tier 1
  //   is configured) or when gating a highRiskAction — never on the common path.
  // - Both tiers: circuit breaker + timeout + degraded fallback, fed the normalized model copy.
  async function checkAsyncInternal(
    input: string,
    ctx: GuardContext | undefined,
    localDetector: LocalModelDetector | undefined,
    remoteDetector: RemoteGuardDetector | undefined,
    embeddingDetector: EmbeddingCorpusDetector | undefined,
  ): Promise<GuardResult> {
    const source: Source = ctx?.source ?? DEFAULT_SOURCE;
    const sp = resolveSourcePolicy(cfg, source);

    // Skipped sources: never scored as an attack (system prompt is trusted).
    if (sp.skip) {
      const res = runTier0(input, ctx);
      emitMetric(res, ctx, false, false);
      return res;
    }

    // Cache check — cached results already include any tier that ran.
    const t0 = nowMs();
    const l0 = frontGate(input, cfg.normalize);
    const l1 = normalizeInput(l0.text, cfg.normalize, ctx?.locale);
    const key = cacheKey(source, ctx?.highRiskAction ?? false, l1.matchingCopy);
    const cached = cache.get(key);
    if (cached) {
      const res: GuardResult = { ...cached, latencyMs: nowMs() - t0 };
      emitMetric(res, ctx, true, false);
      return res;
    }

    // Run Tier 0 full pipeline.
    let current = runTier0(input, ctx);
    let escalated = false;

    if (localDetector) {
      const ml = await maybeEscalateToMl(current, ctx, localDetector, sp);
      current = ml.result;
      escalated = escalated || ml.escalated;
    }

    if (embeddingDetector) {
      const emb = await maybeEscalateToEmbedding(current, ctx, embeddingDetector, sp);
      current = emb.result;
      escalated = escalated || emb.escalated;
    }

    if (remoteDetector) {
      const isHighRisk = ctx?.highRiskAction === true;
      const needsRemote = current.wouldVerdict === 'flag' || isHighRisk;
      if (needsRemote) {
        current = await escalateToRemote(current, ctx, remoteDetector, sp);
        escalated = true;
      }
    }

    current.latencyMs = nowMs() - t0;
    cache.set(key, current);
    emitMetric(current, ctx, false, escalated);
    return current;
  }

  const guard: Guard = {
    checkSync(input, ctx) {
      if (hasAsyncDetector) {
        throw new Error(
          'opensentry checkSync: configured detectors include async tiers (localModel/remoteGuard/embeddingCorpus). Use check() for the full tiered pipeline, or remove async detectors for sync-only Tier 0.',
        );
      }
      return checkSyncInternal(input, ctx);
    },

    async check(input, ctx) {
      // No async detectors configured → Tier 0 only (sync path, same as checkSync).
      if (!localModelDetector && !remoteGuardDetector && !embeddingCorpusDetector) {
        return checkSyncInternal(input, ctx);
      }

      // Full async pipeline: Tier 0 -> conditional Tier 1 (ML) -> conditional embedding ensemble
      // -> conditional Tier 2 (remote).
      return checkAsyncInternal(
        input,
        ctx,
        localModelDetector,
        remoteGuardDetector,
        embeddingCorpusDetector,
      );
    },

    async checkMessages(messages: { role: Source; content: string }[]): Promise<GuardResult[]> {
      // PLAN.md §6: scores each message per its source role; skips the trusted system
      // prompt (handled by the per-source skip policy → verdict 'allow'). Uses guard.check
      // so future async tiers (Phase 3/4) are automatically engaged per message.
      return Promise.all(messages.map((msg) => guard.check(msg.content, { source: msg.role })));
    },

    createStreamScanner(ctx?: GuardContext) {
      // PLAN.md §6: streaming model-output / chunked tool content. Buffers across chunk
      // boundaries so split injection tokens are caught (e.g. "<|im_st" + "art|>").
      // Supports early-abort: abort=true when the enforced verdict reaches 'block'.
      // Uses runTier0 (no cache) for incremental pushes to avoid polluting the LRU with
      // partial buffers; end() runs the full pipeline with cache + metrics.
      let buffer = '';
      let worst: Verdict = 'allow';
      const rank = (v: Verdict): number => (v === 'block' ? 2 : v === 'flag' ? 1 : 0);

      return {
        push(chunk: string): { partial: Verdict; abort: boolean } {
          buffer += chunk;
          const r = runTier0(buffer, ctx);
          if (rank(r.verdict) > rank(worst)) worst = r.verdict;
          return { partial: worst, abort: worst === 'block' };
        },
        end(): GuardResult {
          return checkSyncInternal(buffer, ctx);
        },
      };
    },

    wrap<A extends unknown[], R>(fn: (...a: A) => Promise<R>, opts?: WrapOptions<A, R>) {
      const replaceWithSanitized = opts?.replaceWithSanitized ?? true;
      const wrapped = async (...args: A): Promise<R> => {
        const sel = opts?.inputSelector
          ? opts.inputSelector(...args)
          : {
              text: typeof args[0] === 'string' ? (args[0] as string) : String(args[0] ?? ''),
              ctx: undefined,
            };
        const result = await guard.check(sel.text, sel.ctx);
        if (result.verdict === 'block') {
          if (opts?.onBlock) return (await opts.onBlock(result, ...args)) as R;
          throw new GuardBlockError(result);
        }
        if (result.verdict === 'flag' && opts?.onFlag) opts.onFlag(result, ...args);
        const newArgs = (replaceWithSanitized ? [result.sanitized, ...args.slice(1)] : args) as A;
        return fn(...newArgs);
      };
      return wrapped;
    },

    // Tool-call guard (PLAN.md §11a, §5 Tier 2): least-privilege assist — scans the
    // call's args through the full pipeline and enforces an allowlist of tool names
    // BEFORE execution. highRiskAction is forced so the flag band fails closed (and,
    // if a remote/local tier is configured, escalates rather than passing silently).
    // The privilege model itself (what a tool is actually allowed to do) stays in your runtime.
    async checkToolCall(call, policy) {
      if (!(call.name in policy.allow)) {
        const reason = mkReason(
          'agentic_tool_hijack',
          'structural',
          1,
          `Tool "${call.name}" is not in the allowlist`,
        );
        const decision = decideVerdict(
          1,
          [reason],
          cfg.thresholds,
          cfg.hardBlockRules,
          cfg.mode,
          true,
        );
        const result: GuardResult = {
          verdict: decision.verdict,
          wouldVerdict: decision.wouldVerdict,
          score: 1,
          reasons: [reason],
          sanitized: '',
          normalized: '',
          truncated: false,
          tier: 0,
          source: 'tool',
          shadow: decision.shadow,
          latencyMs: 0,
        };
        return result;
      }

      const argsText = typeof call.args === 'string' ? call.args : JSON.stringify(call.args ?? {});
      return guard.check(argsText, { source: 'tool', highRiskAction: true });
    },
  };

  return guard;
}
