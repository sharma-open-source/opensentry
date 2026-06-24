import { hashStr, LRU } from './cache.js';
import { resolveConfig, resolveSourcePolicy } from './config.js';
import { chunkText } from './ml/chunker.js';
import { CircuitBreaker } from './ml/circuit-breaker.js';
import { getRunner, warmRunner } from './ml/singleton.js';
import { normalizeInput } from './normalize/normalize.js';
import { mkReason } from './reason.js';
import { aggregateScore, decideVerdict } from './scoring.js';
import { frontGate } from './tiers/l0.js';
import { analyzeL2 } from './tiers/l2.js';
import { scanRegex } from './tiers/l3.js';
import type {
  Guard,
  GuardConfig,
  GuardContext,
  GuardMetric,
  GuardResult,
  LocalModelDetector,
  LocalModelResult,
  Reason,
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

  // Find the localModel detector (if any). Phase 3 supports at most one localModel detector.
  const localModelDetector = cfg.detectors.find(
    (d): d is LocalModelDetector => d.kind === 'localModel',
  );

  // Circuit breaker for Tier 1 ML — per-guard instance. Opens after 5 consecutive
  // failures, half-open probe after 30s cooldown.
  const mlCircuitBreaker = new CircuitBreaker();

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

  // Build a degraded result from a Tier 0 verdict when Tier 1 ML fails (circuit open,
  // timeout, model error). PLAN.md §5: "on error/timeout fall back to Tier-0 verdict +
  // degraded flag (hard rules still fire)". If the source failMode is 'closed', the flag
  // band escalates to block (fail-closed — can't verify safety without ML).
  function degradedResult(
    t0Result: GuardResult,
    sp: { thresholds: Thresholds; failMode: 'open' | 'closed' },
    ctx: GuardContext | undefined,
  ): GuardResult {
    const failClosed = sp.failMode === 'closed';
    const highRisk = (ctx?.highRiskAction ?? false) || failClosed;
    const decision = decideVerdict(
      t0Result.score,
      t0Result.reasons,
      sp.thresholds,
      cfg.hardBlockRules,
      cfg.mode,
      highRisk,
    );
    const result: GuardResult = {
      verdict: decision.verdict,
      wouldVerdict: decision.wouldVerdict,
      score: t0Result.score,
      reasons: t0Result.reasons,
      sanitized: t0Result.sanitized,
      normalized: t0Result.normalized,
      truncated: t0Result.truncated,
      tier: 1,
      source: t0Result.source,
      shadow: decision.shadow,
      latencyMs: t0Result.latencyMs,
    };
    result.degraded = { tier: 1, reason: 'degraded_mode' };
    return result;
  }

  // Full async pipeline with Tier 1 ML escalation. PLAN.md §5 Tier 1:
  // - Fired only on the uncertain band (flag) or alwaysEscalate sources (retrieved/tool/web/email)
  // - ML malicious probability folded into the score via noisy-OR (does not replace Tier 0 evidence)
  // - Circuit breaker + timeout + degraded fallback
  // - Fed the normalized model copy (sanitized text)
  async function checkAsyncInternal(
    input: string,
    ctx: GuardContext | undefined,
    detector: LocalModelDetector,
  ): Promise<GuardResult> {
    const source: Source = ctx?.source ?? DEFAULT_SOURCE;
    const sp = resolveSourcePolicy(cfg, source);

    // Skipped sources: no ML (system prompt is trusted, never scored).
    if (sp.skip) {
      const res = runTier0(input, ctx);
      emitMetric(res, ctx, false, false);
      return res;
    }

    // Cache check — cached results already include ML if it was run.
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
    const t0Result = runTier0(input, ctx);

    // Escalation gate (PLAN.md §5): ML fires on the uncertain band (flag) or
    // alwaysEscalate sources (retrieved/tool/web/email). highRiskAction forces
    // escalation even when Tier 0 would-block — the ML opinion is logged + folded.
    const isHighRisk = ctx?.highRiskAction === true;
    const needsEscalation =
      sp.alwaysEscalate ||
      t0Result.wouldVerdict === 'flag' ||
      (isHighRisk && t0Result.wouldVerdict !== 'allow');

    if (!needsEscalation) {
      cache.set(key, t0Result);
      emitMetric(t0Result, ctx, false, false);
      return t0Result;
    }

    // Escalate to Tier 1 ML.
    const timeoutMs = detector.timeoutMs ?? 5000;

    // Circuit breaker — if open, skip ML entirely (degraded fallback).
    if (!mlCircuitBreaker.canAttempt(nowMs())) {
      const degraded = degradedResult(t0Result, sp, ctx);
      degraded.latencyMs = nowMs() - t0;
      cache.set(key, degraded);
      emitMetric(degraded, ctx, false, true);
      return degraded;
    }

    try {
      const runner = await getRunner(detector);
      const mlResult = await classifyChunked(runner, t0Result.sanitized, timeoutMs);
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
      const allReasons = [...t0Result.reasons, mlReason];
      const newScore = aggregateScore(allReasons);
      const newDecision = decideVerdict(
        newScore,
        allReasons,
        sp.thresholds,
        cfg.hardBlockRules,
        cfg.mode,
        ctx?.highRiskAction ?? false,
      );

      const finalResult: GuardResult = {
        verdict: newDecision.verdict,
        wouldVerdict: newDecision.wouldVerdict,
        score: newScore,
        reasons: allReasons,
        sanitized: t0Result.sanitized,
        normalized: t0Result.normalized,
        truncated: t0Result.truncated,
        tier: 1,
        source,
        shadow: newDecision.shadow,
        latencyMs: nowMs() - t0,
      };
      cache.set(key, finalResult);
      emitMetric(finalResult, ctx, false, true);
      return finalResult;
    } catch {
      // ML failure (timeout, model error, package missing) — degraded fallback.
      mlCircuitBreaker.recordFailure(nowMs());
      const degraded = degradedResult(t0Result, sp, ctx);
      degraded.latencyMs = nowMs() - t0;
      cache.set(key, degraded);
      emitMetric(degraded, ctx, false, true);
      return degraded;
    }
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
      // Phase 4 detectors — not yet implemented.
      for (const d of cfg.detectors) {
        if (d.kind === 'remoteGuard') {
          throw new Error(
            'opensentry: remoteGuard detector is not available in this build (planned Phase 4).',
          );
        }
        if (d.kind === 'embeddingCorpus') {
          throw new Error(
            'opensentry: embeddingCorpus detector is not available in this build (planned Phase 4).',
          );
        }
      }

      // No localModel detector → Tier 0 only (sync path, same as checkSync).
      if (!localModelDetector) {
        return checkSyncInternal(input, ctx);
      }

      // Full async pipeline with Tier 1 ML escalation.
      return checkAsyncInternal(input, ctx, localModelDetector);
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

    async checkToolCall() {
      throw new Error(
        'opensentry: checkToolCall is planned for Phase 4 (agentic tool-call gating).',
      );
    },
  };

  return guard;
}
