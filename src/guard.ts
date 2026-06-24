import { hashStr, LRU } from './cache.js';
import { resolveConfig, resolveSourcePolicy } from './config.js';
import { normalizeInput } from './normalize/normalize.js';
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
  Reason,
  Source,
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

export function createGuard(config?: GuardConfig): Guard {
  const cfg = resolveConfig(config);
  const cache = new LRU<string, GuardResult>(cfg.cacheMax);
  const hasAsyncDetector = cfg.detectors.some((d) => d.kind !== 'heuristics');

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

  const guard: Guard = {
    checkSync(input, ctx) {
      if (hasAsyncDetector) {
        throw new Error(
          'opensentry checkSync: configured detectors include async tiers (localModel/remoteGuard/embeddingCorpus). Use check() or remove them for sync-only Tier 0.',
        );
      }
      return checkSyncInternal(input, ctx);
    },

    async check(input, ctx) {
      // Phase 1 ships Tier 0 only. Higher-tier detectors are wired in Phase 3/4.
      for (const d of cfg.detectors) {
        if (d.kind === 'localModel') {
          throw new Error(
            'opensentry: localModel detector is not available in this build — use the opensentry/onnx or opensentry/wasm subpath (planned Phase 3).',
          );
        }
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
      return checkSyncInternal(input, ctx);
    },

    async checkMessages() {
      throw new Error(
        'opensentry: checkMessages is planned for Phase 2 (per-message scoring with conversationId).',
      );
    },

    createStreamScanner() {
      throw new Error(
        'opensentry: createStreamScanner is planned for Phase 2 (streaming/chunked scan).',
      );
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
