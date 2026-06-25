// opensentry/session — stateful multi-turn / session guard (PLAN.md security plan #1).
//
// Crescendo, Bad Likert Judge, and many-shot exceed ~70% success precisely because no single
// turn is flaggable. The core `Guard` is stateless (conversationId is only a cache/metric key).
// This subpath wraps a `Guard` and keeps per-conversation state in an LRU (with a pluggable
// `SessionStore` for distributed deployments), folding three session-level signals into each
// turn's result via the existing noisy-OR (src/scoring.ts):
//
//   - cumulative_risk:     decaying sum of per-turn scores crosses a threshold (slow escalation
//                          trips even when each turn is individually benign).
//   - session_escalation:  score gradient across turns exceeds escalationDelta (Crescendo).
//   - manyshot_density:    a single turn injects many synthetic user:/assistant: example pairs.
//
// FP discipline (PLAN.md §4): session signals are FLAG-weighted, never hard-block.
// `cumulativeScore` decays so a single spike doesn't poison a long benign conversation. Default
// off the common path — only fires when you wire a SessionGuard.
//
// Edge-safe: zero Node builtins (Date.now + string matching only).

import { LRU } from '../cache.js';
import { DEFAULT_THRESHOLDS } from '../config.js';
import { mkReason } from '../reason.js';
import { aggregateScore, decideVerdict } from '../scoring.js';
import type {
  Guard,
  GuardContext,
  GuardResult,
  Mode,
  Reason,
  ReasonCategory,
  Thresholds,
  Verdict,
} from '../types.js';

export interface SessionTurn {
  score: number;
  verdict: Verdict;
  categories: ReasonCategory[];
  ts: number;
}

export interface SessionState {
  cumulativeScore: number; // decaying sum of per-turn scores
  turns: SessionTurn[];
  refusedTopics: string[]; // reserved: markers of content the assistant refused (future use)
}

export interface SessionStore {
  get(id: string): SessionState | undefined;
  set(id: string, s: SessionState): void;
  delete(id: string): void;
}

export interface SessionGuardOptions {
  store?: SessionStore;
  decay?: number; // per-turn multiplier on cumulativeScore, default 0.8
  escalationDelta?: number; // turn-over-turn score rise that trips session_escalation
  manyShotTurnThreshold?: number; // synthetic role-marker count that trips manyshot_density
  cumulativeRiskThreshold?: number; // decaying-sum level that trips cumulative_risk
  ttlMs?: number;
  maxEntries?: number; // default store LRU size (ignored if store is supplied)
  thresholds?: Partial<Thresholds>; // session-signal verdict mapping (default project thresholds)
}

export interface SessionGuard {
  check(input: string, ctx: GuardContext & { conversationId: string }): Promise<GuardResult>;
  reset(conversationId: string): void;
  stateOf(conversationId: string): SessionState | undefined;
}

// Synthetic role-pair markers (many-shot jailbreaks pack many of these into one turn).
// Counts both chat-template tokens and bare role-colon markers on the raw input.
const ROLE_MARKER_RE =
  /(?:<\|im_start\|>|<\|im_end\|>|\[inst\]|\[\/inst\]|<<sys>>|<<\/sys>>|<\|system\|>|<\|assistant\|>|<\|user\|>|<start_of_turn>|<end_of_turn>|\b(?:user|assistant|system|developer)\s*:)/gi;

function countRoleMarkers(input: string): number {
  ROLE_MARKER_RE.lastIndex = 0;
  let count = 0;
  while (ROLE_MARKER_RE.exec(input) !== null) {
    count++;
    if (count > 200) break; // bounded
  }
  return count;
}

function rank(v: Verdict): number {
  return v === 'block' ? 2 : v === 'flag' ? 1 : 0;
}
function rankToVerdict(r: number): Verdict {
  return r >= 2 ? 'block' : r === 1 ? 'flag' : 'allow';
}

// Default in-memory store: LRU with TTL eviction on get. BYO store for Redis/DB backends.
function defaultStore(maxEntries: number, ttlMs: number): SessionStore {
  const lru = new LRU<string, { state: SessionState; ts: number }>(maxEntries);
  return {
    get(id) {
      const entry = lru.get(id);
      if (!entry) return undefined;
      if (Date.now() - entry.ts > ttlMs) {
        lru.delete(id);
        return undefined;
      }
      return entry.state;
    },
    set(id, state) {
      lru.set(id, { state, ts: Date.now() });
    },
    delete(id) {
      lru.delete(id);
    },
  };
}

export function createSessionGuard(guard: Guard, opts?: SessionGuardOptions): SessionGuard {
  const decay = opts?.decay ?? 0.8;
  const escalationDelta = opts?.escalationDelta ?? 0.3;
  const manyShotThreshold = opts?.manyShotTurnThreshold ?? 8;
  const cumulativeThreshold = opts?.cumulativeRiskThreshold ?? 0.6;
  const ttlMs = opts?.ttlMs ?? 30 * 60 * 1000; // 30 min
  const maxEntries = opts?.maxEntries ?? 1024;
  const store: SessionStore = opts?.store ?? defaultStore(maxEntries, ttlMs);
  const thresholds: Thresholds = { ...DEFAULT_THRESHOLDS, ...(opts?.thresholds ?? {}) };

  async function check(
    input: string,
    ctx: GuardContext & { conversationId: string },
  ): Promise<GuardResult> {
    const base = await guard.check(input, ctx);
    const id = ctx.conversationId;
    const now = Date.now();

    const sessionReasons: Reason[] = [];

    // manyshot_density: a single turn injects many synthetic role-pair markers.
    const markerCount = countRoleMarkers(input);
    if (markerCount >= manyShotThreshold) {
      const w = Math.min(0.85, 0.5 + 0.04 * (markerCount - manyShotThreshold));
      sessionReasons.push(
        mkReason(
          'manyshot_density',
          'structural',
          w,
          `many-shot density: ${markerCount} synthetic role markers in one turn`,
        ),
      );
    }

    // Load (or create) session state.
    const prev = store.get(id);
    const prevTurn = prev && prev.turns.length > 0 ? prev.turns[prev.turns.length - 1] : undefined;
    const cumulative = prev ? decay * prev.cumulativeScore + base.score : base.score;

    // cumulative_risk: decaying sum crosses the threshold. Slow escalation trips even when
    // each turn is individually benign. Weight scales above the threshold, capped.
    if (cumulative >= cumulativeThreshold) {
      const over = cumulative - cumulativeThreshold;
      const w = Math.min(0.8, 0.4 + over * 0.8);
      sessionReasons.push(
        mkReason(
          'cumulative_risk',
          'semantic',
          w,
          `cumulative session risk: decaying sum ${cumulative.toFixed(3)} >= ${cumulativeThreshold} (turns=${(prev?.turns.length ?? 0) + 1})`,
        ),
      );
    }

    // session_escalation: score gradient across turns exceeds escalationDelta (Crescendo).
    if (prevTurn && base.score - prevTurn.score >= escalationDelta) {
      const delta = base.score - prevTurn.score;
      const w = Math.min(0.85, 0.45 + delta * 0.5);
      sessionReasons.push(
        mkReason(
          'session_escalation',
          'semantic',
          w,
          `session escalation: turn score rose by ${delta.toFixed(3)} (>= ${escalationDelta}) from ${prevTurn.score.toFixed(3)} to ${base.score.toFixed(3)}`,
        ),
      );
    }

    // Persist updated state.
    const categories = new Set<ReasonCategory>();
    for (const r of base.reasons) categories.add(r.category);
    const state: SessionState = {
      cumulativeScore: cumulative,
      turns: [
        ...(prev?.turns ?? []),
        { score: base.score, verdict: base.wouldVerdict, categories: [...categories], ts: now },
      ].slice(-50), // cap retained turns
      refusedTopics: prev?.refusedTopics ?? [],
    };
    store.set(id, state);

    // No session signals → return the wrapped result unchanged.
    if (sessionReasons.length === 0) return base;

    // Fold session signals into the result via noisy-OR and re-decide. Session signals are
    // flag-weighted (never hard-block), so hardBlockRules is empty. The wrapped guard's
    // verdict is preserved as a FLOOR — session can only escalate, never de-escalate.
    // Re-derive the wrapped guard's mode: GuardResult.mode (set by createGuard) is the source
    // of truth; fall back to the shadow boolean for external Guard impls that don't set it.
    // This preserves soft mode (block→flag downgrade) — base.shadow alone collapses soft→enforce.
    const allReasons = [...base.reasons, ...sessionReasons];
    const newScore = aggregateScore(allReasons);
    const mode: Mode = base.mode ?? (base.shadow ? 'shadow' : 'enforce');
    const decision = decideVerdict(
      newScore,
      allReasons,
      thresholds,
      [], // no hard-block from session signals
      mode,
      ctx.highRiskAction ?? false,
    );
    const finalWould = rankToVerdict(
      Math.max(rank(base.wouldVerdict), rank(decision.wouldVerdict)),
    );
    const finalVerdict: Verdict =
      mode === 'shadow' ? 'allow' : mode === 'soft' && finalWould === 'block' ? 'flag' : finalWould;

    return {
      ...base,
      verdict: finalVerdict,
      wouldVerdict: finalWould,
      score: newScore,
      reasons: allReasons,
      mode,
    };
  }

  return {
    check,
    reset(id) {
      store.delete(id);
    },
    stateOf(id) {
      return store.get(id);
    },
  };
}
