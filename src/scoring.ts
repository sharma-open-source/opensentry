import { isHardBlock } from './config.js';
import type { Mode, Reason, ReasonCode, Thresholds, Verdict } from './types.js';

// PLAN.md §4.2 — score is aggregated weighted evidence via noisy-OR (probabilistic OR):
//   score = 1 - ∏(1 - w_i)
// Bounded [0,1]; a single weight of 1 ⇒ score 1; multiple mid signals combine upward.
// This is the "max-aggregate": it is ≥ the max weight and respects every detector.
export function aggregateScore(reasons: Reason[]): number {
  let prod = 1;
  for (const r of reasons) {
    const w = r.weight < 0 ? 0 : r.weight > 1 ? 1 : r.weight;
    prod *= 1 - w;
  }
  return 1 - prod;
}

export interface VerdictDecision {
  verdict: Verdict; // enforced (respects shadow/soft)
  wouldVerdict: Verdict; // before shadow override
  shadow: boolean;
  mode: Mode; // resolved mode — lets callers re-decide without re-deriving it
  hardBlockTriggered: boolean;
}

// PLAN.md §4.2, §4.5, §4.6, §7 — verdict resolution.
//  - hard-block floor fires even in fail-open (deterministic high-confidence set).
//  - highRiskAction ⇒ fail-closed: uncertain 'flag' escalates to 'block' (Phase 1 has no
//    higher tier to escalate to; Phase 3/4 will route to ML/remote/HITL instead).
//  - shadow: never enforce (verdict='allow'); wouldVerdict shows the real decision.
//  - soft: block downgrades to flag (flag-but-don't-block graduation step).
export function decideVerdict(
  score: number,
  reasons: Reason[],
  thresholds: Thresholds,
  hardBlockRules: readonly ReasonCode[] | true,
  mode: Mode,
  highRiskAction: boolean,
): VerdictDecision {
  const hardBlockTriggered = reasons.some(
    (r) => r.hardBlock === true && isHardBlock(r.code, hardBlockRules),
  );

  let wouldVerdict: Verdict;
  if (hardBlockTriggered) {
    wouldVerdict = 'block';
  } else if (score >= thresholds.block) {
    wouldVerdict = 'block';
  } else if (score >= thresholds.flag) {
    wouldVerdict = 'flag';
  } else {
    wouldVerdict = 'allow';
  }

  if (highRiskAction && wouldVerdict === 'flag') {
    wouldVerdict = 'block'; // fail-closed on uncertain high-risk (pre-tool-call gating)
  }

  const shadow = mode === 'shadow';
  let verdict: Verdict;
  if (shadow) {
    verdict = 'allow';
  } else if (mode === 'soft') {
    verdict = wouldVerdict === 'block' ? 'flag' : wouldVerdict;
  } else {
    verdict = wouldVerdict;
  }

  return { verdict, wouldVerdict, shadow, mode, hardBlockTriggered };
}
