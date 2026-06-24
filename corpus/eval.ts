import { createGuard } from '../src/index.js';
import type { GuardResult, Source } from '../src/types.js';
import { loadAll, type CorpusEntry } from './loader.js';
import { GATES } from './gates.js';

export interface CaseOutcome {
  entry: CorpusEntry;
  verdict: GuardResult['verdict'];
  score: number;
  reasons: string[];
}

export interface EvalReport {
  attackTotal: number;
  attackDetected: number;
  attackRecall: number;
  attackMisses: CaseOutcome[];
  hardBlockTotal: number;
  hardBlockCaught: number;
  hardBlockRecall: number;
  benignTotal: number;
  benignFlagged: number;
  benignFpr: number;
  falsePositives: CaseOutcome[];
  notInjectTotal: number;
  notInjectOverDefended: number;
  notInjectRate: number;
  overDefense: CaseOutcome[];
  outOfScope: CorpusEntry[];
  pass: boolean;
  failures: string[];
}

function ctxFor(e: CorpusEntry): { source: Source } | undefined {
  return e.source ? { source: e.source as Source } : undefined;
}

export function evaluate(): EvalReport {
  const guard = createGuard();
  const { attacks, benign, notinject } = loadAll();
  const outOfScope = attacks.filter((a) => a.outOfScope);
  const inScope = attacks.filter((a) => !a.outOfScope);

  const attackMisses: CaseOutcome[] = [];
  let attackDetected = 0;
  let hardBlockTotal = 0;
  let hardBlockCaught = 0;

  for (const a of inScope) {
    const r = guard.checkSync(a.text, ctxFor(a));
    const detected = r.verdict !== 'allow';
    if (detected) {
      attackDetected++;
    } else {
      attackMisses.push({ entry: a, verdict: r.verdict, score: r.score, reasons: r.reasons.map((x) => x.code) });
    }
    if (a.hardBlock) {
      hardBlockTotal++;
      if (r.verdict === 'block') hardBlockCaught++;
    }
  }
  const attackRecall = inScope.length ? attackDetected / inScope.length : 1;
  const hardBlockRecall = hardBlockTotal ? hardBlockCaught / hardBlockTotal : 1;

  const falsePositives: CaseOutcome[] = [];
  for (const b of benign) {
    const r = guard.checkSync(b.text, ctxFor(b));
    if (r.verdict !== 'allow') {
      falsePositives.push({ entry: b, verdict: r.verdict, score: r.score, reasons: r.reasons.map((x) => x.code) });
    }
  }
  const benignFpr = benign.length ? falsePositives.length / benign.length : 0;

  const overDefense: CaseOutcome[] = [];
  for (const n of notinject) {
    const r = guard.checkSync(n.text, ctxFor(n));
    if (r.verdict !== 'allow') {
      overDefense.push({ entry: n, verdict: r.verdict, score: r.score, reasons: r.reasons.map((x) => x.code) });
    }
  }
  const notInjectRate = notinject.length ? overDefense.length / notinject.length : 0;

  const failures: string[] = [];
  if (benignFpr >= GATES.benignFprMax) {
    failures.push(`benignFpr ${benignFpr.toFixed(3)} >= ${GATES.benignFprMax} (${falsePositives.length}/${benign.length})`);
  }
  if (notInjectRate >= GATES.notinjectOverDefenseMax) {
    failures.push(`notInject over-defense ${notInjectRate.toFixed(3)} >= ${GATES.notinjectOverDefenseMax} (${overDefense.length}/${notinject.length})`);
  }
  if (attackRecall < GATES.attackRecallMin) {
    failures.push(`attackRecall ${attackRecall.toFixed(3)} < ${GATES.attackRecallMin} (misses: ${attackMisses.map((m) => m.entry.id).join(',')})`);
  }
  if (hardBlockTotal > 0 && hardBlockRecall < GATES.hardBlockRecallMin) {
    failures.push(`hardBlockRecall ${hardBlockRecall.toFixed(3)} < ${GATES.hardBlockRecallMin} (${hardBlockCaught}/${hardBlockTotal})`);
  }

  return {
    attackTotal: inScope.length,
    attackDetected,
    attackRecall,
    attackMisses,
    hardBlockTotal,
    hardBlockCaught,
    hardBlockRecall,
    benignTotal: benign.length,
    benignFlagged: falsePositives.length,
    benignFpr,
    falsePositives,
    notInjectTotal: notinject.length,
    notInjectOverDefended: overDefense.length,
    notInjectRate,
    overDefense,
    outOfScope,
    pass: failures.length === 0,
    failures,
  };
}
