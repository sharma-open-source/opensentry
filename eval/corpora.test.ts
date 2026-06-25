import { test, expect } from 'vitest';
import { evaluate } from '../corpus/eval.js';
import { GATES } from '../corpus/gates.js';

test('corpora release gates pass', () => {
  const r = evaluate();
  // Visible report for CI debugging.
  const log = {
    attackRecall: r.attackRecall.toFixed(3),
    hardBlockRecall: r.hardBlockRecall.toFixed(3),
    benignFpr: r.benignFpr.toFixed(3),
    notInjectRate: r.notInjectRate.toFixed(3),
    attackMisses: r.attackMisses.map((m) => ({ id: m.entry.id, cat: m.entry.category, reasons: m.reasons })),
    falsePositives: r.falsePositives.map((f) => ({ id: f.entry.id, verdict: f.verdict, reasons: f.reasons })),
    overDefense: r.overDefense.map((o) => ({ id: o.entry.id, verdict: o.verdict, reasons: o.reasons })),
    outOfScope: r.outOfScope.map((o) => o.id),
  };
  if (!r.pass) {
    // eslint-disable-next-line no-console
    console.log('EVAL REPORT\n', JSON.stringify(log, null, 2));
  } else {
    // eslint-disable-next-line no-console
    console.log('EVAL OK', JSON.stringify(log));
  }
  expect(r.benignFpr).toBeLessThan(GATES.benignFprMax);
  expect(r.notInjectRate).toBeLessThan(GATES.notinjectOverDefenseMax);
  expect(r.attackRecall).toBeGreaterThanOrEqual(GATES.attackRecallMin);
  expect(r.hardBlockRecall).toBeGreaterThanOrEqual(GATES.hardBlockRecallMin);
  expect(r.pass).toBe(true);
});
