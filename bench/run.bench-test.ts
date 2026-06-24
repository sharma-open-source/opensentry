import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'vitest';
import { createGuard } from '../src/index.js';
import type { GuardResult } from '../src/types.js';
import { type BenchEntry, loadBenchCorpora } from './loader.js';
import {
  confusionFromVerdict,
  type LabeledSample,
  latencyStats,
  prAuc,
  precisionRecallF1,
  recallAtFpr,
  rocAuc,
  sweepThresholds,
} from './metrics.js';
import { createRealPromptGuardRunner } from './real-runner.js';

const dir = path.dirname(fileURLToPath(import.meta.url));

interface ViewSample extends LabeledSample {
  id: string;
  category: string;
  tier: number;
  escalated: boolean;
}

function toLabel(e: BenchEntry): 'attack' | 'benign' {
  return e.label;
}

function groupBy<T>(items: T[], key: (t: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    if (!m.has(k)) m.set(k, []);
    m.get(k)!.push(item);
  }
  return m;
}

function reportFor(label: string, samples: ViewSample[]) {
  const c = confusionFromVerdict(samples);
  const stats = precisionRecallF1(c);
  const curve = sweepThresholds(samples);
  const auc = rocAuc(curve);
  const pAuc = prAuc(curve);
  const r05 = recallAtFpr(curve, 0.005);
  const r1 = recallAtFpr(curve, 0.01);
  const r5 = recallAtFpr(curve, 0.05);
  const lat = latencyStats(samples.map((s) => s.latencyMs));
  return {
    label,
    n: samples.length,
    confusion: c,
    precision: stats.precision,
    recall: stats.recall,
    f1: stats.f1,
    fpr: stats.fpr,
    accuracy: stats.accuracy,
    rocAuc: auc,
    prAuc: pAuc,
    recallAtFpr0_5pct: r05,
    recallAtFpr1pct: r1,
    recallAtFpr5pct: r5,
    latencyMs: lat,
  };
}

test(
  'real-corpus benchmark — Tier 0, Tier 1 (Llama-Prompt-Guard-2-22M), blended pipeline',
  async () => {
    const { attacks, benign, notinject } = loadBenchCorpora();
    console.log(
      `Loaded ${attacks.length} attacks, ${benign.length} benign, ${notinject.length} notinject`,
    );

    const guardTier0 = createGuard();
    const modelsDir = path.join(dir, 'models');
    const mlRunner = await createRealPromptGuardRunner(modelsDir, 'llama-prompt-guard-2-22m');
    await mlRunner.warm();
    const guardBlended = createGuard({
      detectors: [{ kind: 'heuristics' }, { kind: 'localModel', runner: mlRunner }],
    });
    // Same pipeline, but with alwaysEscalate forced on for 'user' — shows the ceiling when the
    // escalation gate doesn't depend on Tier 0 already landing in the uncertain "flag" band.
    const guardBlendedAlwaysEscalate = createGuard({
      detectors: [{ kind: 'heuristics' }, { kind: 'localModel', runner: mlRunner }],
      policy: { perSource: { user: { alwaysEscalate: true } } },
    });

    const all: BenchEntry[] = [...attacks, ...benign];
    const tier0: ViewSample[] = [];
    const tier1: ViewSample[] = [];
    const blended: ViewSample[] = [];
    const blendedAlwaysEscalate: ViewSample[] = [];

    let processed = 0;
    for (const e of all) {
      const label = toLabel(e);

      const r0: GuardResult = guardTier0.checkSync(e.text, { source: 'user' });
      tier0.push({
        id: e.id,
        category: e.category,
        label,
        score: r0.score,
        verdict: r0.verdict,
        latencyMs: r0.latencyMs,
        tier: r0.tier,
        escalated: false,
      });

      const t0 = performance.now();
      const ml = await mlRunner.classify(e.text);
      const mlLatency = performance.now() - t0;
      tier1.push({
        id: e.id,
        category: e.category,
        label,
        score: ml.score,
        verdict: ml.score >= 0.85 ? 'block' : ml.score >= 0.4 ? 'flag' : 'allow',
        latencyMs: mlLatency,
        tier: 1,
        escalated: false,
      });

      const rb: GuardResult = await guardBlended.check(e.text, { source: 'user' });
      blended.push({
        id: e.id,
        category: e.category,
        label,
        score: rb.score,
        verdict: rb.verdict,
        latencyMs: rb.latencyMs,
        tier: rb.tier,
        escalated: rb.tier > 0,
      });

      const rbe: GuardResult = await guardBlendedAlwaysEscalate.check(e.text, { source: 'user' });
      blendedAlwaysEscalate.push({
        id: e.id,
        category: e.category,
        label,
        score: rbe.score,
        verdict: rbe.verdict,
        latencyMs: rbe.latencyMs,
        tier: rbe.tier,
        escalated: rbe.tier > 0,
      });

      processed++;
      if (processed % 250 === 0) console.log(`  ${processed}/${all.length} processed`);
    }

    // NotInject — over-defense probe, benign-labeled, reported separately (matches existing
    // corpus/eval.ts convention) rather than folded into the headline benign FPR.
    const notinjectViews = {
      tier0: [] as ViewSample[],
      tier1: [] as ViewSample[],
      blended: [] as ViewSample[],
      blendedAlwaysEscalate: [] as ViewSample[],
    };
    for (const e of notinject) {
      const r0 = guardTier0.checkSync(e.text, { source: 'user' });
      notinjectViews.tier0.push({
        id: e.id,
        category: e.category,
        label: 'benign',
        score: r0.score,
        verdict: r0.verdict,
        latencyMs: r0.latencyMs,
        tier: r0.tier,
        escalated: false,
      });

      const ml = await mlRunner.classify(e.text);
      notinjectViews.tier1.push({
        id: e.id,
        category: e.category,
        label: 'benign',
        score: ml.score,
        verdict: ml.score >= 0.85 ? 'block' : ml.score >= 0.4 ? 'flag' : 'allow',
        latencyMs: ml.latencyMs,
        tier: 1,
        escalated: false,
      });

      const rb = await guardBlended.check(e.text, { source: 'user' });
      notinjectViews.blended.push({
        id: e.id,
        category: e.category,
        label: 'benign',
        score: rb.score,
        verdict: rb.verdict,
        latencyMs: rb.latencyMs,
        tier: rb.tier,
        escalated: rb.tier > 0,
      });

      const rbe = await guardBlendedAlwaysEscalate.check(e.text, { source: 'user' });
      notinjectViews.blendedAlwaysEscalate.push({
        id: e.id,
        category: e.category,
        label: 'benign',
        score: rbe.score,
        verdict: rbe.verdict,
        latencyMs: rbe.latencyMs,
        tier: rbe.tier,
        escalated: rbe.tier > 0,
      });
    }
    mlRunner.dispose();

    const views = { tier0, tier1, blended, blendedAlwaysEscalate };
    const overall: Record<string, ReturnType<typeof reportFor>> = {};
    const perCategory: Record<string, Record<string, ReturnType<typeof reportFor>>> = {};
    const notInjectOverDefense: Record<string, { rate: number; n: number; flagged: number }> = {};
    const escalationRate: Record<string, number> = {};

    for (const [viewName, samples] of Object.entries(views)) {
      overall[viewName] = reportFor(viewName, samples);
      const byCat = groupBy(samples, (s) => s.category);
      perCategory[viewName] = {};
      for (const [cat, catSamples] of byCat) {
        perCategory[viewName][cat] = reportFor(`${viewName}/${cat}`, catSamples);
      }
      if (viewName === 'blended' || viewName === 'blendedAlwaysEscalate') {
        escalationRate[viewName] = samples.filter((s) => s.escalated).length / samples.length;
      }
    }
    for (const [viewName, samples] of Object.entries(notinjectViews)) {
      const flagged = samples.filter((s) => s.verdict !== 'allow').length;
      notInjectOverDefense[viewName] = {
        rate: flagged / samples.length,
        n: samples.length,
        flagged,
      };
    }

    const report = {
      generatedAt: new Date().toISOString(),
      datasetCounts: {
        attacks: attacks.length,
        benign: benign.length,
        notinject: notinject.length,
        total: all.length,
      },
      notes: [
        'Tier 1 / blended use the REAL shipped default model, meta-llama/Llama-Prompt-Guard-2-22M.' +
          ' No ONNX build is published for this gated repo, so it was exported locally via' +
          ' `optimum-cli export onnx` from the PyTorch safetensors checkpoint and loaded from disk' +
          ' (bench/models/llama-prompt-guard-2-22m/). Label index (LABEL_1=malicious) was verified' +
          ' empirically, not assumed from docs, since the exported config.json carries no id2label.',
        'deepset/prompt-injections and JasperLS/prompt-injections were deliberately excluded — same' +
          ' underlying noisy/mislabeled data, and PLAN.md §9 already flags it as training-only/contaminated.',
        'notinject is benign-labeled but reported separately as an over-defense rate, not folded into' +
          ' the headline benign FPR — same convention as corpus/eval.ts.',
      ],
      overall,
      perCategory,
      notInjectOverDefense,
      escalationRate,
    };

    writeFileSync(path.join(dir, 'report.json'), JSON.stringify(report, null, 2));
    console.log('\n=== SUMMARY ===');
    for (const [viewName, r] of Object.entries(overall)) {
      console.log(
        `${viewName}: n=${r.n} precision=${r.precision.toFixed(3)} recall=${r.recall.toFixed(3)} f1=${r.f1.toFixed(3)} fpr=${r.fpr.toFixed(3)} rocAuc=${r.rocAuc.toFixed(3)} prAuc=${r.prAuc.toFixed(3)} p50=${r.latencyMs.p50.toFixed(3)}ms p99=${r.latencyMs.p99.toFixed(3)}ms`,
      );
    }
    for (const [viewName, d] of Object.entries(notInjectOverDefense)) {
      console.log(
        `notinject/${viewName}: over-defense rate=${d.rate.toFixed(3)} (${d.flagged}/${d.n})`,
      );
    }
  },
  30 * 60_000,
);
