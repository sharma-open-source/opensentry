// Tier-0 benchmark of opensentry's shipped zero-dep detector against an external dataset:
// Necent/llm-jailbreak-prompt-injection-dataset (gated, ~1M rows, 30+ aggregated safety sources).
//
// Target label = the dataset's `prompt_adversarial` flag (1 => jailbreak / prompt-injection /
// obfuscation attack on the model). This is the correct evaluation target for a PI guardrail:
// `prompt_harmful` rows (toxic/CBRN topic with no adversarial framing) are intentionally treated
// as BENIGN here, matching the dataset card — opensentry is not a content-moderation classifier.
//
// The sample (25k adversarial + 25k benign, stratified) is produced out-of-band by
// scratchpad/necent/sample.py and pointed at via NECENT_SAMPLE. Tier 0 only — no ML tier.
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'vitest';
import { createGuard } from '../src/index.js';
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

const dir = path.dirname(fileURLToPath(import.meta.url));

interface SampleEntry {
  id: string;
  text: string;
  label: 'attack' | 'benign';
  category: string;
  sourceDataset: string;
  language?: string;
  prompt_harmful?: number | null;
}

interface ViewSample extends LabeledSample {
  id: string;
  source: string;
  language: string;
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
  return {
    label,
    n: samples.length,
    confusion: c,
    precision: stats.precision,
    recall: stats.recall,
    f1: stats.f1,
    fpr: stats.fpr,
    accuracy: stats.accuracy,
    rocAuc: rocAuc(curve),
    prAuc: prAuc(curve),
    recallAtFpr1pct: recallAtFpr(curve, 0.01),
    recallAtFpr5pct: recallAtFpr(curve, 0.05),
    latencyMs: latencyStats(samples.map((s) => s.latencyMs)),
  };
}

test(
  'necent-corpus benchmark — Tier 0 (zero-dep core) on prompt_adversarial',
  () => {
    const samplePath =
      process.env.NECENT_SAMPLE ??
      path.join(dir, 'data-external', 'necent-sample.json');
    const raw = JSON.parse(readFileSync(samplePath, 'utf8')) as {
      meta: Record<string, unknown>;
      attacks: SampleEntry[];
      benign: SampleEntry[];
    };
    const all = [...raw.attacks, ...raw.benign];
    console.log(
      `Loaded ${raw.attacks.length} attacks + ${raw.benign.length} benign (n=${all.length}) from ${samplePath}`,
    );

    const guard = createGuard();
    const samples: ViewSample[] = [];
    let processed = 0;
    for (const e of all) {
      const r = guard.checkSync(e.text, { source: 'user' });
      samples.push({
        id: e.id,
        label: e.label,
        score: r.score,
        verdict: r.verdict,
        category: e.category || 'unknown',
        latencyMs: r.latencyMs,
        source: e.sourceDataset || 'unknown',
        language: e.language || 'unknown',
      });
      if (++processed % 10000 === 0) console.log(`  ${processed}/${all.length} processed`);
    }

    const overall = reportFor('tier0', samples);

    // Per attack-technique / prompt_type slice (the `category` field carries prompt_type).
    const perCategory: Record<string, ReturnType<typeof reportFor>> = {};
    for (const [cat, catSamples] of groupBy(samples, (s) => s.category)) {
      if (catSamples.length < 20) continue; // skip tiny slices
      perCategory[cat] = reportFor(`tier0/${cat}`, catSamples);
    }

    // Per source-dataset slice — see which of the 30+ aggregated sources Tier 0 handles well.
    const perSource: Record<string, ReturnType<typeof reportFor>> = {};
    for (const [src, srcSamples] of groupBy(samples, (s) => s.source)) {
      if (srcSamples.length < 20) continue;
      perSource[src] = reportFor(`tier0/${src}`, srcSamples);
    }

    // Per language — multilingual coverage (Tier 0 has no model, so this is a real stress test).
    const perLanguage: Record<string, { n: number; attackRecall: number; benignFpr: number }> = {};
    for (const [lang, langSamples] of groupBy(samples, (s) => s.language)) {
      if (langSamples.length < 30) continue;
      const c = confusionFromVerdict(langSamples);
      const stats = precisionRecallF1(c);
      perLanguage[lang] = { n: langSamples.length, attackRecall: stats.recall, benignFpr: stats.fpr };
    }

    const report = {
      generatedAt: new Date().toISOString(),
      dataset: 'Necent/llm-jailbreak-prompt-injection-dataset',
      labelField: 'prompt_adversarial',
      tier: 'Tier 0 (zero-dep heuristics, createGuard().checkSync)',
      sampleMeta: raw.meta,
      datasetCounts: { attacks: raw.attacks.length, benign: raw.benign.length, total: all.length },
      overall,
      perCategory,
      perSource,
      perLanguage,
    };

    writeFileSync(path.join(dir, 'report-necent.json'), JSON.stringify(report, null, 2));

    const r = overall;
    console.log('\n=== SUMMARY (Tier 0 vs prompt_adversarial) ===');
    console.log(
      `overall: n=${r.n} precision=${r.precision.toFixed(3)} recall=${r.recall.toFixed(3)} f1=${r.f1.toFixed(3)} fpr=${r.fpr.toFixed(3)} acc=${r.accuracy.toFixed(3)} rocAuc=${r.rocAuc.toFixed(3)} prAuc=${r.prAuc.toFixed(3)} p50=${r.latencyMs.p50.toFixed(4)}ms p99=${r.latencyMs.p99.toFixed(4)}ms`,
    );
    console.log('\n=== By prompt_type ===');
    for (const [cat, cr] of Object.entries(perCategory).sort((a, b) => b[1].n - a[1].n)) {
      console.log(
        `  ${cat}: n=${cr.n} recall=${cr.recall.toFixed(3)} fpr=${cr.fpr.toFixed(3)} f1=${cr.f1.toFixed(3)}`,
      );
    }
    console.log('\n=== By language (recall on attacks / FPR on benign) ===');
    for (const [lang, lr] of Object.entries(perLanguage).sort((a, b) => b[1].n - a[1].n).slice(0, 20)) {
      console.log(`  ${lang}: n=${lr.n} attackRecall=${lr.attackRecall.toFixed(3)} benignFpr=${lr.benignFpr.toFixed(3)}`);
    }
  },
  30 * 60_000,
);
