// Tier 0 + Tier 1 (local ML) benchmark of opensentry against the external dataset
// Necent/llm-jailbreak-prompt-injection-dataset (gated). Companion to run-necent.bench-test.ts
// (Tier 0 only). Same sample (NECENT_SAMPLE), same `prompt_adversarial` target.
//
// The local ML tier is Meta's Llama-Prompt-Guard-2 (86M) run via @huggingface/transformers on
// the native ONNX backend. The meta-llama repo ships only safetensors, so we point the runner at
// an ONNX export with the transformers.js layout (`onnx/model_quantized.onnx`); override with
// NECENT_ML_MODEL. The model emits LABEL_1 = injection / LABEL_0 = benign, so the runner maps
// LABEL_1 → injection (the package's stock onnx runner keys on a literal "INJECTION" label).
//
// IMPORTANT — escalation gate: Tier 1 only runs when Tier 0 already flagged OR the source is
// alwaysEscalate (PLAN.md §5). Under the default `user` policy, ML never sees the ~83% of attacks
// Tier 0 scores 0, so it cannot lift recall there. To measure what the ML tier can actually
// deliver we set perSource.user.alwaysEscalate = true (the realistic high-assurance config for an
// untrusted channel). We report BOTH the combined guard verdict AND the ML classifier in isolation
// (threshold sweep / AUC) so the model's intrinsic ceiling is separable from the wiring.
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'vitest';
import { createGuard } from '../src/index.js';
import type { LocalModelResult, LocalModelRunner } from '../src/types.js';
import {
  type CurvePoint,
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

const ML_MODEL = process.env.NECENT_ML_MODEL ?? 'sinatras/Llama-Prompt-Guard-2-86M-ONNX';

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
  mlScore: number | null; // raw ML injection probability (null if ML did not run / errored)
}

// Structural type for the @huggingface/transformers pipeline (optional peer dep).
interface TransformersPipeline {
  (
    text: string | string[],
    options?: { top_k?: number },
  ): Promise<Array<{ label: string; score: number }> | Array<Array<{ label: string; score: number }>>>;
  dispose?: () => void;
}

// Build a LocalModelRunner backed by an ONNX-exported Prompt-Guard-2. LABEL_1 = injection.
async function buildRunner(): Promise<LocalModelRunner> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mod: any = await import('@huggingface/transformers');
  mod.env.backends.onnx.wasm.wasmPaths = undefined;
  const clf: TransformersPipeline = await mod.pipeline('text-classification', ML_MODEL, {
    dtype: 'q8',
    device: 'cpu',
  });
  let warmed = false;
  return {
    loaded: true,
    async warm() {
      if (warmed) return;
      await clf('warmup', { top_k: 2 });
      warmed = true;
    },
    async classify(text: string): Promise<LocalModelResult> {
      const t0 = performance.now();
      const out = (await clf(text, { top_k: 2 })) as Array<{ label: string; score: number }>;
      const t1 = performance.now();
      // LABEL_1 = injection probability.
      let injectionScore = 0;
      for (const item of out) {
        if (item.label.toUpperCase() === 'LABEL_1' || item.label.toUpperCase().includes('INJECT')) {
          injectionScore = item.score;
          break;
        }
      }
      return {
        score: injectionScore,
        label: injectionScore > 0.5 ? 'injection' : 'benign',
        latencyMs: t1 - t0,
      };
    },
    dispose() {
      clf.dispose?.();
    },
  };
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
  const curve = sweepThresholds(samples); // sweeps the aggregate guard score
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

// ML-in-isolation metrics: treat the raw ML probability as the score (ignores Tier 0). Only over
// samples where ML actually ran.
function mlStandalone(samples: ViewSample[]) {
  const withMl = samples.filter((s) => s.mlScore !== null);
  const ml: LabeledSample[] = withMl.map((s) => ({
    label: s.label,
    score: s.mlScore as number,
    verdict: (s.mlScore as number) > 0.5 ? 'block' : 'allow',
    category: s.category,
    latencyMs: s.latencyMs,
  }));
  const curve: CurvePoint[] = sweepThresholds(ml);
  const at05 = confusionFromVerdict(ml);
  const stats05 = precisionRecallF1(at05);
  return {
    n: ml.length,
    coverage: samples.length > 0 ? withMl.length / samples.length : 0,
    atThreshold0_5: {
      precision: stats05.precision,
      recall: stats05.recall,
      f1: stats05.f1,
      fpr: stats05.fpr,
      confusion: at05,
    },
    rocAuc: rocAuc(curve),
    prAuc: prAuc(curve),
    recallAtFpr1pct: recallAtFpr(curve, 0.01),
    recallAtFpr0_1pct: recallAtFpr(curve, 0.001),
  };
}

test(
  'necent-corpus benchmark — Tier 0 + Tier 1 (local ML) on prompt_adversarial',
  async () => {
    const samplePath =
      process.env.NECENT_SAMPLE ?? path.join(dir, 'data-external', 'necent-sample.json');
    const raw = JSON.parse(readFileSync(samplePath, 'utf8')) as {
      meta: Record<string, unknown>;
      attacks: SampleEntry[];
      benign: SampleEntry[];
    };
    const all = [...raw.attacks, ...raw.benign];
    console.log(
      `Loaded ${raw.attacks.length} attacks + ${raw.benign.length} benign (n=${all.length}) from ${samplePath}`,
    );

    console.log(`Loading ML model: ${ML_MODEL} (q8, onnx/cpu) ...`);
    const tLoad = performance.now();
    const runner = await buildRunner();
    await runner.warm();
    console.log(`Model loaded + warmed in ${((performance.now() - tLoad) / 1000).toFixed(1)}s`);

    // alwaysEscalate so ML scores EVERY input (untrusted-channel / high-assurance config).
    const guard = createGuard({
      detectors: [{ kind: 'heuristics' }, { kind: 'localModel', runner, timeoutMs: 20000 }],
      policy: { perSource: { user: { alwaysEscalate: true } } },
    });

    const samples: ViewSample[] = [];
    let processed = 0;
    const tRun = performance.now();
    for (const e of all) {
      const r = await guard.check(e.text, { source: 'user' });
      const mlReason = r.reasons.find((x) => x.code === 'ml_classifier');
      samples.push({
        id: e.id,
        label: e.label,
        score: r.score,
        verdict: r.verdict,
        category: e.category || 'unknown',
        latencyMs: r.latencyMs,
        source: e.sourceDataset || 'unknown',
        language: e.language || 'unknown',
        mlScore: mlReason ? mlReason.weight : null,
      });
      if (++processed % 2500 === 0) {
        const rate = processed / ((performance.now() - tRun) / 1000);
        console.log(
          `  ${processed}/${all.length} (${rate.toFixed(0)}/s, eta ${(((all.length - processed) / rate) / 60).toFixed(1)}m)`,
        );
      }
    }
    runner.dispose();

    const overall = reportFor('tier0+1', samples);
    const ml = mlStandalone(samples);

    const perCategory: Record<string, ReturnType<typeof reportFor>> = {};
    for (const [cat, catSamples] of groupBy(samples, (s) => s.category)) {
      if (catSamples.length < 20) continue;
      perCategory[cat] = reportFor(`tier0+1/${cat}`, catSamples);
    }

    const perSource: Record<string, ReturnType<typeof reportFor>> = {};
    for (const [src, srcSamples] of groupBy(samples, (s) => s.source)) {
      if (srcSamples.length < 20) continue;
      perSource[src] = reportFor(`tier0+1/${src}`, srcSamples);
    }

    const perLanguage: Record<
      string,
      { n: number; attackRecall: number; benignFpr: number; mlAttackRecall: number }
    > = {};
    for (const [lang, langSamples] of groupBy(samples, (s) => s.language)) {
      if (langSamples.length < 30) continue;
      const c = confusionFromVerdict(langSamples);
      const stats = precisionRecallF1(c);
      const atk = langSamples.filter((s) => s.label === 'attack' && s.mlScore !== null);
      const mlAttackRecall =
        atk.length > 0 ? atk.filter((s) => (s.mlScore as number) > 0.5).length / atk.length : 0;
      perLanguage[lang] = {
        n: langSamples.length,
        attackRecall: stats.recall,
        benignFpr: stats.fpr,
        mlAttackRecall,
      };
    }

    const report = {
      generatedAt: new Date().toISOString(),
      dataset: 'Necent/llm-jailbreak-prompt-injection-dataset',
      labelField: 'prompt_adversarial',
      tier: `Tier 0 + Tier 1 local ML (${ML_MODEL}, q8 onnx/cpu)`,
      mlModel: ML_MODEL,
      escalation: 'perSource.user.alwaysEscalate = true (ML scores every input)',
      sampleMeta: raw.meta,
      datasetCounts: { attacks: raw.attacks.length, benign: raw.benign.length, total: all.length },
      overall,
      mlStandalone: ml,
      perCategory,
      perSource,
      perLanguage,
    };
    writeFileSync(path.join(dir, 'report-necent-ml.json'), JSON.stringify(report, null, 2));

    const r = overall;
    console.log('\n=== SUMMARY (Tier 0+1 combined verdict) ===');
    console.log(
      `overall: n=${r.n} precision=${r.precision.toFixed(3)} recall=${r.recall.toFixed(3)} f1=${r.f1.toFixed(3)} fpr=${r.fpr.toFixed(3)} acc=${r.accuracy.toFixed(3)} p50=${r.latencyMs.p50.toFixed(2)}ms p99=${r.latencyMs.p99.toFixed(2)}ms`,
    );
    console.log('\n=== ML classifier in isolation ===');
    console.log(
      `coverage=${(ml.coverage * 100).toFixed(1)}% | @0.5: precision=${ml.atThreshold0_5.precision.toFixed(3)} recall=${ml.atThreshold0_5.recall.toFixed(3)} f1=${ml.atThreshold0_5.f1.toFixed(3)} fpr=${ml.atThreshold0_5.fpr.toFixed(3)} | rocAuc=${ml.rocAuc.toFixed(3)} prAuc=${ml.prAuc.toFixed(3)} recall@1%FPR=${ml.recallAtFpr1pct.recall.toFixed(3)} recall@0.1%FPR=${ml.recallAtFpr0_1pct.recall.toFixed(3)}`,
    );
    console.log('\n=== By prompt_type (combined recall / fpr) ===');
    for (const [cat, cr] of Object.entries(perCategory).sort((a, b) => b[1].n - a[1].n)) {
      console.log(`  ${cat}: n=${cr.n} recall=${cr.recall.toFixed(3)} fpr=${cr.fpr.toFixed(3)} f1=${cr.f1.toFixed(3)}`);
    }
    console.log('\n=== By language (combined recall/fpr | ML-only attack recall) ===');
    for (const [lang, lr] of Object.entries(perLanguage).sort((a, b) => b[1].n - a[1].n).slice(0, 20)) {
      console.log(
        `  ${lang}: n=${lr.n} recall=${lr.attackRecall.toFixed(3)} fpr=${lr.benignFpr.toFixed(3)} mlRecall=${lr.mlAttackRecall.toFixed(3)}`,
      );
    }
  },
  60 * 60_000,
);
