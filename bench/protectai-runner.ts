// Candidate open-model runner: protectai/deberta-v3-base-prompt-injection-v2.
// Apache-2.0, ungated, ONNX weights published in-repo — no export tooling, no HF access
// request, no license ambiguity (unlike meta-llama/Llama-Prompt-Guard-2, see
// bench/REPORT.md). Downloaded directly from the HF hub (no local
// export step exists or is needed — transformers.js caches it under its own cache dir).
//
// Label convention: config.json publishes id2label = {0: "SAFE", 1: "INJECTION"} explicitly
// (verified via the raw HF API) — unlike Llama-Prompt-Guard-2, no empirical guessing needed.
import type { LocalModelResult, LocalModelRunner } from '../src/types.js';

interface TransformersPipeline {
  (text: string, options?: { top_k?: number }): Promise<Array<{ label: string; score: number }>>;
  dispose?: () => void;
}

interface TransformersModule {
  pipeline: (
    task: string,
    model: string,
    options?: { device?: string; dtype?: string },
  ) => Promise<TransformersPipeline>;
}

const MODEL_ID = 'protectai/deberta-v3-base-prompt-injection-v2';
export const INJECTION_LABEL = 'INJECTION';

export async function createProtectAiRunner(
  dtype: 'fp32' | 'q8' = 'fp32',
): Promise<LocalModelRunner> {
  const mod = (await import('@huggingface/transformers')) as unknown as TransformersModule;
  const classifier = await mod.pipeline('text-classification', MODEL_ID, { device: 'cpu', dtype });
  let warmed = false;

  return {
    loaded: true,
    async warm(): Promise<void> {
      if (warmed) return;
      await classifier('warmup', { top_k: 2 });
      warmed = true;
    },
    async classify(text: string): Promise<LocalModelResult> {
      const t0 = performance.now();
      const output = await classifier(text.slice(0, 2000), { top_k: 2 });
      const t1 = performance.now();
      let score = 0;
      for (const item of output) {
        if (item.label === INJECTION_LABEL) {
          score = item.score;
          break;
        }
      }
      return { score, label: score > 0.5 ? 'injection' : 'benign', latencyMs: t1 - t0 };
    },
    dispose(): void {
      classifier.dispose?.();
    },
  };
}
