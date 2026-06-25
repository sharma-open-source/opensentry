// REAL Tier-1 runner: the shipped default model, meta-llama/Llama-Prompt-Guard-2-22M,
// exported locally to ONNX via `optimum-cli export onnx` (no public ONNX mirror exists for
// this gated repo) and loaded from disk — see bench/models/llama-prompt-guard-2-22m/.
//
// Label convention: the exported config.json carries no id2label (verified against the
// raw upstream config.json — Meta's card example assumes a mapping that isn't actually in
// the repo's config). MALICIOUS_LABEL below was fixed empirically against known attack/benign
// text rather than guessed from docs.
//
// dtype defaults to 'fp32' (matches the original model.onnx export). Pass 'q8' to load
// model_quantized.onnx instead (produced via onnxruntime.quantization.quantize_dynamic —
// see bench/REPORT.md "Quantization" section for the exact command) — this is the file
// transformers.js looks for when dtype:'q8' is requested (src/onnx/index.ts uses the same
// mapping for the shipped `quantized` detector option).
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
  env: {
    allowLocalModels: boolean;
    allowRemoteModels: boolean;
    localModelPath: string;
    backends: { onnx: { wasm: { wasmPaths: string | undefined } } };
  };
}

export const MALICIOUS_LABEL = 'LABEL_1';

export async function createRealPromptGuardRunner(
  localModelPath: string,
  modelDirName: string,
  dtype: 'fp32' | 'q8' = 'fp32',
): Promise<LocalModelRunner> {
  const mod = (await import('@huggingface/transformers')) as unknown as TransformersModule;
  mod.env.allowLocalModels = true;
  mod.env.allowRemoteModels = false;
  mod.env.localModelPath = localModelPath;
  mod.env.backends.onnx.wasm.wasmPaths = undefined;

  const classifier = await mod.pipeline('text-classification', modelDirName, {
    device: 'cpu',
    dtype,
  });
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
      let maliciousScore = 0;
      for (const item of output) {
        if (item.label === MALICIOUS_LABEL) {
          maliciousScore = item.score;
          break;
        }
      }
      return {
        score: maliciousScore,
        label: maliciousScore > 0.5 ? 'injection' : 'benign',
        latencyMs: t1 - t0,
      };
    },
    dispose(): void {
      classifier.dispose?.();
    },
  };
}
