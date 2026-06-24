// opensentry/wasm — Tier 1 local ML for edge (WASM SIMD/threads).
// PLAN.md §5: "transformers.js / onnxruntime-web (WASM SIMD/threads) for edge — so edge
// bundles never pull onnxruntime-node". Uses @huggingface/transformers with the WASM backend.
//
// Requires peer dependency:
//   pnpm add @huggingface/transformers
//
// The first call downloads the model from HuggingFace (~25MB int8) unless cached locally.
// In edge runtimes (Cloudflare Workers, Vercel Edge), you may need to configure the model
// path and WASM paths — see the README for deployment guides.

import type { LocalModelDetector, LocalModelResult, LocalModelRunner } from '../types.js';

const MODEL_IDS: Record<string, string> = {
  'llama-prompt-guard-2-22m': 'meta-llama/Llama-Prompt-Guard-2-22m',
  'llama-prompt-guard-2-86m': 'meta-llama/Llama-Prompt-Guard-2-86m',
};

interface TransformersPipeline {
  (text: string, options?: { top_k?: number }): Promise<Array<{ label: string; score: number }>>;
  dispose?: () => void;
}

interface TransformersEnv {
  allowLocalModels: boolean;
  allowRemoteModels: boolean;
  localModelPath: string;
  backends: {
    onnx: {
      wasm: {
        wasmPaths: string | undefined;
        numThreads: number;
        proxy: boolean;
      };
    };
  };
}

interface TransformersModule {
  pipeline: (
    task: string,
    model: string,
    options?: { device?: string; dtype?: string },
  ) => Promise<TransformersPipeline>;
  env: TransformersEnv;
}

export async function createWasmRunner(detector: LocalModelDetector): Promise<LocalModelRunner> {
  let mod: TransformersModule;
  try {
    mod = (await import('@huggingface/transformers')) as unknown as TransformersModule;
  } catch {
    throw new Error(
      'opensentry/wasm: @huggingface/transformers is not installed. Install it with: pnpm add @huggingface/transformers',
    );
  }

  // Configure for WASM backend (onnxruntime-web). In edge environments, onnxruntime-node
  // is not available, so transformers.js falls back to WASM automatically.
  // numThreads=1 for edge compatibility (Workers don't support SharedArrayBuffer).
  mod.env.backends.onnx.wasm.numThreads = 1;

  const modelId =
    MODEL_IDS[detector.model ?? 'llama-prompt-guard-2-22m'] ??
    MODEL_IDS['llama-prompt-guard-2-22m']!;

  // `quantized` (boolean) was a transformers.js v2 option; v3+ replaced it with `dtype` —
  // the old key is silently ignored. Map detector.quantized to dtype explicitly instead of
  // hardcoding 'q8' (so `quantized: false` is actually honorable on this runtime too).
  const classifier = await mod.pipeline('text-classification', modelId, {
    device: 'cpu',
    dtype: (detector.quantized ?? true) ? 'q8' : 'fp32', // q8 default for smaller WASM downloads
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
      const t0 =
        (globalThis as { performance?: { now(): number } }).performance?.now() ?? Date.now();
      const output = await classifier(text, { top_k: 2 });
      const t1 =
        (globalThis as { performance?: { now(): number } }).performance?.now() ?? Date.now();

      let injectionScore = 0;
      let label: 'benign' | 'injection' = 'benign';
      for (const item of output) {
        if (item.label.toUpperCase().includes('INJECTION')) {
          injectionScore = item.score;
          if (injectionScore > 0.5) label = 'injection';
          break;
        }
      }

      return {
        score: injectionScore,
        label,
        latencyMs: t1 - t0,
      };
    },

    dispose(): void {
      classifier.dispose?.();
    },
  };
}
