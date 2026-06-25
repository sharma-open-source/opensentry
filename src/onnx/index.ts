// opensentry/onnx — Tier 1 local ML for Node (native ONNX runtime).
// "onnxruntime-node for Node". Uses @huggingface/transformers for tokenization
// + inference with the native ONNX backend. Edge bundles never pull this subpath.
//
// Requires peer dependencies:
//   pnpm add @huggingface/transformers onnxruntime-node
//
// The first call downloads the model from HuggingFace (~25MB int8) unless cached locally.

import type { LocalModelDetector, LocalModelResult, LocalModelRunner } from '../types.js';

const MODEL_IDS: Record<string, string> = {
  'llama-prompt-guard-2-22m': 'meta-llama/Llama-Prompt-Guard-2-22m',
  'llama-prompt-guard-2-86m': 'meta-llama/Llama-Prompt-Guard-2-86m',
};

// Structural type for the @huggingface/transformers pipeline — avoids importing the
// package at the type level (it's an optional peer dep).
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
    options?: { dtype?: string; device?: string },
  ) => Promise<TransformersPipeline>;
  env: TransformersEnv;
}

export async function createOnnxRunner(detector: LocalModelDetector): Promise<LocalModelRunner> {
  let mod: TransformersModule;
  try {
    mod = (await import('@huggingface/transformers')) as unknown as TransformersModule;
  } catch {
    throw new Error(
      'opensentry/onnx: @huggingface/transformers is not installed. Install it with: pnpm add @huggingface/transformers onnxruntime-node',
    );
  }

  // Prefer native ONNX backend (onnxruntime-node). Don't set wasmPaths so transformers.js
  // auto-detects the native runtime in Node.
  mod.env.backends.onnx.wasm.wasmPaths = undefined;

  const modelId =
    MODEL_IDS[detector.model ?? 'llama-prompt-guard-2-22m'] ??
    MODEL_IDS['llama-prompt-guard-2-22m']!;

  // `quantized` (boolean) was a transformers.js v2 option; v3+ replaced it with `dtype` —
  // passing the old key is silently ignored, which meant `quantized: true` (the default)
  // never actually selected the int8 (`q8`) build and always loaded fp32 on Node. Map it
  // to `dtype` explicitly. Requires the model repo/local export to ship a `model_quantized.onnx`
  // (transformers.js's expected filename for `q8`) — see bench/REPORT.md for how to produce one.
  const classifier = await mod.pipeline('text-classification', modelId, {
    dtype: (detector.quantized ?? true) ? 'q8' : 'fp32',
    device: 'cpu',
  });

  let warmed = false;

  return {
    loaded: true,

    async warm(): Promise<void> {
      if (warmed) return;
      // Run a dummy inference to warm JIT caches and pre-load model weights.
      await classifier('warmup', { top_k: 2 });
      warmed = true;
    },

    async classify(text: string): Promise<LocalModelResult> {
      const t0 =
        (globalThis as { performance?: { now(): number } }).performance?.now() ?? Date.now();
      // top_k: 2 to get both BENIGN and INJECTION labels.
      const output = await classifier(text, { top_k: 2 });
      const t1 =
        (globalThis as { performance?: { now(): number } }).performance?.now() ?? Date.now();

      // Find the INJECTION label (case-insensitive — model may use "INJECTION" or "injection").
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
