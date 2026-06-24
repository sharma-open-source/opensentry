import type { LocalModelDetector, LocalModelRunner } from '../types.js';

// Warm singleton — loads the ML runner once and reuses it across all guard instances.
// PLAN.md §5: "Warm singleton session, int8 weights, graph opts".
// The runner is loaded lazily on first check() that requires escalation, or proactively
// via warmOnBoot. The promise is cached so concurrent callers share the same load.

const runnerCache = new Map<string, Promise<LocalModelRunner>>();

function runnerKey(detector: LocalModelDetector): string {
  return `${detector.runtime ?? 'wasm'}:${detector.model ?? 'llama-prompt-guard-2-22m'}:${detector.quantized ?? true}`;
}

async function loadRunner(detector: LocalModelDetector): Promise<LocalModelRunner> {
  const runtime = detector.runtime ?? 'wasm';
  if (runtime === 'node') {
    try {
      const mod = await import('opensentry/onnx');
      return mod.createOnnxRunner(detector);
    } catch {
      throw new Error(
        'opensentry: failed to load opensentry/onnx. Ensure @huggingface/transformers and onnxruntime-node are installed, or pass a custom runner via the detector config.',
      );
    }
  }
  try {
    const mod = await import('opensentry/wasm');
    return mod.createWasmRunner(detector);
  } catch {
    throw new Error(
      'opensentry: failed to load opensentry/wasm. Ensure @huggingface/transformers is installed, or pass a custom runner via the detector config.',
    );
  }
}

// Get or create the singleton runner for a detector. If detector.runner is provided,
// it's used directly (no lazy import — for testing or custom model paths).
export async function getRunner(detector: LocalModelDetector): Promise<LocalModelRunner> {
  if (detector.runner) return detector.runner;

  const key = runnerKey(detector);
  let cached = runnerCache.get(key);
  if (!cached) {
    cached = loadRunner(detector);
    runnerCache.set(key, cached);
    // If loading fails, evict from cache so the next attempt retries.
    cached.catch(() => {
      runnerCache.delete(key);
    });
  }
  return cached;
}

// Fire-and-forget warming for warmOnBoot. The first check() that needs ML will
// await getRunner() (same promise) and then classify().
export function warmRunner(detector: LocalModelDetector): Promise<void> {
  return getRunner(detector).then((r) => r.warm());
}

// Test-only: clear the runner cache between test cases.
export function clearRunnerCache(): void {
  runnerCache.clear();
}
