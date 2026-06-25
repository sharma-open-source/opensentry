// Tier 2 live runner — meta-llama/llama-guard-4-12b via OpenRouter, using Llama Guard's own
// native classification protocol (raw passthrough message -> "safe" | "unsafe\nS<n>"),
// NOT src/remote's createLlamaGuardChatProvider.
//
// Why not the shared adapter: createLlamaGuardChatProvider wraps the input text in a custom
// "respond with JSON" judge prompt (designed for general instruction-following LLM judges).
// Llama Guard is a purpose-built safety classifier, not an instruction-follower — sent that
// wrapper, it classifies the wrapper prompt itself (which reads as benign) and always
// replies "safe", regardless of what's embedded inside. Verified directly against the live
// endpoint: sending the raw text reproduces Llama Guard's documented "safe"/"unsafe\nS<n>"
// taxonomy output correctly (e.g. a harmful-content request returns "unsafe\nS2"), while the
// wrapped judge prompt does not. This is a content-safety classifier (violence, weapons,
// CSAE, etc.), not a prompt-injection/instruction-override classifier — see
// bench/REPORT.md "Tier 2 — live llama-guard sample" for what that means for recall here.

export interface RemoteRunnerResult {
  score: number; // binary: 1 = unsafe, 0 = safe (Llama Guard has no continuous confidence)
  label: 'benign' | 'injection';
  categories?: string[]; // e.g. ["S2"] — Llama Guard taxonomy codes, raw passthrough
  latencyMs: number;
  error?: string;
}

interface ChatCompletionResponse {
  choices?: Array<{ message?: { content?: string } }>;
}

function parseLlamaGuardContent(content: string): { score: number; categories: string[] } {
  const trimmed = content.trim();
  if (trimmed.toLowerCase().startsWith('unsafe')) {
    const categories = trimmed
      .split('\n')
      .slice(1)
      .flatMap((line) => line.split(','))
      .map((c) => c.trim())
      .filter(Boolean);
    return { score: 1, categories };
  }
  return { score: 0, categories: [] };
}

export function createLlamaGuardRunner(opts: {
  apiKey: string;
  baseURL: string;
  model: string;
  fetchImpl?: typeof fetch;
}) {
  const url = new URL('chat/completions', opts.baseURL).toString();
  const doFetch = opts.fetchImpl ?? fetch;

  return {
    async classify(text: string): Promise<RemoteRunnerResult> {
      const t0 = performance.now();
      try {
        const res = await doFetch(url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${opts.apiKey}`,
          },
          body: JSON.stringify({
            model: opts.model,
            temperature: 0,
            messages: [{ role: 'user', content: text }],
          }),
        });
        if (!res.ok) {
          throw new Error(`${opts.model} responded ${res.status}`);
        }
        const json = (await res.json()) as ChatCompletionResponse;
        const content = json.choices?.[0]?.message?.content ?? '';
        const { score, categories } = parseLlamaGuardContent(content);
        return {
          score,
          label: score >= 0.5 ? 'injection' : 'benign',
          categories,
          latencyMs: performance.now() - t0,
        };
      } catch (err) {
        return {
          score: 0,
          label: 'benign',
          latencyMs: performance.now() - t0,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  };
}
