// opensentry/canary — canary tokens for system-prompt-leak detection (PLAN.md security plan #4).
//
// System-prompt extraction is currently caught only heuristically (L3 regex). A canary makes
// leakage DETERMINISTIC and near-zero-FP: inject an unguessable nonce into the system prompt;
// if the nonce ever appears in model output, the prompt was extracted.
//
// Edge-safe: uses only web globals (crypto.getRandomValues, TextEncoder), zero Node builtins.

const CANARY_PREFIX = 'opensentry-canary-';

function randomBytes(n: number): Uint8Array {
  const arr = new Uint8Array(n);
  const c = (globalThis as { crypto?: { getRandomValues(a: Uint8Array): Uint8Array } }).crypto;
  if (c?.getRandomValues) {
    c.getRandomValues(arr);
  } else {
    for (let i = 0; i < n; i++) arr[i] = Math.floor(Math.random() * 256);
  }
  return arr;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += (bytes[i] as number).toString(16).padStart(2, '0');
  return hex;
}

// Create a unique, unguessable canary nonce. 16 random bytes (128 bits) — collision-resistant
// and never typed by a user. The prefix makes it grep-able in logs.
export function createCanary(): string {
  return `${CANARY_PREFIX}${bytesToHex(randomBytes(16))}`;
}

// Inject a canary into a system prompt at a stable, hard-to-strip location (end of the prompt,
// inside an innocuous instruction). Returns the new system prompt. The canary is appended so it
// does not disturb the caller's framing; if the prompt already contains the canary (re-inject),
// it is returned unchanged to avoid duplication.
export function injectCanary(systemPrompt: string, canary: string): string {
  if (canary.length === 0) return systemPrompt;
  if (systemPrompt.includes(canary)) return systemPrompt;
  return `${systemPrompt}\n\n[internal-reference:${canary}]`;
}

// Detect whether any canary leaked into model output. Returns the leaked canary + its span.
// Near-zero FP by construction: a 128-bit random nonce with a fixed prefix does not appear in
// legitimate output unless the system prompt (which contains it) was extracted and echoed.
export function detectCanaryLeak(
  output: string,
  canaries: string[],
): { leaked: boolean; canary?: string; span?: [number, number] } {
  for (const canary of canaries) {
    if (canary.length === 0) continue;
    const idx = output.indexOf(canary);
    if (idx >= 0) {
      return { leaked: true, canary, span: [idx, idx + canary.length] };
    }
  }
  return { leaked: false };
}
