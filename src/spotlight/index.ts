// opensentry/spotlight — Microsoft Spotlighting companion (PLAN.md §11a).
// Makes untrusted content unmistakably "data, not instructions" so a successful
// injection cannot forge the channel boundary. Three modes:
//   - delimit:  wrap in a random, unpredictable delimiter (best for raw text)
//   - datamark: prefix each line with a private-use marker char (best ASR/quality tradeoff)
//   - encode:   base64-encode so the content is non-instructional (strongest, needs decode instruction)
//
// Guarantee: if the untrusted input already contains the chosen delimiter/marker,
// spotlight THROWS — preventing delimiter-forgery attacks. Edge-safe: uses only web
// globals (btoa, TextEncoder, crypto.getRandomValues), zero Node builtins.

export type SpotlightMode = 'delimit' | 'datamark' | 'encode';

export interface SpotlightResult {
  text: string;
  delimiter?: string;
  mode: SpotlightMode;
}

export interface SpotlightOptions {
  mode?: SpotlightMode;
  marker?: string;
  randomDelimiter?: () => string;
}

// Private Use Area U+E000 — invisible in most contexts, not typed by users.
const DEFAULT_MARKER = '\uE000';

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
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] as number).toString(16).padStart(2, '0');
  }
  return hex;
}

function defaultRandomDelimiter(): string {
  return `---opensentry-spotlight-${bytesToHex(randomBytes(12))}---`;
}

function base64Encode(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] as number);
  }
  return btoa(binary);
}

export function spotlight(untrusted: string, opts?: SpotlightOptions): SpotlightResult {
  const mode = opts?.mode ?? 'datamark';

  if (mode === 'delimit') {
    const gen = opts?.randomDelimiter ?? defaultRandomDelimiter;
    const delimiter = gen();
    if (untrusted.includes(delimiter)) {
      throw new Error(
        'opensentry spotlight: untrusted input already contains the delimiter — possible forgery attempt',
      );
    }
    return {
      text: `${delimiter}\n${untrusted}\n${delimiter}`,
      delimiter,
      mode,
    };
  }

  if (mode === 'datamark') {
    const marker = opts?.marker ?? DEFAULT_MARKER;
    if (marker.length === 0) {
      throw new Error('opensentry spotlight: marker must not be empty');
    }
    if (untrusted.includes(marker)) {
      throw new Error(
        'opensentry spotlight: untrusted input already contains the marker — possible forgery attempt',
      );
    }
    const marked = untrusted
      .split('\n')
      .map((line) => `${marker}${line}`)
      .join('\n');
    return { text: marked, mode };
  }

  // encode
  return { text: base64Encode(untrusted), mode };
}
