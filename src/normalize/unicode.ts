// Unicode character classification + single-pass cleaning for L1 normalization.
// PLAN.md §5 L1: strip+count invisible/variation-selectors/C0-C1, hard-flag Tag block,
// strip/isolate bidi controls. Pure arithmetic over code units — no allocations beyond
// the output string. Edge-safe (no Node builtins).

export interface CleanCounts {
  zeroWidth: number;
  variationSelector: number;
  control: number;
  tag: number;
  bidiEmbed: number; // 202A,202B,202C (LRE/RLE/PDF)
  bidiOverride: number; // 202D (LRO), 202E (RLO)
  bidiIsolate: number; // 2066–2069 (LRI/RLI/FSI/PDI)
  strippedTotal: number;
}

export interface CleanResult {
  text: string;
  counts: CleanCounts;
}

const ZERO_WIDTH = new Set<number>([0x200b, 0x200c, 0x200d, 0xfeff, 0x2060, 0x00ad]);
const BIDI_EMBED = new Set<number>([0x202a, 0x202b, 0x202c]); // LRE, RLE, PDF
const BIDI_OVERRIDE = new Set<number>([0x202d, 0x202e]); // LRO, RLO
const BIDI_ISOLATE = new Set<number>([0x2066, 0x2067, 0x2068, 0x2069]); // LRI, RLI, FSI, PDI

function isVariationSelector(cp: number): boolean {
  return (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
}
function isControl(cp: number): boolean {
  // C0 0x00–0x1F except \t \n \r, plus DEL 0x7F and C1 0x80–0x9F
  if (cp === 0x09 || cp === 0x0a || cp === 0x0d) return false;
  if (cp >= 0x00 && cp <= 0x1f) return true;
  return cp >= 0x7f && cp <= 0x9f;
}
function isTagBlock(cp: number): boolean {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

export type BidiMode = 'strip' | 'isolate' | 'off';

// Strip invisible/controls/Tag/bidi in one pass and count by category.
// `bidiMode`:
//   'strip'   – remove ALL bidi controls (202A–202E and 2066–2069)
//   'isolate' – remove legacy embed/override (202A–202E), KEEP isolates (2066–2069)
//   'off'     – keep everything (no bidi stripping)
export function cleanInvisibles(input: string, bidiMode: BidiMode): CleanResult {
  const counts: CleanCounts = {
    zeroWidth: 0,
    variationSelector: 0,
    control: 0,
    tag: 0,
    bidiEmbed: 0,
    bidiOverride: 0,
    bidiIsolate: 0,
    strippedTotal: 0,
  };
  if (input.length === 0) return { text: input, counts };

  // Lazy output: only start building `out` once we hit the first stripped char. For clean
  // input (the common case), we scan without allocating a copy and return the original.
  let out = '';
  let outStarted = false;
  for (let i = 0; i < input.length; ) {
    const code = input.charCodeAt(i);
    // Astral code point?
    let cp = code;
    let adv = 1;
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < input.length) {
      const low = input.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        cp = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        adv = 2;
      }
    }

    let strip = false;
    if (isTagBlock(cp)) {
      counts.tag++;
      strip = true;
    } else if (ZERO_WIDTH.has(cp)) {
      counts.zeroWidth++;
      strip = true;
    } else if (isVariationSelector(cp)) {
      counts.variationSelector++;
      strip = true;
    } else if (isControl(cp)) {
      counts.control++;
      strip = true;
    } else if (BIDI_EMBED.has(cp)) {
      counts.bidiEmbed++;
      if (bidiMode !== 'off') strip = true;
    } else if (BIDI_OVERRIDE.has(cp)) {
      counts.bidiOverride++;
      if (bidiMode !== 'off') strip = true;
    } else if (BIDI_ISOLATE.has(cp)) {
      counts.bidiIsolate++;
      if (bidiMode === 'strip') strip = true; // isolates kept in 'isolate' and 'off'
    }

    if (strip) {
      if (!outStarted) {
        out = input.slice(0, i);
        outStarted = true;
      }
      counts.strippedTotal++;
      i += adv;
      continue;
    }
    if (outStarted) out += adv === 2 ? input.slice(i, i + 2) : (input[i] as string);
    i += adv;
  }

  // Nothing stripped → return original string (avoids a redundant copy for clean input).
  if (counts.strippedTotal === 0) return { text: input, counts };
  return { text: out, counts };
}

// Collapse horizontal whitespace (incl. exotic/nbsp) runs to a single space;
// normalize CRLF/CR to LF. Preserves newline structure for L3 structural regex.
const HWS_RUN = /[^\S\n]+/g;
const CR = /\r\n?/g;
export function collapseWhitespace(s: string): string {
  if (s.length === 0) return s;
  return s.replace(CR, '\n').replace(HWS_RUN, ' ');
}

// Fast UTF-8 byte length without allocating a TextEncoder buffer (PLAN.md L0: no
// hot-path allocation). O(n) arithmetic over code units.
export function utf8ByteLength(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; ) {
    const code = s.charCodeAt(i);
    if (code < 0x80) {
      n += 1;
      i += 1;
    } else if (code < 0x800) {
      n += 2;
      i += 1;
    } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < s.length) {
      const low = s.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        n += 4;
        i += 2;
      } else {
        n += 3;
        i += 1; // lone surrogate → 3-byte replacement-ish
      }
    } else {
      n += 3;
      i += 1;
    }
  }
  return n;
}

// Truncate to a UTF-8 byte budget on a code-point boundary; never split a surrogate.
export function truncateToBytes(s: string, maxBytes: number): { text: string; truncated: boolean } {
  if (s.length === 0) return { text: s, truncated: false };
  let n = 0;
  let i = 0;
  while (i < s.length) {
    const code = s.charCodeAt(i);
    let inc = 1;
    let add = 0;
    if (code < 0x80) add = 1;
    else if (code < 0x800) add = 2;
    else if (code >= 0xd800 && code <= 0xdbff && i + 1 < s.length) {
      const low = s.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        add = 4;
        inc = 2;
      } else {
        add = 3;
      }
    } else {
      add = 3;
    }
    if (n + add > maxBytes) break;
    n += add;
    i += inc;
  }
  return { text: s.slice(0, i), truncated: i < s.length };
}
