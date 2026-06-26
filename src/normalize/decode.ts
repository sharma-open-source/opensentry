// L2 — bounded decode-and-rescan. Decodes base64/hex/URL/HTML-entity blobs and
// ROT13, returning candidate decoded strings for re-scanning through L1+L3.
// Gated behind an entropy/looks-encoded check so benign text skips it (hot path stays fast).
// Uses only Web-standard globals (atob, TextDecoder, Uint8Array) — edge-safe, zero-dep.

const NAMED_ENTITIES: Readonly<Record<string, string>> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  sol: '/',
  verbar: '|',
  lpar: '(',
  rpar: ')',
  semi: ';',
  period: '.',
  colon: ':',
  num: '#',
  equals: '=',
  comma: ',',
  excl: '!',
  quest: '?',
  dollar: '$',
  percnt: '%',
};

function bytesToUtf8(bin: string): string {
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

export function decodeBase64(blob: string): string | null {
  try {
    const clean = blob.replace(/[^A-Za-z0-9+/=]/g, '');
    if (clean.length === 0) return null;
    const pad = (4 - (clean.length % 4)) % 4;
    const padded = pad ? clean + '='.repeat(pad) : clean;
    const bin = atob(padded);
    if (bin.length < 4) return null;
    return bytesToUtf8(bin);
  } catch {
    return null;
  }
}

export function decodeHex(blob: string): string | null {
  if (blob.length % 2 !== 0 || blob.length < 4) return null;
  const bytes = new Uint8Array(blob.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const b = parseInt(blob.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(b)) return null;
    bytes[i] = b;
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

export function decodeUrl(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export function decodeBase32(blob: string): string | null {
  // RFC 4648 base32 (case-insensitive). A backslash-free, alnum-only alphabet so the existing
  // alnum-run gate covers it. Pad to a multiple of 8 like a standard base32 decoder.
  const up = blob.toUpperCase().replace(/[^A-Z2-7=]/g, '');
  if (up.length === 0) return null;
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let bin = '';
  for (let i = 0; i < up.length; i++) {
    const ch = up.charAt(i);
    if (ch === '=') break;
    const idx = ALPHA.indexOf(ch);
    if (idx < 0) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bin += String.fromCharCode((value >> bits) & 0xff);
    }
  }
  if (bin.length < 4) return null;
  return bytesToUtf8(bin);
}

export function decodeJsUnicodeEscape(s: string): string | null {
  // JS/JSON-style escapes: \uXXXX, \u{XXXXXX}, \xXX. Substitutes the escapes IN PLACE so
  // the surrounding literal text (which usually carries the injection verbs) survives for
  // rescan — only the escapes are decoded, not the whole text discarded. Backslash-gated.
  if (!s.includes('\\')) return null;
  let any = false;
  const re = /\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g;
  const out = s.replace(re, (m, brace?: string, quad?: string, hex?: string) => {
    const cp =
      brace !== undefined
        ? parseInt(brace, 16)
        : quad !== undefined
          ? parseInt(quad, 16)
          : parseInt(hex as string, 16);
    if (cp > 0x10ffff) return m;
    any = true;
    try {
      return String.fromCodePoint(cp);
    } catch {
      return m;
    }
  });
  if (!any) return null;
  return out;
}

export function decodeOctal(s: string): string | null {
  // C-style \NNN / \NN octal escapes (1–3 octal digits). Substitutes in place so surrounding
  // text survives for rescan. Backslash-gated so prose with no `\` pays nothing.
  if (!s.includes('\\')) return null;
  let any = false;
  const re = /\\([0-3][0-7]{0,2}|[4-7][0-7]?)/g;
  const out = s.replace(re, (_m, digits?: string) => {
    any = true;
    return String.fromCharCode(parseInt(digits as string, 8) & 0xff);
  });
  if (!any) return null;
  return out;
}

export function decodeHtmlEntities(s: string): string {
  return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, (m, body: string) => {
    if (body.length > 0 && body[0] === '#') {
      let cp: number;
      if (body.length > 1 && (body[1] === 'x' || body[1] === 'X')) {
        cp = Number.parseInt(body.slice(2), 16);
      } else {
        cp = Number.parseInt(body.slice(1), 10);
      }
      if (Number.isNaN(cp) || cp < 0 || cp > 0x10ffff) return m;
      try {
        return String.fromCodePoint(cp);
      } catch {
        return m;
      }
    }
    return NAMED_ENTITIES[body] ?? m;
  });
}

export function rot13(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) {
      out += String.fromCharCode(((c - 65 + 13) % 26) + 65);
    } else if (c >= 97 && c <= 122) {
      out += String.fromCharCode(((c - 97 + 13) % 26) + 97);
    } else {
      out += s[i] as string;
    }
  }
  return out;
}

function isMostlyPrintable(s: string): boolean {
  if (s.length === 0) return false;
  let printable = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 0x20 && c < 0x7f) || c === 0x09 || c === 0x0a || c === 0x0d || c >= 0x80) printable++;
  }
  return printable / s.length > 0.7;
}

export interface DecodedCandidate {
  kind: 'base64' | 'hex' | 'url' | 'html' | 'base32' | 'jsunicode' | 'octal';
  decoded: string;
  source: string; // the exact matched blob text in the input (case-preserved)
  span: [number, number]; // offsets of `source` in the scanned text
}

const MORSE_ALPHABET: Readonly<Record<string, string>> = {
  '.-': 'a',
  '-...': 'b',
  '-.-.': 'c',
  '-..': 'd',
  '.': 'e',
  '..-.': 'f',
  '--.': 'g',
  '....': 'h',
  '..': 'i',
  '.---': 'j',
  '-.-': 'k',
  '.-..': 'l',
  '--': 'm',
  '-.': 'n',
  '---': 'o',
  '.--.': 'p',
  '--.-': 'q',
  '.-.': 'r',
  '...': 's',
  '-': 't',
  '..-': 'u',
  '...-': 'v',
  '.--': 'w',
  '-..-': 'x',
  '-.--': 'y',
  '--..': 'z',
  '-----': '0',
  '.----': '1',
  '..---': '2',
  '...--': '3',
  '....-': '4',
  '.....': '5',
  '-....': '6',
  '--...': '7',
  '---..': '8',
  '----.': '9',
};
// Whole-text gate: the input must be ONLY morse glyphs (dot/dash/word-slash) and whitespace —
// a single stray letter or digit aborts the match. This keeps normal prose containing the
// occasional dash or bullet ("- item one\n- item two") from ever reaching the decode attempt.
const MORSE_ONLY_RE = /^[.\-\s/]+$/;

export function decodeMorse(s: string): string | null {
  const trimmed = s.trim();
  if (trimmed.length < 4 || !MORSE_ONLY_RE.test(trimmed)) return null;
  const words = trimmed.split(/\s{2,}|\//).filter((w) => w.trim().length > 0);
  if (words.length === 0) return null;
  const decodedWords: string[] = [];
  for (const word of words) {
    const letters = word.trim().split(/\s+/).filter(Boolean);
    let decodedWord = '';
    for (const letter of letters) {
      const ch = MORSE_ALPHABET[letter];
      if (ch === undefined) return null; // any invalid token aborts — no partial-garbage decodes
      decodedWord += ch;
    }
    decodedWords.push(decodedWord);
  }
  return decodedWords.join(' ');
}

const B64_RE = /\b[A-Za-z0-9+/]{20,}={0,2}\b/g;
const HEX_RE = /\b[0-9a-fA-F]{20,}\b/g;
const URL_RE = /%[0-9a-fA-F]{2}/;
const ENT_RE = /&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/;
// Base32 alnum-only blob (RFC 4648 alphabet A–Z2–7). Covered by the ≥20 alnum-run gate.
const B32_RE = /\b[A-Za-z2-7]{20,}={0,6}\b/g;
// Catch base64/hex blobs split with whitespace/newlines (e.g. "SWdub3JlIGFs\nbCBydWxlcw==").
// Only applied when the single-run gate fails; matches two+ alnum runs of >=8 chars separated
// only by whitespace so a benign two-word sentence (rare) costs one bounded regex pass.
const SPLIT_ALNUM_RE = /[A-Za-z0-9+/]{8,}(?:[\s]+[A-Za-z0-9+/=]{8,})+/g;

interface AlnumStats {
  max: number;
  splitCandidate: boolean;
}

// Longest run of base64-alphabet chars ([A-Za-z0-9+/]) plus a "split candidate" flag: true when
// the text contains two alnum runs of >=8 chars separated only by whitespace with a combined
// length >=20 (a base64/hex blob split to evade the single-run gate). Computed in the SAME
// char-loop pass so benign prose pays nothing extra for the split-aware decode path.
function alnumStats(s: string): AlnumStats {
  let max = 0;
  let cur = 0;
  let splitCandidate = false;
  // Length of the last alnum run (>=8) that is immediately followed by whitespace — candidate
  // for the left half of a whitespace-split base64/hex blob. Cleared by any non-ws non-alnum char.
  let leftPending = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const isAlnum =
      (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 43 || c === 47;
    if (isAlnum) {
      cur++;
      if (cur > max) max = cur;
      if (cur >= 8 && leftPending >= 8 && leftPending + cur >= 20) splitCandidate = true;
    } else {
      if (cur > 0) {
        leftPending = cur >= 8 ? cur : 0;
        cur = 0;
      }
      const isWs = c === 32 || c === 9 || c === 10 || c === 13;
      if (!isWs) leftPending = 0;
    }
  }
  return { max, splitCandidate };
}

// Find encoded blobs in `text` (the matching copy) and return decoded candidates that
// look like real text. ROT13 is handled by the caller (whole-text transform + rescan).
// `source`/`span` are populated for discrete, span-localized blobs (base64/hex) so callers
// can neutralize them in the model copy; url/html are whole-text transforms (no discrete span).
export function findAndDecode(text: string): DecodedCandidate[] {
  const out: DecodedCandidate[] = [];
  if (text.length === 0) return out;

  let m: RegExpExecArray | null;
  const stats = alnumStats(text);
  if (stats.max >= 20) {
    B64_RE.lastIndex = 0;
    while ((m = B64_RE.exec(text)) !== null) {
      const blob = m[0] as string;
      const dec = decodeBase64(blob);
      if (dec !== null && isMostlyPrintable(dec)) {
        out.push({
          kind: 'base64',
          decoded: dec,
          source: blob,
          span: [m.index, m.index + blob.length],
        });
      }
      if (blob.length === 0) B64_RE.lastIndex++;
    }

    HEX_RE.lastIndex = 0;
    while ((m = HEX_RE.exec(text)) !== null) {
      const blob = m[0] as string;
      if (blob.length % 2 === 0) {
        const dec = decodeHex(blob);
        if (dec !== null && isMostlyPrintable(dec)) {
          out.push({
            kind: 'hex',
            decoded: dec,
            source: blob,
            span: [m.index, m.index + blob.length],
          });
        }
      }
      if (blob.length === 0) HEX_RE.lastIndex++;
    }

    // Base32 (RFC 4648, alnum-only A–Z2–7 alphabet) — reuses the ≥20 alnum-run gate.
    B32_RE.lastIndex = 0;
    while ((m = B32_RE.exec(text)) !== null) {
      const blob = m[0] as string;
      const dec = decodeBase32(blob);
      if (dec !== null && isMostlyPrintable(dec)) {
        out.push({
          kind: 'base32',
          decoded: dec,
          source: blob,
          span: [m.index, m.index + blob.length],
        });
      }
      if (blob.length === 0) B32_RE.lastIndex++;
    }
  }

  // Split base64/hex: a blob sliced with whitespace/newlines slips under the ≥20 single-run
  // gate (`SWdub3JlIGFs bCBydWxlcw==`). Only reached when the single-run gate failed but the
  // one-pass flag spotted two ≥8 alnum runs across whitespace — confined to the decode copy
  // (R4) and bounded by count so a pathological input can't loop.
  if (stats.max < 20 && stats.splitCandidate) {
    SPLIT_ALNUM_RE.lastIndex = 0;
    let splitCount = 0;
    while ((m = SPLIT_ALNUM_RE.exec(text)) !== null && splitCount < 16) {
      const matched = m[0] as string;
      const blob = matched.replace(/\s+/g, '');
      if (blob.length >= 20) {
        // Only attempt base64 when the joined run carries a base64 signature (digit / + / / / =).
        // Pure-letter pairs like "previous instructions" join to a valid-base64-alphabet string
        // that atob happily decodes to garbage — skipped here so benign two-word prose (already
        // rare to reach this gate) doesn't pay for a wasted decode + rescan.
        if (/[0-9+/=]/.test(blob)) {
          const dec = decodeBase64(blob);
          if (dec !== null && isMostlyPrintable(dec)) {
            out.push({
              kind: 'base64',
              decoded: dec,
              source: matched,
              span: [m.index, m.index + matched.length],
            });
            splitCount++;
            continue;
          }
        }
        if (blob.length % 2 === 0) {
          const hdec = decodeHex(blob);
          if (hdec !== null && isMostlyPrintable(hdec)) {
            out.push({
              kind: 'hex',
              decoded: hdec,
              source: matched,
              span: [m.index, m.index + matched.length],
            });
            splitCount++;
          }
        }
      }
      if (matched.length === 0) SPLIT_ALNUM_RE.lastIndex++;
    }
  }

  if (URL_RE.test(text)) {
    const dec = decodeUrl(text);
    if (dec !== text) out.push({ kind: 'url', decoded: dec, source: '', span: [0, 0] });
  }

  if (ENT_RE.test(text)) {
    const dec = decodeHtmlEntities(text);
    if (dec !== text) out.push({ kind: 'html', decoded: dec, source: '', span: [0, 0] });
  }

  // JS-unicode (\uXXXX / \u{...} / \xXX) and C-octal (\NNN) escapes: backslash-gated so prose
  // with no `\` pays nothing. Whole-text transforms (no discrete span) like url/html.
  if (text.includes('\\')) {
    const ju = decodeJsUnicodeEscape(text);
    if (ju !== null && ju !== text && isMostlyPrintable(ju)) {
      out.push({ kind: 'jsunicode', decoded: ju, source: '', span: [0, 0] });
    }
    const oc = decodeOctal(text);
    if (oc !== null && oc !== text && isMostlyPrintable(oc)) {
      out.push({ kind: 'octal', decoded: oc, source: '', span: [0, 0] });
    }
  }

  return out;
}

// Shannon entropy (bits/char) over a 256-bucket byte histogram of code units. A fast
// proxy used as the decode-rescan routing gate (reused module-level buffer, no Map).
const FREQ = new Uint32Array(256);
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const n = s.length;
  for (let i = 0; i < 256; i++) FREQ[i] = 0;
  for (let i = 0; i < n; i++) {
    const idx = s.charCodeAt(i) & 0xff;
    FREQ[idx] = (FREQ[idx] ?? 0) + 1;
  }
  let h = 0;
  for (let i = 0; i < 256; i++) {
    const c = FREQ[i] ?? 0;
    if (c > 0) {
      const p = c / n;
      h -= p * Math.log2(p);
    }
  }
  return h;
}
