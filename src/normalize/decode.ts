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
  kind: 'base64' | 'hex' | 'url' | 'html';
  decoded: string;
  source: string; // the exact matched blob text in the input (case-preserved)
  span: [number, number]; // offsets of `source` in the scanned text
}

const B64_RE = /\b[A-Za-z0-9+/]{20,}={0,2}\b/g;
const HEX_RE = /\b[0-9a-fA-F]{20,}\b/g;
const URL_RE = /%[0-9a-fA-F]{2}/;
const ENT_RE = /&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/;

// Longest run of base64-alphabet chars ([A-Za-z0-9+/]). A single cheap char-loop gate
// so benign prose (words ~8 chars) skips the base64/hex regex scans entirely.
function maxAlnumRun(s: string): number {
  let max = 0;
  let cur = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const isAlnum =
      (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 43 || c === 47;
    if (isAlnum) {
      cur++;
      if (cur > max) max = cur;
    } else {
      cur = 0;
    }
  }
  return max;
}

// Find encoded blobs in `text` (the matching copy) and return decoded candidates that
// look like real text. ROT13 is handled by the caller (whole-text transform + rescan).
// `source`/`span` are populated for discrete, span-localized blobs (base64/hex) so callers
// can neutralize them in the model copy; url/html are whole-text transforms (no discrete span).
export function findAndDecode(text: string): DecodedCandidate[] {
  const out: DecodedCandidate[] = [];
  if (text.length === 0) return out;

  let m: RegExpExecArray | null;
  if (maxAlnumRun(text) >= 20) {
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
  }

  if (URL_RE.test(text)) {
    const dec = decodeUrl(text);
    if (dec !== text) out.push({ kind: 'url', decoded: dec, source: '', span: [0, 0] });
  }

  if (ENT_RE.test(text)) {
    const dec = decodeHtmlEntities(text);
    if (dec !== text) out.push({ kind: 'html', decoded: dec, source: '', span: [0, 0] });
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
