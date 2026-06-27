// Compact curated subset of UTS-39 confusables covering the high-impact cross-script
// look-alikes that NFKC does NOT fold (Cyrillic/Greek letters resembling ASCII letters).
// Applied to the MATCHING copy only — NEVER the model copy (risk R4).
//
// NFKC already folds fullwidth (U+FF01–FF5E) and Mathematical Alphanumeric Symbols
// (U+1D400–1D7FF) to ASCII, so this table only needs the visually-confusable-but-
// not-compatibility-equivalent chars that survive NFKC.

export const COMPACT_CONFUSABLES: ReadonlyMap<number, string> = new Map<number, string>([
  // Cyrillic lowercase → ASCII
  [0x0430, 'a'], // а
  [0x0435, 'e'], // е
  [0x0456, 'i'], // і
  [0x0438, 'u'], // и (Cyrillic I — UTS#39-confusable with Latin u)
  [0x043e, 'o'], // о
  [0x043f, 'n'], // п (Cyrillic PE — UTS#39-confusable with Latin n)
  [0x0440, 'p'], // р
  [0x0441, 'c'], // с
  [0x0443, 'y'], // у
  [0x0445, 'x'], // х
  [0x0433, 'r'], // г (Cyrillic GE — UTS#39-confusable with Latin r)
  [0x0458, 'j'], // ј
  [0x0455, 's'], // ѕ
  [0x04bb, 'h'], // һ (shha)
  // Cyrillic uppercase → ASCII
  [0x0410, 'A'], // А
  [0x0412, 'B'], // В
  [0x0413, 'R'], // Г (Cyrillic GE — UTS#39-confusable with Latin R)
  [0x0415, 'E'], // Е
  [0x0406, 'I'], // І
  [0x0408, 'J'], // Ј
  [0x041a, 'K'], // К
  [0x041c, 'M'], // М
  [0x041d, 'H'], // Н
  [0x041e, 'O'], // О
  [0x041f, 'N'], // П (Cyrillic PE — UTS#39-confusable with Latin N)
  [0x0420, 'P'], // Р
  [0x0421, 'C'], // С
  [0x0405, 'S'], // Ѕ
  [0x0422, 'T'], // Т
  [0x0425, 'X'], // Х
  [0x04c0, 'I'], // Ӏ (palochka)
  // Greek lowercase → ASCII
  [0x03b1, 'a'], // α
  [0x03b5, 'e'], // ε
  [0x03b7, 'n'], // η (Greek ETA — UTS#39-confusable with Latin n)
  [0x03b9, 'i'], // ι
  [0x03bc, 'u'], // μ (Greek MU — UTS#39-confusable with Latin u)
  [0x03bd, 'v'], // ν (Greek NU — UTS#39-confusable with Latin v)
  [0x03bf, 'o'], // ο
  [0x03c1, 'p'], // ρ
  [0x03c4, 't'], // τ (Greek TAU — UTS#39-confusable with Latin t; uppercase Τ already present)
  // Greek uppercase → ASCII
  [0x0391, 'A'], // Α
  [0x0392, 'B'], // Β (Greek BETA — UTS#39-confusable with Latin B)
  [0x0395, 'E'], // Ε
  [0x0399, 'I'], // Ι
  [0x039c, 'M'], // Μ (Greek MU — UTS#39-confusable with Latin M)
  [0x039d, 'N'], // Ν (Greek NU — UTS#39-confusable with Latin N)
  [0x039f, 'O'], // Ο
  [0x03a1, 'P'], // Ρ
  [0x03a4, 'T'], // Τ
  // Latin extensions that are visually confusable
  [0x0269, 'i'], // ɩ Latin small iota
]);

export interface FoldResult {
  text: string;
  count: number;
}

// Whitespace boundaries for token segmentation (ASCII + common Unicode spaces). Folding runs
// before whitespace collapse, so exotic spaces are still present here — covering them keeps a
// non-Latin word from being glued to a neighbouring Latin one and mis-scoring the token.
function isTokenSpace(cc: number): boolean {
  return (
    cc === 32 ||
    cc === 9 ||
    cc === 10 ||
    cc === 13 ||
    cc === 12 ||
    cc === 11 ||
    cc === 0xa0 ||
    (cc >= 0x2000 && cc <= 0x200a) ||
    cc === 0x202f ||
    cc === 0x205f ||
    cc === 0x3000
  );
}

// A Cyrillic or Greek letter that is NOT itself a confusable — i.e. proof the token is genuinely
// written in that script (ж, ц, ш, β, γ, …), not a Latin word with a few look-alikes swapped in.
function isNativeCyrillicOrGreek(cc: number, table: ReadonlyMap<number, string>): boolean {
  if (table.has(cc)) return false;
  return (cc >= 0x0400 && cc <= 0x04ff) || (cc >= 0x0370 && cc <= 0x03ff);
}

// Fold confusables; also report how many substitutions were made so L1 can emit a
// `confusable_run` reason proportional to density.
//
// Token-aware: a confusable letter is only a homoglyph signal when it sits inside a
// predominantly-LATIN token (the Cyrillic 'а' in "pаypal"). A coherent non-Latin token — a real
// Russian/Greek word — is full of look-alikes that would ALL fold, manufacturing a false
// `confusable_run` AND, because the residual native letters survive, a false L2 `script_mixing`
// on otherwise-monoscript text. So we fold a token only when its Latin anchors are at least as
// many as its native Cyrillic/Greek anchors (and it has at least one Latin anchor). Pure-ASCII /
// clean text takes a fast no-allocation path.
export function foldConfusables(
  s: string,
  table: ReadonlyMap<number, string> = COMPACT_CONFUSABLES,
): FoldResult {
  if (s.length === 0) return { text: s, count: 0 };

  // Fast path: no confusables anywhere → return original untouched (covers all clean text).
  let hasConfusable = false;
  for (let i = 0; i < s.length; i++) {
    if (table.has(s.charCodeAt(i))) {
      hasConfusable = true;
      break;
    }
  }
  if (!hasConfusable) return { text: s, count: 0 };

  let out = '';
  let count = 0;
  const n = s.length;
  let i = 0;
  while (i < n) {
    const c0 = s.charCodeAt(i);
    if (isTokenSpace(c0)) {
      out += s[i] as string;
      i++;
      continue;
    }
    // Scan the whole non-space token first so the fold decision sees its full script makeup.
    let j = i;
    let latinAnchors = 0;
    let nativeAnchors = 0;
    while (j < n && !isTokenSpace(s.charCodeAt(j))) {
      const c = s.charCodeAt(j);
      if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) latinAnchors++;
      else if (isNativeCyrillicOrGreek(c, table)) nativeAnchors++;
      j++;
    }
    const token = s.slice(i, j);
    if (latinAnchors >= 1 && latinAnchors >= nativeAnchors) {
      for (let k = 0; k < token.length; k++) {
        const sub = table.get(token.charCodeAt(k));
        if (sub !== undefined) {
          out += sub;
          count++;
        } else {
          out += token[k] as string;
        }
      }
    } else {
      out += token;
    }
    i = j;
  }

  if (count === 0) return { text: s, count: 0 };
  return { text: out, count };
}
