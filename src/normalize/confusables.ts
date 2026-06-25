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
  [0x043e, 'o'], // о
  [0x0440, 'p'], // р
  [0x0441, 'c'], // с
  [0x0443, 'y'], // у
  [0x0445, 'x'], // х
  [0x0458, 'j'], // ј
  [0x0455, 's'], // ѕ
  [0x04bb, 'h'], // һ (shha)
  // Cyrillic uppercase → ASCII
  [0x0410, 'A'], // А
  [0x0412, 'B'], // В
  [0x0415, 'E'], // Е
  [0x0406, 'I'], // І
  [0x0408, 'J'], // Ј
  [0x041a, 'K'], // К
  [0x041c, 'M'], // М
  [0x041d, 'H'], // Н
  [0x041e, 'O'], // О
  [0x0420, 'P'], // Р
  [0x0421, 'C'], // С
  [0x0405, 'S'], // Ѕ
  [0x0422, 'T'], // Т
  [0x0425, 'X'], // Х
  [0x04c0, 'I'], // Ӏ (palochka)
  // Greek lowercase → ASCII
  [0x03b1, 'a'], // α
  [0x03b5, 'e'], // ε
  [0x03b9, 'i'], // ι
  [0x03bf, 'o'], // ο
  [0x03c1, 'p'], // ρ
  // Greek uppercase → ASCII
  [0x0391, 'A'], // Α
  [0x0395, 'E'], // Ε
  [0x0399, 'I'], // Ι
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

// Fold confusables in one pass; also report how many substitutions were made so L1
// can emit a `confusable_run` reason proportional to density. Uses lazy output building:
// for clean input (no confusables — the common case), returns the original string without
// allocating a copy.
export function foldConfusables(
  s: string,
  table: ReadonlyMap<number, string> = COMPACT_CONFUSABLES,
): FoldResult {
  if (s.length === 0) return { text: s, count: 0 };
  let out = '';
  let outStarted = false;
  let count = 0;
  for (let i = 0; i < s.length; ) {
    const code = s.charCodeAt(i);
    const sub = table.get(code);
    if (sub !== undefined) {
      if (!outStarted) {
        out = s.slice(0, i);
        outStarted = true;
      }
      out += sub;
      count++;
      i++;
      continue;
    }
    // Handle surrogate pairs for astral code points (none in the compact table, but
    // keep this correct so future tables with astral entries work).
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < s.length) {
      const low = s.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        const cp = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        const sub2 = table.get(cp);
        if (sub2 !== undefined) {
          if (!outStarted) {
            out = s.slice(0, i);
            outStarted = true;
          }
          out += sub2;
          count++;
          i += 2;
          continue;
        }
        if (outStarted) out += s.slice(i, i + 2);
        i += 2;
        continue;
      }
    }
    if (outStarted) out += s[i] as string;
    i++;
  }
  if (count === 0) return { text: s, count: 0 };
  return { text: out, count };
}
