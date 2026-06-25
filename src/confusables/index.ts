// opensentry/confusables — optional, lazily-imported UTS-39 confusables table.
// Keeps the full table OUT of the edge core bundle.
//
// This is a curated subset of Unicode UTS-39 confusables.txt covering the entries
// most relevant to prompt-injection obfuscation (cross-script letter look-alikes
// that survive NFKC, plus a handful of symbol look-alikes). To upgrade to the full
// official table, regenerate from https://www.unicode.org/reports/tr39/ and replace
// the map; the fold algorithm in ../normalize/confusables.ts accepts any
// Map<number, string>.

import { COMPACT_CONFUSABLES, foldConfusables } from '../normalize/confusables.js';

export { foldConfusables } from '../normalize/confusables.js';

// Extended table: the compact core set plus additional curated UTS-39 entries.
export const CONFUSABLES_FULL: ReadonlyMap<number, string> = new Map<number, string>([
  ...COMPACT_CONFUSABLES,
  // Extra Cyrillic look-alikes
  [0x0501, 'd'], // ԁ
  [0x04cf, 'l'], // ӏ (small palochka)
  // Extra Latin-extension look-alikes
  [0x0261, 'g'], // ɡ
  [0x028b, 'v'], // ʋ
  // Symbol look-alikes not folded by NFKC
  [0x2018, "'"], // ‘
  [0x2019, "'"], // ’
  [0x201c, '"'], // “
  [0x201d, '"'], // ”
  [0x2215, '/'], // ∕ division slash
  [0x2216, '\\'], // ∖ set minus
  [0x2223, '|'], // ∣ divides
  [0x2502, '|'], // │ box drawings light vertical
  [0x223c, '~'], // ∼ tilde operator
  [0x02c8, "'"], // ʹ modifier letter prime
  [0x02b9, "'"], // ʹ modifier letter prime
  [0x02ee, '"'], // ˮ modifier letter double prime
]);

export function foldConfusablesFull(s: string): { text: string; count: number } {
  return foldConfusables(s, CONFUSABLES_FULL);
}
