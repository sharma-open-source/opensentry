import { isRtlLocale, type ResolvedNormalize } from '../config.js';
import { clamp01, densityWeight, mkReason } from '../reason.js';
import type { Reason } from '../types.js';
import { foldConfusables } from './confusables.js';
import { type BidiMode, cleanInvisibles, collapseWhitespace } from './unicode.js';

export interface NormalizeOutput {
  modelCopy: string; // sanitized source — pass downstream (minimal cleaning)
  matchingCopy: string; // folded + casefolded + whitespace-collapsed — for detectors
  decodeCopy: string; // folded + whitespace-collapsed, NOT casefolded — preserves base64 case
  reasons: Reason[];
}

// Quick pure-ASCII check: NFKC is the identity for ASCII, so we skip it entirely for the
// common case. Scans until the first non-ASCII code unit; branch-predicted to be nearly
// free on ASCII text.
function isPureAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) >= 0x80) return false;
  }
  return true;
}

// L1 — the load-bearing normalization layer.
// Produces two copies: an aggressively-folded MATCHING copy (scored by detectors) and a
// minimally-cleaned MODEL copy (passed downstream). Confusable folding NEVER touches the
// model copy (risk R4 — would corrupt legitimate CJK/Arabic/emoji).
export function normalizeInput(
  input: string,
  opts: ResolvedNormalize,
  locale: string | undefined,
): NormalizeOutput {
  const reasons: Reason[] = [];

  // (1) NFKC — skip for pure-ASCII (identity); catch-and-continue on malformed input.
  let base = input;
  if (opts.nfkc && !isPureAscii(input)) {
    try {
      base = input.normalize('NFKC');
    } catch {
      base = input;
    }
  }

  // Bidi mode: RTL locale → 'isolate' (keep isolates, strip legacy override); else configured.
  const bidiMode: BidiMode =
    opts.handleBidi === 'off'
      ? 'off'
      : isRtlLocale(locale, opts.rtlLocales)
        ? 'isolate'
        : opts.handleBidi;

  // (2)(3)(4) strip + count invisible / variation selectors / C0-C1 / Tag block / bidi
  const { text: cleaned, counts } = cleanInvisibles(base, bidiMode);

  // MODEL copy: minimal cleaning only (no fold, no casefold, no whitespace collapse).
  const modelCopy = cleaned;

  // (5) UTS-39 confusable skeleton fold — MATCHING copy only.
  let foldCount = 0;
  let folded = cleaned;
  if (opts.foldConfusables) {
    const fold = foldConfusables(cleaned);
    folded = fold.text;
    foldCount = fold.count;
  }

  // (6) whitespace/exotic-space collapse + casefold — MATCHING copy only.
  // `decodeCopy` keeps original case so base64 (case-sensitive) survives for L2 decode.
  const decodeCopy = collapseWhitespace(folded);
  const matchingCopy = decodeCopy.toLowerCase();

  // ---- Build obfuscation reasons from counts ----
  const len = base.length || 1;

  if (counts.tag > 0) {
    reasons.push(
      mkReason(
        'unicode_tag_smuggling',
        'obfuscation',
        1.0,
        `Unicode Tag block chars (U+E0000–E007F): ${counts.tag}`,
        {
          hardBlock: true,
        },
      ),
    );
  }

  const bidiTotal = counts.bidiEmbed + counts.bidiOverride;
  if (bidiTotal > 0) {
    const w = counts.bidiOverride > 0 ? 0.7 : 0.5;
    const detail =
      counts.bidiOverride > 0
        ? `bidi override controls (LRO/RLO): ${counts.bidiOverride}`
        : `bidi embedding controls (LRE/RLE/PDF): ${counts.bidiEmbed}`;
    reasons.push(mkReason('bidi_override', 'obfuscation', w, detail));
  }

  if (counts.zeroWidth > 0) {
    const w = clamp01(0.25 + 0.04 * counts.zeroWidth);
    reasons.push(
      mkReason(
        'zero_width_chars',
        'obfuscation',
        w,
        `zero-width/invisible chars stripped: ${counts.zeroWidth}`,
      ),
    );
  }

  const invisibleTotal =
    counts.zeroWidth + counts.variationSelector + counts.control + counts.tag + bidiTotal;
  if (invisibleTotal > 0) {
    const density = invisibleTotal / len;
    if (density > 0.02) {
      const w = densityWeight(0.0, density, 2.2, 0.7);
      reasons.push(
        mkReason(
          'invisible_density',
          'obfuscation',
          w,
          `invisible/control char density: ${(density * 100).toFixed(1)}%`,
        ),
      );
    }
  }

  if (foldCount > 0) {
    const w = clamp01(0.2 + 0.06 * foldCount);
    reasons.push(
      mkReason(
        'confusable_run',
        'obfuscation',
        w,
        `confusable look-alike chars folded: ${foldCount}`,
      ),
    );
  }

  return { modelCopy, matchingCopy, decodeCopy, reasons };
}
