import type { ResolvedNormalize } from '../config.js';
import { truncateToBytes } from '../normalize/unicode.js';
import { clamp01, mkReason } from '../reason.js';
import type { Reason } from '../types.js';

export interface L0Output {
  text: string;
  truncated: boolean;
  reasons: Reason[];
}

// L0 — front gate. Pure arithmetic over raw chars; no hot-path allocation.
// Bounds downstream work (maxScanBytes truncate-with-flag) + crude flooding signals.
// Never blocks alone (resource reasons carry low weight, not in hard-block set).
export function frontGate(input: string, opts: ResolvedNormalize): L0Output {
  const reasons: Reason[] = [];
  const { text, truncated } = truncateToBytes(input, opts.maxScanBytes);

  if (truncated) {
    reasons.push(
      mkReason(
        'length_cap',
        'resource',
        0.3,
        `input exceeded maxScanBytes (${opts.maxScanBytes}); truncated`,
      ),
    );
  }

  // Repeated-character run flooding (context-window flooding / distraction, OWASP LLM10-ish)
  if (text.length > 400) {
    let run = 1;
    let maxRun = 1;
    for (let i = 1; i < text.length; i++) {
      if (text[i] === text[i - 1]) {
        run++;
        if (run > maxRun) maxRun = run;
      } else {
        run = 1;
      }
    }
    if (maxRun > 200) {
      const w = clamp01(0.2 + Math.min(0.2, (maxRun - 200) / 2000));
      reasons.push(
        mkReason(
          'length_cap',
          'resource',
          w,
          `repeated-character run of length ${maxRun} (possible flooding)`,
        ),
      );
    }
  }

  return { text, truncated, reasons };
}
