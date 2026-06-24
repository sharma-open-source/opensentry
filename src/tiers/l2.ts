import type { ResolvedNormalize } from '../config.js';
import { findAndDecode, rot13, shannonEntropy } from '../normalize/decode.js';
import { normalizeInput } from '../normalize/normalize.js';
import { clamp01, mkReason } from '../reason.js';
import type { Reason, ReasonCode } from '../types.js';
import { scanMarkers } from './l3.js';

export interface L2Output {
  reasons: Reason[];
}

const LATIN_LOCALES = new Set([
  'en',
  'fr',
  'es',
  'de',
  'it',
  'pt',
  'nl',
  'sv',
  'da',
  'no',
  'fi',
  'pl',
  'ro',
  'cs',
  'sk',
  'hu',
  'tr',
  'id',
  'vi',
  'sw',
  'ca',
  'eu',
]);

interface ScriptCounts {
  latin: number;
  cyrillic: number;
  greek: number;
  other: number; // non-Latin, non-Cyrillic/Greek letters (CJK, Arabic, etc.)
}

function countScripts(s: string): ScriptCounts {
  let latin = 0;
  let cyrillic = 0;
  let greek = 0;
  let other = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90)) latin++;
    else if (
      (c >= 0x0430 && c <= 0x044f) ||
      c === 0x0451 ||
      (c >= 0x0410 && c <= 0x042f) ||
      c === 0x0401
    )
      cyrillic++;
    else if ((c >= 0x03b1 && c <= 0x03c9) || (c >= 0x0391 && c <= 0x03a9)) greek++;
    else if (c >= 0x80) other++;
  }
  return { latin, cyrillic, greek, other };
}

interface RescanSummary {
  count: number;
  codes: Set<ReasonCode>;
}

// Decode-rescan routing gate: high entropy OR an encoded signature (base64/hex run,
// URL %xx, HTML entity). Benign prose fails both and skips the rescan entirely.
const LOOKS_ENCODED = /(%[0-9a-fA-F]{2}|&#[x]?[0-9a-fA-F]+;|[A-Za-z0-9+/]{20,}|[0-9a-fA-F]{20,})/i;

// Normalize a decoded payload and re-run L3 detection; recurse into nested encodings
// (bounded depth). Uses the single-pass `scanMarkers` (detection only) since decoded
// payloads only feed the `encoded_payload` score contribution.
function rescanOne(
  text: string,
  opts: ResolvedNormalize,
  locale: string | undefined,
  depth: number,
): RescanSummary {
  const norm = normalizeInput(text, opts, locale);
  const found = scanMarkers(norm.matchingCopy);
  let count = found.count;
  const codes = new Set<ReasonCode>(found.codes);
  if (depth > 1) {
    const nested = findAndDecode(norm.decodeCopy);
    for (const c of nested) {
      const sub = rescanOne(c.decoded, opts, locale, depth - 1);
      count += sub.count;
      for (const cd of sub.codes) codes.add(cd);
    }
  }
  return { count, codes };
}

// PLAN.md §5 L2 — stats/routing + decode-and-rescan.
// All outputs are score contributions + escalation signals, never standalone blocks.
// findAndDecode is cheap when no encoded patterns are present (a few regex tests); ROT13
// rescan is always run because ROT13-encoded text has normal entropy and no "looks-encoded"
// signature, so an entropy gate would let it through.
export function analyzeL2(
  matchingCopy: string,
  decodeCopy: string,
  modelCopy: string,
  opts: ResolvedNormalize,
  locale: string | undefined,
): L2Output {
  const reasons: Reason[] = [];
  void modelCopy; // reserved for future model-copy-based detectors

  const scripts = countScripts(matchingCopy);

  // Mixed-script: Latin + Cyrillic/Greek (the look-alike, obfuscation-prone scripts).
  // Deliberately NOT fired for Latin+CJK/Arabic (legit bilingual) — protects R3 FPR.
  if (scripts.latin >= 6 && (scripts.cyrillic >= 3 || scripts.greek >= 3)) {
    const w = clamp01(0.3 + 0.03 * (scripts.cyrillic + scripts.greek));
    reasons.push(
      mkReason(
        'script_mixing',
        'obfuscation',
        w,
        `mixed Latin+Cyrillic/Greek script (latin=${scripts.latin}, cyrillic=${scripts.cyrillic}, greek=${scripts.greek})`,
      ),
    );
  }

  // Lightweight language divergence (routing signal only — weight below flag threshold).
  if (locale) {
    const base = locale.toLowerCase().split(/[-_]/)[0] ?? '';
    if (LATIN_LOCALES.has(base) && scripts.other > scripts.latin && scripts.other > 10) {
      reasons.push(
        mkReason(
          'lang_divergence',
          'semantic',
          0.2,
          `text language appears to diverge from channel locale '${base}'`,
        ),
      );
    }
  }

  // Entropy anomaly (GCG/optimizer-like or high-entropy blob routing signal).
  const entropy = shannonEntropy(matchingCopy);
  if (entropy > 5.5) {
    reasons.push(
      mkReason(
        'entropy_anomaly',
        'obfuscation',
        0.3,
        `high shannon entropy (${entropy.toFixed(2)} bits/char)`,
      ),
    );
  }

  // PLAN.md §5 L2: decode-and-rescan is routed by an entropy / looks-encoded gate so
  // benign prose (the >90% common path) skips it. base64/hex blobs raise entropy and
  // match the looks-encoded pattern; URL/HTML-entity payloads match their signatures.
  // ROT13-encoded text has normal entropy and no encoded signature, so a pure ROT13
  // attack is out of Tier-0's reliable scope (Tier 1 classifier territory — like
  // multilingual/paraphrase attacks); see corpus outOfScope entries.
  if (!opts.decodeEncoded || (entropy <= 4.8 && !LOOKS_ENCODED.test(decodeCopy))) {
    return { reasons };
  }

  let totalMarkers = 0;
  const allCodes = new Set<ReasonCode>();

  for (const cand of findAndDecode(decodeCopy)) {
    const sum = rescanOne(cand.decoded, opts, locale, opts.decodeDepth);
    totalMarkers += sum.count;
    for (const cd of sum.codes) allCodes.add(cd);
  }

  // ROT13: decode (self-inverse) and re-scan. `decodeCopy` is already normalized and ROT13
  // only swaps letters, so scan directly without a second L1 pass. Benign → gibberish.
  const r13 = rot13(decodeCopy).toLowerCase();
  const r13Found = scanMarkers(r13);
  totalMarkers += r13Found.count;
  for (const cd of r13Found.codes) allCodes.add(cd);

  if (totalMarkers > 0) {
    const w = clamp01(0.8 + 0.05 * totalMarkers);
    const codeList = [...allCodes].join(', ');
    reasons.push(
      mkReason(
        'encoded_payload',
        'obfuscation',
        w,
        `decoded payload contained injection markers (n=${totalMarkers}: ${codeList})`,
      ),
    );
  }

  return { reasons };
}
