import type { ResolvedNormalize } from '../config.js';
import { findAndDecode, rot13, shannonEntropy } from '../normalize/decode.js';
import { normalizeInput } from '../normalize/normalize.js';
import { clamp01, mkReason } from '../reason.js';
import type { Reason, ReasonCode } from '../types.js';
import { scanMarkers } from './l3.js';

export interface L2Output {
  reasons: Reason[];
  // Encoded blobs (base64/hex) whose decoded content re-scanned as injection → eligible for
  // model-copy neutralization. Each entry is the exact matched blob
  // text (case-preserved) so the caller can locate it in the model copy. Empty unless
  // neutralization-relevant blobs were found.
  maliciousBlobs?: { source: string; decoded: string }[];
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

// Detect a whitespace-split base64/hex blob: two ≥8 base64-alphabet runs ([A-Za-z0-9+/]) across
// whitespace, combined ≥20, where one run carries a base64 signature char (digit / + / / / a
// trailing '='). A pure-letter pair like "previous instructions" has no signature → false, so
// benign prose is rejected with a single early-exit linear scan (no backtracking regex). This
// is what trips the decode gate for the "SWdub3JlIGFs bCBydWxlcw==" attack without slowing the
// common path. Single O(n) pass, allocation-free.
function detectSplitB64(s: string): boolean {
  const n = s.length;
  let i = 0;
  while (i < n) {
    const c = s.charCodeAt(i);
    const isB64Char =
      (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 43 || c === 47;
    if (!isB64Char) {
      i++;
      continue;
    }
    // Start of a potential b64 run: measure it and whether it carries a signature char.
    const runStart = i;
    let sig = false;
    while (i < n) {
      const d = s.charCodeAt(i);
      if (
        (d >= 97 && d <= 122) ||
        (d >= 65 && d <= 90) ||
        (d >= 48 && d <= 57) ||
        d === 43 ||
        d === 47
      ) {
        if (d >= 48 && d <= 57) sig = true;
        i++;
      } else if (d === 61) {
        // '=' (padding) — a signature terminator; if the preceding run + a prior ≥8 run qualify,
        // flag split-b64 (covers a first run + this run terminated by padding).
        const runLen = i - runStart;
        if (runLen >= 8 && (sig || s.charCodeAt(runStart - 1) === 61)) {
          // Treat trailing '=' as the signature for this run for the pair check below.
          sig = true;
        }
        i++;
        break;
      } else {
        break;
      }
    }
    const runLen = i - runStart;
    if (runLen < 8) continue; // run too short to matter; resume scanning after it
    // We have a ≥8 b64 run. Walk the following whitespace, then look for a second ≥8 b64 run.
    let j = i;
    while (j < n) {
      const w = s.charCodeAt(j);
      if (w === 32 || w === 9 || w === 10 || w === 13) j++;
      else break;
    }
    if (j === i) continue; // no whitespace → not a split candidate; resume
    // Second run (≤255 chars scan; bounded so we terminate on pathological inputs).
    let k = j;
    let sig2 = false;
    let secondLen = 0;
    const cap = Math.min(j + 255, n);
    while (k < cap) {
      const e = s.charCodeAt(k);
      if (
        (e >= 97 && e <= 122) ||
        (e >= 65 && e <= 90) ||
        (e >= 48 && e <= 57) ||
        e === 43 ||
        e === 47
      ) {
        if (e >= 48 && e <= 57) sig2 = true;
        secondLen++;
        k++;
      } else if (e === 61) {
        sig2 = true; // trailing padding
        break;
      } else {
        break;
      }
    }
    if (secondLen >= 8 && runLen + secondLen >= 20 && (sig || sig2)) return true;
    // Continue scanning after the first run for further candidates.
    i = j;
  }
  return false;
}

interface RescanSummary {
  count: number;
  codes: Set<ReasonCode>;
}

// Decode-rescan routing gate: high entropy OR an encoded signature (base64/hex run,
// URL %xx, HTML entity, JS \u/\x and C-style \NNN octal escapes). Benign prose fails both
// and skips the rescan entirely. The escape signatures are matched lazily and never without a
// leading backslash, so prose keeps paying nothing extra here.
const LOOKS_ENCODED =
  /(%[0-9a-fA-F]{2}|&#[x]?[0-9a-fA-F]+;|[A-Za-z0-9+/]{20,}|[0-9a-fA-F]{20,}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}|\\x[0-9a-fA-F]{2}|\\[0-3][0-7]{0,2}|\\[4-7][0-7]?)/i;
// Cheap "any base64 signature char" pre-check: a whitespace-split base64/hex blob must carry a
// digit / + / / / =. Used to skip the O(n) detectSplitB64 scan for prose with no such chars at
// all (one fast char-class search, no backtracking).
const B64_SIG_RE = /[0-9+/=]/;

// Escape regex metacharacters in a literal token string so it can be embedded in an
// alternation. Control tokens contain `<`, `|`, `[`, `]`, `/` etc. which are all special.
function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Build (and cache) a case-insensitive alternation regex from the configured special-token
// vocabulary. The matching copy is already casefolded, so tokens are lowercased too; matching
// is still done case-insensitively to be robust to caller-provided mixed-case tokens. Returns
// undefined when the vocabulary is empty or every entry is empty/non-matching.
let cachedSpecialRe: { tokens: readonly string[]; re: RegExp } | undefined;
function specialTokenRe(tokens: readonly string[]): RegExp | undefined {
  if (tokens.length === 0) return undefined;
  if (cachedSpecialRe && cachedSpecialRe.tokens === tokens) return cachedSpecialRe.re;
  const parts: string[] = [];
  for (const t of tokens) {
    if (t.length === 0) continue;
    parts.push(escapeRe(t.toLowerCase()));
  }
  if (parts.length === 0) return undefined;
  const re = new RegExp(parts.join('|'), 'g');
  cachedSpecialRe = { tokens, re };
  return re;
}

// Scan the matching copy for tokenizer control/special tokens outside their legitimate
// channel (system prompt). Control tokens have essentially zero legitimate use in untrusted
// user data → special_token_injection. Not a hard-block (the model copy is untouched, R4);
// weight is moderate so it raises attacker cost without an FP-driven block on benign prose
// that happens to type `<|...|>`.
function scanSpecialTokens(matchingCopy: string, tokens: readonly string[]): Reason[] {
  if (matchingCopy.length === 0) return [];
  const re = specialTokenRe(tokens);
  if (!re) return [];
  // Cheap pre-check: every default + typical special token starts with '<' or '['. When the
  // input contains neither char AND every configured token starts with one of them, no token
  // can possibly match — skip the 20-branch alternation regex entirely. This keeps the
  // always-on Tier-0 path cheap for prose/base64/JSON inputs.
  if (!matchingCopy.includes('<') && !matchingCopy.includes('[')) {
    const allBracketed = tokens.every(
      (t) => t.length > 0 && (t.charCodeAt(0) === 60 || t.charCodeAt(0) === 91),
    );
    if (allBracketed) return [];
  }
  const reasons: Reason[] = [];
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  let count = 0;
  let firstSpan: [number, number] | undefined;
  while ((m = re.exec(matchingCopy)) !== null) {
    count++;
    if (!firstSpan) firstSpan = [m.index, m.index + m[0].length];
    if (m[0].length === 0) re.lastIndex++;
    if (count > 20) break;
  }
  if (count > 0) {
    const w = clamp01(Math.min(0.95, 0.6 + 0.1 * (count - 1)));
    reasons.push(
      mkReason(
        'special_token_injection',
        'structural',
        w,
        `tokenizer special/control token in untrusted input (n=${count})`,
        { span: firstSpan },
      ),
    );
  }
  return reasons;
}

// Common English letter trigrams (lowercase). Used as a tiny zero-dep frequency proxy to spot
// "token salad" — optimizer-generated (GCG) suffixes stitch word-fragments with punctuation,
// producing many letter trigrams that never occur in real English. KEPT SMALL on purpose: a
// coarse improbability signal, not a language model.
const COMMON_TRIGRAMS = new Set([
  'the',
  'and',
  'ing',
  'ion',
  'tio',
  'ent',
  'ati',
  'for',
  'her',
  'ter',
  'hat',
  'tha',
  'ere',
  'ain',
  'con',
  'nce',
  'edt',
  'hth',
  'dth',
  'ith',
  'sth',
  'out',
  'our',
  'not',
  'was',
  'had',
  'his',
  'hen',
  'han',
  'ave',
  'ter',
  'wit',
  'ver',
  'all',
  'ould',
  'unt',
  'res',
  'ive',
  'are',
  'eed',
  'red',
  'nce',
  'ble',
  'ght',
  'est',
  'ted',
  'ers',
  'pro',
  'com',
  'int',
  'rso',
  'uld',
]);

// Cheap GCG / token-salad signal. Zero-LM proxy: optimizer
// suffixes read as garbage to humans but flip models. The signal is calibrated against benign
// prose, code, base64, and hashes (see tests/l2.test.ts) and is deliberately conservative:
//
// A "salad run" is a whitespace-free run that is mostly letters, contains an embedded
// punctuation/symbol char (NOT a pure base64/hex blob), has no base64-length alnum subrun
// (maxAlnum < 20), and whose letter-trigrams are mostly NOT common English. GCG suffixes
// stitch several such word-fragment-with-punctuation tokens; a single one looks like a code
// identifier, so the signal requires >= 2 salad runs in the same input — this is what separates
// real token-salad from a normal `import { foo } from "bar"` line.
//
// Weight is LOW (escalation signal only — routes to Tier 1, never blocks on its own).
function scanAdversarialSuffix(matchingCopy: string): Reason[] {
  const n = matchingCopy.length;
  if (n < 24) return [];

  // Two-phase, allocation-free on the common path:
  //  Phase 1 — one cheap pass tracking whitespace-free runs and whether each has an embedded
  //            non-alnum char. NO trigram work here (that's the expensive part).
  //  Phase 2 — only for eligible runs (len >= 10 && has embedded punct), slice + run the
  //            trigram/maxAlnum analysis. Benign prose (short words) and pure base64/hex
  //            blobs (no embedded punct) never reach phase 2 → stays off the perf-critical path.
  let saladRuns = 0;
  let firstSaladSpan: [number, number] | undefined;

  let runStart = -1;
  let runLen = 0;
  let hasEmbeddedPunct = false;

  const analyzeRun = (start: number, len: number) => {
    const run = matchingCopy.slice(start, start + len);
    let letters = 0;
    let embeddedPunct = 0;
    let letterTri = 0;
    let odd = 0;
    let lr = '';
    let maxAlnum = 0;
    let cur = 0;
    for (let i = 0; i < len; i++) {
      const code = run.charCodeAt(i);
      const isAlpha = (code >= 97 && code <= 122) || (code >= 65 && code <= 90);
      const isAlnum = isAlpha || (code >= 48 && code <= 57);
      if (isAlpha) {
        letters++;
        lr += run.charAt(i).toLowerCase();
        if (lr.length > 3) lr = lr.slice(-3);
        if (lr.length === 3) {
          letterTri++;
          if (!COMMON_TRIGRAMS.has(lr)) odd++;
        }
      } else {
        lr = '';
      }
      if (isAlnum) {
        cur++;
        if (cur > maxAlnum) maxAlnum = cur;
      } else {
        cur = 0;
        if (i > 0 && i < len - 1) embeddedPunct++;
      }
    }
    if (embeddedPunct < 1) return;
    const letterRatio = letters / len;
    const oddR = letterTri > 3 ? odd / letterTri : 0;
    if (letterRatio >= 0.6 && maxAlnum < 20 && oddR >= 0.75) {
      saladRuns++;
      if (!firstSaladSpan) firstSaladSpan = [start, start + len];
    }
  };

  for (let i = 0; i <= n; i++) {
    const code = i === n ? 32 : matchingCopy.charCodeAt(i);
    const isSpace = code === 32 || code === 9 || code === 10 || code === 13;
    if (isSpace) {
      if (runStart >= 0) {
        // Phase 2 only for runs that could possibly be salad.
        if (runLen >= 10 && hasEmbeddedPunct) analyzeRun(runStart, runLen);
        runStart = -1;
        runLen = 0;
        hasEmbeddedPunct = false;
      }
      continue;
    }
    if (runStart < 0) runStart = i;
    runLen++;
    const isAlnum =
      (code >= 97 && code <= 122) || (code >= 65 && code <= 90) || (code >= 48 && code <= 57);
    if (!isAlnum && runLen > 1) hasEmbeddedPunct = true;
  }

  if (saladRuns < 3) return [];

  const w = clamp01(0.3 + 0.05 * Math.min(saladRuns - 3, 6));
  return [
    mkReason(
      'adversarial_suffix',
      'obfuscation',
      w,
      `possible GCG/token-salad suffix (salad runs=${saladRuns})`,
      { span: firstSaladSpan },
    ),
  ];
}
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

// L2 — stats/routing + decode-and-rescan.
// All outputs are score contributions + escalation signals, never standalone blocks.
// findAndDecode is cheap when no encoded patterns are present (a few regex tests). The decode
// rescan INCLUDING ROT13 is gated by an entropy / looks-encoded check (see the early return
// below) so benign prose skips it on the hot path. Pure ROT13-encoded text has normal entropy
// and no "looks-encoded" signature, so a pure-ROT13 attack slips the gate: that is out of
// Tier-0 scope (Tier 1 classifier territory — like multilingual/paraphrase attacks); the
// ROT13 scan is reached only when SOMETHING else (base64 run / %xx / HTML entity / high
// entropy) already tripped the gate. Do NOT advertise ROT13 as always-on at Tier 0.
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

  // Special/control-token detection: tokenizer control tokens in
  // untrusted input → special_token_injection. Scanned on the matching copy only; the model
  // copy is untouched. Runs before the entropy gate (it is not decode-routed).
  reasons.push(...scanSpecialTokens(matchingCopy, opts.specialTokens));

  // Cheap GCG / token-salad signal: low-weight escalation signal,
  // never blocks on its own. Opt-in (default off) so the zero-config Tier-0 hot path is
  // unchanged; enable via normalize.scanAdversarialSuffix.
  if (opts.scanAdversarialSuffix) reasons.push(...scanAdversarialSuffix(matchingCopy));

  // Mixed-script homoglyph signature is Latin and Cyrillic/Greek INTERLEAVED inside a single
  // run of letters with NO separator (e.g. "Рецеnзия", "pаypаl"), NOT a document that merely
  // contains separate Latin and Cyrillic words — legitimate bilingual text (a Russian review
  // quoting "HTC Desire", "admin\nэкскаватор", "ai-инфлюенсер") is not an attack. We therefore
  // accumulate maximal letter-only runs, breaking on ANY non-letter (whitespace, newline,
  // hyphen, punctuation, digit, CJK/Arabic), and flag only a run that internally interleaves
  // both scripts. (True homoglyph words are also already folded to Latin by L1 before this
  // point, so a stray-script residual here is far more likely benign than an attack — hence the
  // conservative intra-run threshold.) Deliberately NOT fired for Latin+CJK/Arabic (legit
  // bilingual) — protects R3 FPR.
  let mixedRuns = 0;
  let mixedLetters = 0;
  let runLatin = 0;
  let runCyrGreek = 0;
  const flushRun = () => {
    if (runLatin >= 2 && runCyrGreek >= 2) {
      mixedRuns++;
      mixedLetters += runLatin + runCyrGreek;
    }
    runLatin = 0;
    runCyrGreek = 0;
  };
  for (let i = 0; i < matchingCopy.length; i++) {
    const c = matchingCopy.charCodeAt(i);
    if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90)) runLatin++;
    else if (
      (c >= 0x0430 && c <= 0x044f) ||
      c === 0x0451 ||
      (c >= 0x0410 && c <= 0x042f) ||
      c === 0x0401 ||
      (c >= 0x03b1 && c <= 0x03c9) ||
      (c >= 0x0391 && c <= 0x03a9)
    )
      runCyrGreek++;
    else flushRun();
  }
  flushRun();
  if (mixedRuns >= 1) {
    const w = clamp01(0.3 + 0.03 * mixedLetters);
    reasons.push(
      mkReason(
        'script_mixing',
        'obfuscation',
        w,
        `Latin+Cyrillic/Greek interleaved within ${mixedRuns} word(s) (${mixedLetters} mixed letters)`,
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

  // L2: decode-and-rescan is routed by an entropy / looks-encoded gate so
  // benign prose (the >90% common path) skips it. base64/hex blobs raise entropy and
  // match the looks-encoded pattern; URL/HTML-entity payloads match their signatures.
  // ROT13-encoded text has normal entropy and no encoded signature, so a pure ROT13 attack
  // is out of Tier-0's reliable scope (Tier 1 classifier territory — like multilingual /
  // paraphrase attacks); the ROT13 scan below only runs when the gate was already tripped
  // by something else. See corpus outOfScope entries (e.g. atk-007). A whitespace-split
  // base64/hex blob with no other signature is caught here as a last-chance gate via a
  // single linear scan (no backtracking regex) so the hot path stays cheap.
  if (!opts.decodeEncoded) {
    return { reasons };
  }
  const looksEncoded = LOOKS_ENCODED.test(decodeCopy);
  if (entropy <= 4.8 && !looksEncoded) {
    // Last-chance gate: a whitespace-split base64/hex blob with no other encoded signature.
    // The B64_SIG_RE pre-check lets prose with no signature char escape without the scan.
    // (Morse is decoded earlier, in L1 normalizeInput, because its word boundaries are double
    // spaces that whitespace-collapse would destroy before this point.)
    const split = B64_SIG_RE.test(decodeCopy) && detectSplitB64(decodeCopy);
    if (!split) return { reasons };
  }

  let totalMarkers = 0;
  const allCodes = new Set<ReasonCode>();
  const maliciousBlobs: { source: string; decoded: string }[] = [];

  for (const cand of findAndDecode(decodeCopy)) {
    const sum = rescanOne(cand.decoded, opts, locale, opts.decodeDepth);
    totalMarkers += sum.count;
    for (const cd of sum.codes) allCodes.add(cd);
    // A discrete blob (base64/hex) whose decoded content contained injection markers is
    // eligible for model-copy neutralization. url/html have no discrete span (source === '').
    if (sum.count > 0 && cand.source.length > 0) {
      maliciousBlobs.push({ source: cand.source, decoded: cand.decoded });
    }
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

  if (maliciousBlobs.length > 0) return { reasons, maliciousBlobs };
  return { reasons };
}
