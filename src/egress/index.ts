// opensentry/egress — outbound exfiltration filter.
// Scans model output / tool-call results for:
//   - disallowed URLs (markdown-image exfil lures, bare URLs) against a caller allowlist,
//   - leaked secrets (known key shapes + high-entropy token runs) → secret_egress,
//   - PII (email/phone/card/SSN, or caller patterns) → pii_egress.
//
// FP discipline: output-side, so secret/PII default to FLAG-not-block (blocking a
// response is costly). URL exfil stays hard-block. `scanPii` defaults OFF (locale-sensitive).
// Zero Node builtins — pure string + regex + the shared Shannon-entropy helper.

import { shannonEntropy } from '../normalize/decode.js';
import type { Reason, Verdict } from '../types.js';

export interface EgressPolicy {
  allowlist: (string | RegExp)[];
  stripDisallowed?: boolean;
  // Secret-leak scanning: known key formats (AWS/GitHub/OpenAI/JWT) + high-entropy token runs.
  scanSecrets?: boolean;
  // Allowlist for known-safe tokens (string startsWith or RegExp test). Matched secrets are
  // not flagged — e.g. a public/example key your app legitimately emits.
  secretAllowlist?: (string | RegExp)[];
  // PII scanning. `true` → built-in email/phone/card/SSN patterns; or supply your own RegExp[].
  // Defaults off (locale/format-sensitive).
  scanPii?: boolean | RegExp[];
}

export interface EgressResult {
  safe: string;
  verdict: Verdict;
  reasons: Reason[];
}

// Matches markdown images ![alt](url) and bare http/https/ftp URLs.
// Alt excludes '[' and the image URL excludes '(' so a partial "![..." / "![](..."
// start that never completes fails in O(1) instead of re-scanning to the end of the
// input, which would make matching quadratic on adversarial egress text (ReDoS).
const URL_RE = /!\[([^\]\[]*)\]\(\s*([^)\s(]+)(?:\s+"[^"]*")?\)|(?:https?|ftp):\/\/[^\s)<>"']+/g;

function urlAllowed(url: string, allowlist: (string | RegExp)[]): boolean {
  return allowlist.some((entry) => {
    if (typeof entry === 'string') return url.startsWith(entry);
    return entry.test(url);
  });
}

function tokenAllowed(token: string, allowlist: (string | RegExp)[] | undefined): boolean {
  if (!allowlist || allowlist.length === 0) return false;
  return allowlist.some((entry) => {
    if (typeof entry === 'string') return token.startsWith(entry);
    return entry.test(token);
  });
}

// ---- Secret detectors ----
// Known key formats. Each is high-confidence (format is purpose-specific, not accidental).
const SECRET_RES: { code: 'secret_egress'; re: RegExp; label: string }[] = [
  // OpenAI API keys: sk-... (sk-proj-..., sk-...)
  { code: 'secret_egress', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, label: 'OpenAI API key' },
  // GitHub tokens: ghp_ / gho_ / ghs_ / ghr_ / github_pat_ ...
  {
    code: 'secret_egress',
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
    label: 'GitHub token',
  },
  // AWS access key id: AKIA + 16 alnum
  { code: 'secret_egress', re: /\bAKIA[0-9A-Z]{16}\b/g, label: 'AWS access key id' },
  // JWT: three base64url segments separated by dots (header.payload.signature)
  {
    code: 'secret_egress',
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    label: 'JWT',
  },
  // Slack: xox[bpoa]-...
  { code: 'secret_egress', re: /\bxox[bpoa]-[A-Za-z0-9-]{10,}\b/g, label: 'Slack token' },
  // Google API key: AIza + 35 base64-std chars
  { code: 'secret_egress', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, label: 'Google API key' },
];

// Generic high-entropy token run: a long alnum run with high Shannon entropy (an opaque
// secret/key leaked into prose). Tuned conservatively to avoid flagging base64 image data
// (which is usually inside a data URI / fenced block) — requires a long standalone run.
const HIGH_ENTROPY_RUN_RE = /\b[A-Za-z0-9+/=_-]{40,}\b/g;

function scanSecrets(text: string, policy: EgressPolicy): Reason[] {
  if (!policy.scanSecrets) return [];
  const reasons: Reason[] = [];
  const seen = new Set<string>();

  for (const spec of SECRET_RES) {
    spec.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = spec.re.exec(text)) !== null) {
      const tok = m[0];
      if (tok && !tokenAllowed(tok, policy.secretAllowlist) && !seen.has(tok)) {
        seen.add(tok);
        reasons.push({
          code: 'secret_egress',
          category: 'exfil',
          weight: 0.8,
          message: `possible leaked ${spec.label} in egress`,
          span: [m.index, m.index + tok.length],
        });
      }
      if (tok && tok.length === 0) spec.re.lastIndex++;
    }
  }

  // High-entropy run signal (catches unstructured secrets not matching a known format).
  HIGH_ENTROPY_RUN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = HIGH_ENTROPY_RUN_RE.exec(text)) !== null) {
    const run = m[0];
    if (!run) continue;
    if (tokenAllowed(run, policy.secretAllowlist) || seen.has(run)) {
      if (run.length === 0) HIGH_ENTROPY_RUN_RE.lastIndex++;
      continue;
    }
    const ent = shannonEntropy(run);
    if (ent >= 4.5) {
      seen.add(run);
      reasons.push({
        code: 'secret_egress',
        category: 'exfil',
        weight: 0.6,
        message: `possible leaked high-entropy token in egress (entropy=${ent.toFixed(2)} bits/char, len=${run.length})`,
        span: [m.index, m.index + run.length],
      });
    }
    if (run.length === 0) HIGH_ENTROPY_RUN_RE.lastIndex++;
  }

  return reasons;
}

// ---- PII detectors ----
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
// International phone: optional leading +, 7-15 digits, allowing separators.
const PHONE_RE = /(?:\+?\d[\d\s().-]{6,}\d)/g;
// SSN: 000-00-0000 (not 000 in area, not 0000 in serial — loose, flag-not-block).
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
// Credit card: 13-16 digits, optionally grouped by spaces/dashes. Luhn-validated to cut FP.
const CARD_RE = /\b(?:\d[ -]?){13,16}\b/g;

function luhnValid(s: string): boolean {
  const digits = s.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 16) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

function scanPii(text: string, policy: EgressPolicy): Reason[] {
  const mode = policy.scanPii;
  if (!mode) return [];
  const reasons: Reason[] = [];

  if (mode === true) {
    EMAIL_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = EMAIL_RE.exec(text)) !== null) {
      const tok = m[0];
      if (tok) {
        reasons.push({
          code: 'pii_egress',
          category: 'exfil',
          weight: 0.5,
          message: `possible PII (email) in egress: ${tok}`,
          span: [m.index, m.index + tok.length],
        });
      }
      if (tok && tok.length === 0) EMAIL_RE.lastIndex++;
    }

    SSN_RE.lastIndex = 0;
    while ((m = SSN_RE.exec(text)) !== null) {
      const tok = m[0];
      if (tok) {
        reasons.push({
          code: 'pii_egress',
          category: 'exfil',
          weight: 0.7,
          message: `possible PII (SSN) in egress`,
          span: [m.index, m.index + tok.length],
        });
      }
      if (tok && tok.length === 0) SSN_RE.lastIndex++;
    }

    // Card-shaped spans (13-16 digits) are excluded from the phone scan below, whether or
    // not they pass Luhn — a Luhn-failed run is still a card-shaped number (e.g. truncated/
    // redacted), not a phone number, and shouldn't be downgraded to the lower-weight signal.
    const cardSpans: [number, number][] = [];
    CARD_RE.lastIndex = 0;
    while ((m = CARD_RE.exec(text)) !== null) {
      const tok = m[0];
      if (!tok) continue;
      cardSpans.push([m.index, m.index + tok.length]);
      if (luhnValid(tok)) {
        reasons.push({
          code: 'pii_egress',
          category: 'exfil',
          weight: 0.8,
          message: `possible PII (credit card) in egress`,
          span: [m.index, m.index + tok.length],
        });
      }
      if (tok.length === 0) CARD_RE.lastIndex++;
    }

    // Phone: flag long digit-runs with a + or separators (loose; flag-not-block by design).
    PHONE_RE.lastIndex = 0;
    while ((m = PHONE_RE.exec(text)) !== null) {
      const tok = m[0];
      if (!tok) continue;
      const digits = tok.replace(/\D/g, '');
      const start = m.index;
      const end = m.index + tok.length;
      const overlapsCard = cardSpans.some(([cs, ce]) => start < ce && end > cs);
      if (digits.length >= 10 && digits.length <= 15 && !overlapsCard) {
        reasons.push({
          code: 'pii_egress',
          category: 'exfil',
          weight: 0.4,
          message: `possible PII (phone number) in egress`,
          span: [start, end],
        });
      }
      if (tok.length === 0) PHONE_RE.lastIndex++;
    }
  } else if (Array.isArray(mode)) {
    // Caller-supplied patterns.
    for (const re of mode) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const tok = m[0];
        if (tok) {
          reasons.push({
            code: 'pii_egress',
            category: 'exfil',
            weight: 0.6,
            message: `possible PII (custom pattern) in egress`,
            span: [m.index, m.index + tok.length],
          });
        }
        if (tok && tok.length === 0) re.lastIndex++;
      }
    }
  }

  return reasons;
}

export function egressFilter(text: string, policy: EgressPolicy): EgressResult {
  const reasons: Reason[] = [];
  const disallowed: { start: number; end: number; url: string; isImage: boolean }[] = [];

  URL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = URL_RE.exec(text)) !== null) {
    const isImage = m[0].startsWith('![');
    const url = isImage ? (m[2] ?? '') : m[0];
    if (!urlAllowed(url, policy.allowlist)) {
      disallowed.push({
        start: m.index,
        end: m.index + m[0].length,
        url,
        isImage,
      });
      reasons.push({
        code: 'exfil_markdown_image',
        category: 'exfil',
        weight: 1,
        message: isImage
          ? `Disallowed markdown image URL: ${url}`
          : `Disallowed egress URL: ${url}`,
        hardBlock: true,
      });
    }
  }

  // Secret / PII scanning. Flag-weighted, not hard-block.
  reasons.push(...scanSecrets(text, policy));
  reasons.push(...scanPii(text, policy));

  let safe = text;
  if (disallowed.length > 0 && policy.stripDisallowed) {
    for (let i = disallowed.length - 1; i >= 0; i--) {
      const d = disallowed[i];
      if (d) safe = safe.slice(0, d.start) + safe.slice(d.end);
    }
  }

  const hardBlock = reasons.some((r) => r.hardBlock === true);
  const verdict: Verdict = reasons.length === 0 ? 'allow' : hardBlock ? 'block' : 'flag';

  return {
    safe,
    verdict,
    reasons,
  };
}
