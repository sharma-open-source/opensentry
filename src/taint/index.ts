// opensentry/taint — provenance tracking for indirect-injection defense.
// JS has no true taint propagation, so this ships an explicit provenance-passing
// API: callers mark spans of untrusted-origin text (retrieved/tool/web/email) and later ask
// whether a candidate string (e.g. a tool-call's args) contains any tainted span.
//
// This is deliberately HONEST about being a heuristic, not magic: it does not follow data
// flow through arbitrary transforms. It catches the common indirect-injection pattern where
// untrusted content is concatenated/copy-pasted into a privileged action verbatim or
// near-verbatim. Pair with guard.checkToolCall(..., { tracker }) to fail closed on
// tainted data reaching a high-risk tool.
//
// Edge-safe: zero Node builtins — pure string matching.

import type { Source } from '../types.js';

export interface TaintMark {
  text: string; // the exact untrusted-origin span registered via mark()
  source: Source;
  ts: number;
}

export interface TaintMatch {
  tainted: boolean;
  sources: Source[];
  marks: TaintMark[];
}

export interface TaintTracker {
  // Register a span of untrusted-origin text. Returns the same text (passthrough) so it can
  // be used inline: `const x = tracker.mark(retrievedDoc, 'retrieved')`.
  mark(text: string, source: Source): string;
  // Best-effort: does `text` contain any registered tainted span? Substring lookup.
  containsTainted(text: string): TaintMatch;
  // Best-effort origin lookup for a substring.
  originOf(text: string): Source | undefined;
  // All registered marks (for audit / serialization).
  marks(): readonly TaintMark[];
  clear(): void;
}

export function createTaintTracker(): TaintTracker {
  const registry: TaintMark[] = [];

  // Track the minimum mark length so containsTainted can skip a full scan when every mark is
  // longer than the candidate (a common, cheap short-circuit).
  let minLen = Infinity;

  function mark(text: string, source: Source): string {
    if (text.length === 0) return text;
    registry.push({ text, source, ts: Date.now() });
    if (text.length < minLen) minLen = text.length;
    return text;
  }

  function containsTainted(text: string): TaintMatch {
    if (registry.length === 0 || text.length === 0) {
      return { tainted: false, sources: [], marks: [] };
    }
    // Short-circuit: if the candidate is shorter than every registered mark, nothing can match.
    if (text.length < minLen) {
      return { tainted: false, sources: [], marks: [] };
    }
    const hits: TaintMark[] = [];
    const sources = new Set<Source>();
    for (const m of registry) {
      if (text.length >= m.text.length && text.includes(m.text)) {
        hits.push(m);
        sources.add(m.source);
      }
    }
    return { tainted: hits.length > 0, sources: [...sources], marks: hits };
  }

  function originOf(text: string): Source | undefined {
    if (text.length === 0) return undefined;
    for (let i = registry.length - 1; i >= 0; i--) {
      const m = registry[i]!;
      if (text.length >= m.text.length && text.includes(m.text)) return m.source;
    }
    return undefined;
  }

  return {
    mark,
    containsTainted,
    originOf,
    marks: () => registry,
    clear: () => {
      registry.length = 0;
      minLen = Infinity;
    },
  };
}
