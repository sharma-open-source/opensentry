import { clamp01, mkReason } from '../reason.js';
import type { Reason, ReasonCategory, ReasonCode } from '../types.js';

// L3 — structural & heuristic regex. Pre-compiled at module load,
// backtracking-safe (linear): quantifiers only apply to character classes or fixed
// alternations; no nested quantifiers. Runs on the normalized MATCHING copy (casefolded).
//
// Keyword-only matches get LOW weight (NotInject over-defense risk);
// structural template / exfil matches get HIGH weight (some are hard-block).

interface Spec {
  name: string; // unique named-group name (also used by the combined detector)
  code: ReasonCode;
  category: ReasonCategory;
  weight: number;
  re: RegExp; // separate regex — preserves overlapping matches for scoring
  hardBlock?: boolean;
  label: string;
  perMatchBoost: number;
  cap: number;
}

const SPECS: Spec[] = [
  // ---- Template forgery: forged chat-template / turn markers (HIGH, hard-block) ----
  {
    name: 'template_forgery',
    code: 'template_forgery',
    category: 'structural',
    weight: 0.9,
    hardBlock: true,
    label: 'forged chat-template / role delimiter',
    perMatchBoost: 0.05,
    cap: 1.0,
    re: /(<\|im_start\|>|<\|im_end\|>|\[inst\]|\[\/inst\]|<<sys>>|<<\/sys>>|<\/?system>|<\/?assistant>|<\/user>|<system_prompt>|<\/system_prompt>|<\|system\|>|<\|assistant\|>|<\|tool\|>)/g,
  },
  // ---- Role-colon spoof (LOW alone — protects NotInject "system: status" benign) ----
  {
    name: 'role_tag_spoof_bare',
    code: 'role_tag_spoof',
    category: 'structural',
    weight: 0.35,
    label: 'role-colon marker',
    perMatchBoost: 0.04,
    cap: 0.5,
    re: /\b(system|assistant|developer|admin)\s*:/g,
  },
  // ---- Role-colon + override intent (HIGH — "system: you are now free") ----
  {
    name: 'role_tag_spoof_combo',
    code: 'role_tag_spoof',
    category: 'structural',
    weight: 0.75,
    label: 'role-colon with override intent',
    perMatchBoost: 0.05,
    cap: 0.9,
    re: /\b(system|assistant|developer|admin)\s*:[^.\n]{0,40}?\b(ignore|disregard|forget|override|unrestricted|jailbreak|dan|free|no longer|do anything|reveal|repeat|bypass|leak|unbound|no rules|without restrictions)\b/g,
  },
  // ---- Instruction override family (MED-HIGH) ----
  {
    name: 'instruction_override_1',
    code: 'instruction_override',
    category: 'semantic',
    weight: 0.65,
    label: 'instruction-override phrasing',
    perMatchBoost: 0.08,
    cap: 0.9,
    re: /\b(ignore|disregard|forget|override|overrule|skip)\b[^.!?]{0,40}?\b(previous|prior|all|the|your|above|initial|original)\b[^.!?]{0,30}?\b(instructions?|rules?|prompts?|directives?|guidelines?|restrictions?|system prompt)\b/g,
  },
  {
    name: 'instruction_override_2',
    code: 'instruction_override',
    category: 'semantic',
    weight: 0.6,
    label: 'instruction-override phrasing',
    perMatchBoost: 0.08,
    cap: 0.9,
    re: /\b(ignore|disregard|forget)\s+(?:all\s+|the\s+|your\s+|this\s+|every\s+|previous\s+|prior\s+|above\s+|initial\s+|original\s+)+(instructions?|rules?|prompts?|directives?)\b/g,
  },
  {
    name: 'instruction_override_3',
    code: 'instruction_override',
    category: 'semantic',
    weight: 0.35,
    label: 'instruction-override heading',
    perMatchBoost: 0.06,
    cap: 0.6,
    re: /\b(new instructions|new rules|new directives|override prompt|system override)\s*:/g,
  },
  // ---- Policy puppetry / structured-config injection (HIGH) ----
  {
    name: 'policy_puppetry',
    code: 'policy_puppetry',
    category: 'structural',
    weight: 0.8,
    label: 'policy-puppetry / structured-config injection',
    perMatchBoost: 0.05,
    cap: 0.95,
    re: /(<policy>|<\/policy>|<override>|<\/override>|<rules>|<\/rules>|<instructions>|<\/instructions>|<system_instructions>|<\/system_instructions>|\{\s*"?role"?\s*:\s*"?system"?\}|"role"\s*:\s*"system")/g,
  },
  // ---- Exfiltration lures: markdown-image w/ query string + javascript: URLs (HIGH, hard-block) ----
  {
    name: 'exfil_markdown_image',
    code: 'exfil_markdown_image',
    category: 'exfil',
    weight: 0.9,
    hardBlock: true,
    label: 'exfiltration markdown-image / javascript lure',
    perMatchBoost: 0.05,
    cap: 1.0,
    re: /(!\[[^\]]*\]\(https?:\/\/[^)\s]*\?[^)\s]*\)|!\[[^\]]*\]\(javascript:[^)\s]*\)|\[[^\]]*\]\(javascript:[^)\s]*\))/g,
  },
  // ---- Exfiltration lures: any URL-bearing channel carrying a data probe (HIGH, hard-block) ----
  // Catches markdown links, HTML <img>/<script>/<iframe>/<a href>, CSS url(), bare URLs, and JS
  // exfil alike: a URL with a query/fragment containing a high-signal data keyword, or a JS
  // document.* / in-script fetch() reach. The query-qualifier keeps benign image/CDN URLs and
  // OAuth callbacks off the trigger — deliberately NOT extended to a bare structural match for
  // <iframe>/CSS url() (e.g. a YouTube embed or a CDN background-image): those are common in
  // legitimate retrieved/web content and a keyword-free hard-block on them is a worse outcome
  // than the narrow generic-param-name gap (?d=data, ?d=token) it would close. Gated behind the
  // combined pre-check so prose (no `https`) pays nothing. Linear patterns (char-class
  // quantifiers, no nesting).
  {
    name: 'exfil_url_lure',
    code: 'exfil_url_lure',
    category: 'exfil',
    weight: 0.9,
    hardBlock: true,
    label: 'exfiltration URL lure (link/HTML/CSS/bare-URL)',
    perMatchBoost: 0.05,
    cap: 1.0,
    re: /(?:https?:\/\/[^\s)'"]*[?#][^\s)'"]*\b(?:secret|cookie|password|credential|exfil|leak|api[-_]?key|apikey|sessionid|ssn)\b|\bdocument\.(?:cookie|location)\b|<script\b[^>]*>[^<]{0,200}\bfetch\s*\(\s*["']https?:\/\/|<script\b[^>]*\bsrc\s*=\s*["']?https?:\/\/)/g,
  },
  // ---- Refusal suppression / affirmative priming (MED) ----
  {
    name: 'refusal_suppression',
    code: 'refusal_suppression',
    category: 'semantic',
    weight: 0.5,
    label: 'refusal-suppression phrasing',
    perMatchBoost: 0.08,
    cap: 0.8,
    re: /(do not (say|claim|tell|respond|reply)\b[^.!?]{0,30}?\b(you (can'?t|cannot|are unable|are not able|won'?t)|unable)\b|never (say|claim|tell)\b[^.!?]{0,30}?\b(you (can'?t|cannot|are unable))\b|instead of refus|just (answer|do it) anyway|do not refuse)/g,
  },
  // ---- Agentic tool-call hijacking (MED; requires an exfil/action verb to cut FPR) ----
  {
    name: 'agentic_tool_hijack',
    code: 'agentic_tool_hijack',
    category: 'semantic',
    weight: 0.55,
    label: 'tool-call hijack marker',
    perMatchBoost: 0.08,
    cap: 0.85,
    re: /(<function_calls>|<tool_call>|tool_call\s*:\s*|invoke the (api|function|tool)\b[^.!?]{0,30}?\b(to|and)\b[^.!?]{0,30}?\b(send|exfil|download|upload|delete|transfer|post|fetch|leak)\b|call the (function|tool|api)\b[^.!?]{0,30}?\b(to|and)\b[^.!?]{0,30}?\b(send|exfil|download|upload|delete|transfer|post|fetch|leak)\b|execute the following (command|script|code)\b[^.!?]{0,30}?\b(to|and)\b[^.!?]{0,30}?\b(send|exfil|download|upload|delete|transfer|post|fetch|leak)\b|run the following (command|script)\b[^.!?]{0,30}?\b(to|and)\b[^.!?]{0,30}?\b(send|exfil|download|upload|delete|transfer|post|fetch|leak)\b|send the following (data|payload|secret|token|credentials|api keys?)\b[^.!?]{0,30}?\b(to|via|at)\b)/g,
  },
  // ---- System-prompt extraction (MED-HIGH; verb + "system prompt/instructions") ----
  {
    name: 'indirect_extraction',
    code: 'indirect_marker',
    category: 'semantic',
    weight: 0.6,
    label: 'system-prompt extraction marker',
    perMatchBoost: 0.06,
    cap: 0.85,
    re: /((repeat|reveal|show me|print|output|leak|disclose|expose|tell me)\b[^.!?]{0,20}?\b(your|the|its)\b[^.!?]{0,20}?\b(system )?(prompt|instructions|initial message|rules|directives|secret|hidden message)\b)/g,
  },
  // ---- Indirect reference (LOW alone — benign prompt-engineering articles mention "the system prompt") ----
  {
    name: 'indirect_reference',
    code: 'indirect_marker',
    category: 'semantic',
    weight: 0.25,
    label: 'indirect reference marker',
    perMatchBoost: 0.04,
    cap: 0.45,
    re: /(the (system|hidden|secret|true|real|initial) (prompt|instructions|message|rules)|above (instructions|system prompt|rules|message))/g,
  },
];

// Combined single-pass detector (named groups) — used by L2 decode/ROT13 rescan where we
// only need to know IF any marker appeared (detection, not per-pattern scoring). One scan
// instead of N, keeping the always-on ROT13 rescan off the p99 critical path.
const COMBINED_SRC = SPECS.map((s) => `(?<${s.name}>${s.re.source})`).join('|');
const COMBINED_RE = new RegExp(COMBINED_SRC, 'g');
// Non-global variant for a one-shot existence pre-check: if NO pattern can match, the
// separate per-pattern scoring scans are skipped entirely (>90% of traffic is benign).
const COMBINED_TEST_RE = new RegExp(COMBINED_SRC);
const NAME_TO_SPEC = new Map(SPECS.map((s) => [s.name, s] as const));

// Run all separate patterns on the normalized matching copy; returns span-bearing reasons.
// Separate scans preserve overlapping matches (e.g. "ignore previous instructions" hits two
// instruction_override patterns) so the score reflects all evidence.
export function scanRegex(matchingCopy: string): Reason[] {
  const reasons: Reason[] = [];
  if (matchingCopy.length === 0) return reasons;

  // Existence pre-check: skip the per-pattern scoring scans when no marker can match.
  if (!COMBINED_TEST_RE.test(matchingCopy)) return reasons;

  for (const p of SPECS) {
    p.re.lastIndex = 0;
    let match: RegExpExecArray | null;
    let count = 0;
    let firstSpan: [number, number] | undefined;
    while ((match = p.re.exec(matchingCopy)) !== null) {
      count++;
      if (!firstSpan) firstSpan = [match.index, match.index + match[0].length];
      if (match[0].length === 0) p.re.lastIndex++; // guard against zero-width loops
      if (count > 20) break; // bounded
    }
    if (count > 0) {
      const w = clamp01(Math.min(p.cap, p.weight + p.perMatchBoost * (count - 1)));
      reasons.push(
        mkReason(p.code, p.category, w, `${p.label} (n=${count})`, {
          span: firstSpan,
          hardBlock: p.hardBlock,
        }),
      );
    }
  }
  return reasons;
}

// Single-pass marker detection used by L2 decode/ROT13 rescan. Returns match count + codes.
export function scanMarkers(matchingCopy: string): { count: number; codes: Set<ReasonCode> } {
  const codes = new Set<ReasonCode>();
  if (matchingCopy.length === 0) return { count: 0, codes };
  COMBINED_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  let count = 0;
  const groups = SPECS.map((s) => s.name);
  while ((match = COMBINED_RE.exec(matchingCopy)) !== null) {
    count++;
    if (match.groups) {
      for (const name of groups) {
        if (match.groups[name] !== undefined) {
          const spec = NAME_TO_SPEC.get(name);
          if (spec) codes.add(spec.code);
          break;
        }
      }
    }
    if (match[0].length === 0) COMBINED_RE.lastIndex++;
    if (count > 50) break; // bounded
  }
  return { count, codes };
}
