// opensentry/prompt — typed channel-separation prompt assembler (PLAN.md §11a).
// Assembles prompts from TYPED fields, never string concatenation. Untrusted content is
// role-marker-stripped (prevents role spoofing) then auto-spotlighted (datamark mode) so
// the model sees it as data, not instructions. The trusted system prompt passes through
// unchanged as the system message.
//
// PLAN.md security plan #4: an optional `canary` (from opensentry/canary) can be auto-injected
// into the system prompt so downstream output-scan can deterministically detect extraction.

import { injectCanary } from '../canary/index.js';
import { spotlight } from '../spotlight/index.js';
import type { Source } from '../types.js';

// Common chat-template / role markers that an indirect injection could forge.
const ROLE_MARKERS_RE =
  /<\|im_start\|>|<\|im_end\|>|\[\/?(?:system|assistant|user|developer)\]|<\/?(?:system|assistant|user|developer)>/gi;

function stripRoleMarkers(s: string): string {
  return s.replace(ROLE_MARKERS_RE, '');
}

export interface AssembleParts {
  system: string;
  untrusted: { source: Source; content: string }[];
  // Optional canary nonce (createCanary from opensentry/canary). When provided, it is injected
  // into the system prompt and surfaced in the result so callers can scan output for it.
  canary?: string;
}

export interface AssembledMessage {
  role: 'system' | 'user';
  content: string;
}

export interface AssembleResult {
  messages: AssembledMessage[];
  canary?: string;
}

export function assemble(parts: AssembleParts): AssembleResult {
  const systemContent = parts.canary ? injectCanary(parts.system, parts.canary) : parts.system;
  const messages: AssembledMessage[] = [{ role: 'system', content: systemContent }];
  for (const item of parts.untrusted) {
    const cleaned = stripRoleMarkers(item.content);
    const spotlit = spotlight(cleaned, { mode: 'datamark' });
    messages.push({ role: 'user', content: spotlit.text });
  }
  const result: AssembleResult = { messages };
  if (parts.canary) result.canary = parts.canary;
  return result;
}
