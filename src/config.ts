import type {
  Detector,
  GuardConfig,
  GuardMetric,
  Mode,
  PerSourcePolicy,
  ReasonCode,
  Source,
  Thresholds,
} from './types.js';

// ---- Locked defaults ----

export const DEFAULT_THRESHOLDS: Thresholds = { flag: 0.4, block: 0.85 };
export const DEFAULT_MAX_SCAN_BYTES = 65536;
export const DEFAULT_DECODE_DEPTH = 2;
export const DEFAULT_MODE: Mode = 'enforce';
export const DEFAULT_FAIL_MODE: 'open' | 'closed' = 'open';

// Deterministic hard-block floor: fires even in fail-open.
// Kept tiny + high-confidence to protect benign quality / NotInject hard-negatives.
export const DEFAULT_HARD_BLOCK_RULES: readonly ReasonCode[] = [
  'unicode_tag_smuggling', // U+E0000–E007F Tag block — zero legitimate use
  'exfil_markdown_image', // markdown-image exfil lure
  'template_forgery', // forged chat-template / turn markers
];

// Per-source defaults (policy.perSource).
//
// `user` defaults to alwaysEscalate:true (changed from false — see bench/REPORT.md and
// Real-corpus benchmarking). Real-corpus benchmarking found that harmful-intent/jailbreak
// attacks with no structural marker (AdvBench, JBB-harmful, DAN-style prompts) score exactly
// 0 on Tier 0 and never reach the flag band, so under the old default Tier 1 never saw them
// for the dominant attack channel. This only changes behavior once a localModel/remoteGuard/
// embeddingCorpus detector is configured — Tier 0-only zero-config is unaffected. Pair with
// LocalModelDetector.minConfidence (src/types.ts) to avoid raising NotInject over-defense.
export const DEFAULT_PER_SOURCE: Partial<Record<Source, PerSourcePolicy>> = {
  system: { skip: true }, // never scored as attack
  user: { alwaysEscalate: true },
  retrieved: { alwaysEscalate: true },
  tool: { alwaysEscalate: true },
  web: { alwaysEscalate: true },
  email: { alwaysEscalate: true },
};

export const UNTRUSTED_SOURCES: readonly Source[] = ['retrieved', 'tool', 'web', 'email'];

// Common chat-template / control tokens across Llama/Qwen/GPT/Mistral/Gemma families.
// Scanned on the MATCHING copy only → special_token_injection. Control tokens have
// essentially zero legitimate use in untrusted user data; the model copy is untouched
// (R4 two-copy invariant). Only FULL, unambiguous tokens are listed — no partial prefixes
// or model names that risk flagging benign mentions.
export const DEFAULT_SPECIAL_TOKENS: readonly string[] = [
  '<|im_start|>',
  '<|im_end|>',
  '<|endofprompt|>',
  '<|begin_of_text|>',
  '<|end_of_text|>',
  '<|start_header_id|>',
  '<|end_header_id|>',
  '<|eot_id|>',
  '<|eom_id|>',
  '[INST]',
  '[/INST]',
  '<<SYS>>',
  '<</SYS>>',
  '<start_of_turn>',
  '<end_of_turn>',
  '<|tool|>',
  '<|resource|>',
  '<|assistant|>',
  '<|system|>',
  '<|user|>',
];

export const DEFAULT_RTL_LOCALES: readonly string[] = [
  'ar',
  'arc',
  'dv',
  'fa',
  'ha',
  'he',
  'iw',
  'khw',
  'ks',
  'ku',
  'ps',
  'ur',
  'yi',
];

// ---- Resolved config (internal) ----

export interface ResolvedNormalize {
  nfkc: boolean;
  stripInvisible: boolean;
  foldConfusables: boolean;
  handleBidi: 'strip' | 'isolate' | 'off';
  decodeEncoded: boolean;
  decodeDepth: number;
  maxScanBytes: number;
  rtlLocales: readonly string[];
  neutralizeEncoded: 'off' | 'strip' | 'spotlight';
  specialTokens: readonly string[];
  scanAdversarialSuffix: boolean;
}

export interface ResolvedConfig {
  mode: Mode;
  thresholds: Thresholds;
  failMode: 'open' | 'closed';
  hardBlockRules: readonly ReasonCode[] | true;
  perSource: Partial<Record<Source, PerSourcePolicy>>;
  normalize: ResolvedNormalize;
  detectors: Detector[];
  cacheMax: number;
  onMetric?: (m: GuardMetric) => void;
}

export function resolveConfig(config?: GuardConfig): ResolvedConfig {
  const n = config?.normalize ?? {};
  const perSource: Partial<Record<Source, PerSourcePolicy>> = { ...DEFAULT_PER_SOURCE };
  if (config?.policy?.perSource) {
    for (const key of Object.keys(config.policy.perSource) as Source[]) {
      const override = config.policy.perSource[key];
      if (override) perSource[key] = { ...perSource[key], ...override };
    }
  }
  const resolved: ResolvedConfig = {
    mode: config?.mode ?? DEFAULT_MODE,
    thresholds: { ...DEFAULT_THRESHOLDS, ...(config?.thresholds ?? {}) },
    failMode: config?.policy?.failMode ?? DEFAULT_FAIL_MODE,
    hardBlockRules: config?.policy?.hardBlockRules ?? DEFAULT_HARD_BLOCK_RULES,
    perSource,
    normalize: {
      nfkc: n.nfkc ?? true,
      stripInvisible: n.stripInvisible ?? true,
      foldConfusables: n.foldConfusables ?? true,
      handleBidi: n.handleBidi ?? 'strip',
      decodeEncoded: n.decodeEncoded ?? true,
      decodeDepth: n.decodeDepth ?? DEFAULT_DECODE_DEPTH,
      maxScanBytes: n.maxScanBytes ?? DEFAULT_MAX_SCAN_BYTES,
      rtlLocales: n.rtlLocales ?? DEFAULT_RTL_LOCALES,
      neutralizeEncoded: n.neutralizeEncoded ?? 'off',
      specialTokens: n.specialTokens ?? DEFAULT_SPECIAL_TOKENS,
      scanAdversarialSuffix: n.scanAdversarialSuffix ?? false,
    },
    detectors: config?.detectors ?? [{ kind: 'heuristics' }],
    cacheMax: config?.cache?.max ?? 1024,
  };
  if (config?.onMetric) resolved.onMetric = config.onMetric;
  return resolved;
}

export function isHardBlock(code: ReasonCode, rules: readonly ReasonCode[] | true): boolean {
  if (rules === true) return true;
  return rules.includes(code);
}

export function isRtlLocale(locale: string | undefined, rtlLocales: readonly string[]): boolean {
  if (!locale) return false;
  const base = locale.toLowerCase().split(/[-_]/)[0] ?? '';
  return rtlLocales.includes(base);
}

// Resolve the effective thresholds + failMode for a given source context.
export function resolveSourcePolicy(
  cfg: ResolvedConfig,
  source: Source,
): { thresholds: Thresholds; alwaysEscalate: boolean; skip: boolean; failMode: 'open' | 'closed' } {
  const p = cfg.perSource[source];
  return {
    thresholds: { ...cfg.thresholds, ...(p?.thresholds ?? {}) },
    alwaysEscalate: p?.alwaysEscalate ?? false,
    skip: p?.skip ?? false,
    failMode: p?.failMode ?? cfg.failMode,
  };
}
