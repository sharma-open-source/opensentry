import type { Reason, ReasonCategory, ReasonCode } from './types.js';

// Reason constructor that respects `exactOptionalPropertyTypes` — optional fields are
// only set when provided, never assigned `undefined`.
export function mkReason(
  code: ReasonCode,
  category: ReasonCategory,
  weight: number,
  message: string,
  opts?: { span?: [number, number] | undefined; hardBlock?: boolean | undefined },
): Reason {
  const r: Reason = { code, category, weight: clamp01(weight), message };
  if (opts?.span) r.span = opts.span;
  if (opts?.hardBlock) r.hardBlock = true;
  return r;
}

export function clamp01(x: number): number {
  if (x < 0) return 0;
  if (x > 1) return 1;
  return x;
}

// Linear-interpolate weight by a 0..1 density, capped.
export function densityWeight(base: number, density: number, scale: number, cap: number): number {
  return Math.min(cap, base + density * scale);
}
