// opensentry — tiered prompt-injection validation layer.
// Phase 1: zero-dep, sub-ms Tier 0 core (Node + edge identical).
// Phase 3: optional Tier 1 local ML via opensentry/onnx (Node) or opensentry/wasm (edge).
// ML/remote tiers are progressive enhancements added via config; call sites never change.

export { assertUntrustedSource, createGuard, GuardBlockError } from './guard.js';
export type * from './types.js';
