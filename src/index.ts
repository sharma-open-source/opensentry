// opensentry — tiered prompt-injection validation layer.
// Phase 1: zero-dep, sub-ms Tier 0 core (Node + edge identical). ML/remote tiers are
// progressive enhancements added via config in later phases; call sites never change.

export { createGuard, GuardBlockError } from './guard.js';
export type * from './types.js';
