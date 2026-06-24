# AGENTS.md

## Commands

| Task | Command |
|---|---|
| Install | `pnpm install` |
| Lint | `pnpm lint` |
| Typecheck | `pnpm typecheck` |
| Unit tests (153) | `pnpm test` |
| Perf SLA (p99 < 1ms) | `pnpm test:perf` |
| Corpora eval gates | `pnpm eval` |
| Build (ESM + DTS) | `pnpm build` |
| Full CI locally | `pnpm ci` |

## Architecture

- **Tier 0** (sync, sub-ms, zero Node builtins): L0 front-gate → L1 normalize → L2 statistical → L3 structural → scoring. All in `src/tiers/`, `src/normalize/`, `src/scoring.ts`.
- **Phase 2 DX & companions**: `checkMessages` (per-message scoring), `createStreamScanner` (streaming + split-token catch + early-abort), framework middleware (`src/middleware/express.ts`, `hono.ts`, `next.ts`), companions (`src/spotlight/`, `src/egress/`, `src/prompt/`).
- **Phase 3 Tier 1 local ML**: `opensentry/onnx` (Node, onnxruntime-node) + `opensentry/wasm` (edge, onnxruntime-web). Warm singleton, int8, chunking (>512 tok), score-folding (noisy-OR), circuit breaker, degraded fallback. ML infrastructure in `src/ml/` (circuit-breaker, chunker, singleton). Runner interface pluggable via `LocalModelDetector.runner` for testing/custom models.
- **R4 invariant**: confusable folding touches the MATCHING copy only; the MODEL copy (passed downstream) is never folded.
- **Edge-safety**: `src/` must never import `node:*`, use `Buffer`, `process`, `__dirname`, or `setImmediate`. Enforced by `tests/no-node-builtins.test.ts`. Applies to ALL subpaths including companions and middleware — web globals (`btoa`, `TextEncoder`, `crypto.getRandomValues`, `Response`) are allowed. **Exception**: `src/onnx/` is a Node-only subpath (uses onnxruntime-node) and is excluded from the edge-safety check.
- **Performance**: `cleanInvisibles` and `foldConfusables` use lazy-output (return original string if nothing changed) to avoid copying clean input.
- **Subpath exports**: `opensentry` (core), `/confusables`, `/spotlight`, `/egress`, `/prompt`, `/express`, `/hono`, `/next`, `/onnx`, `/wasm`. All built via tsup as separate self-contained ESM bundles.

## Hard Gates (CI-enforced)

- Benign FPR < 1%
- NotInject over-defense < 5%
- Attack recall >= 90%
- Hard-block recall 100%
- Tier 0 p99 < 1ms on few-KB input

## Corpora

- `corpus/attacks.json` — 24 in-scope + 4 outOfScope attack samples
- `corpus/benign.json` — 20 benign samples
- `corpus/notinject.json` — 25 "looks like injection but isn't" samples (over-defense guard)
- To add real datasets: drop JSON files into `corpus/` with the same schema (`id`, `text`, `label`, optional `outOfScope`)
