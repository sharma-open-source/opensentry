# AGENTS.md

## Commands

| Task | Command |
|---|---|
| Install | `pnpm install` |
| Lint | `pnpm lint` |
| Typecheck | `pnpm typecheck` |
| Unit tests (66) | `pnpm test` |
| Perf SLA (p99 < 1ms) | `pnpm test:perf` |
| Corpora eval gates | `pnpm eval` |
| Build (ESM + DTS) | `pnpm build` |
| Full CI locally | `pnpm ci` |

## Architecture

- **Tier 0** (sync, sub-ms, zero Node builtins): L0 front-gate → L1 normalize → L2 statistical → L3 structural → scoring. All in `src/tiers/`, `src/normalize/`, `src/scoring.ts`.
- **R4 invariant**: confusable folding touches the MATCHING copy only; the MODEL copy (passed downstream) is never folded.
- **Edge-safety**: `src/` must never import `node:*`, use `Buffer`, `process`, `__dirname`, or `setImmediate`. Enforced by `tests/no-node-builtins.test.ts`.
- **Performance**: `cleanInvisibles` and `foldConfusables` use lazy-output (return original string if nothing changed) to avoid copying clean input.

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
