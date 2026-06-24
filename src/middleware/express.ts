// opensentry/express — Express-style middleware adapter (PLAN.md §6, §12 Phase 2).
// Scans a body field through the guard; blocks (400) or sanitizes and calls next().
// Uses structural typing so no @types/express dependency is needed. Also works with
// Next.js Pages Router (same req/res/next shape).

import { createGuard } from '../index.js';
import type { Guard, Source } from '../types.js';

interface ExpressReq {
  body?: Record<string, unknown>;
}
interface ExpressRes {
  status(code: number): ExpressRes;
  json(body: unknown): void;
}
type ExpressNext = (err?: unknown) => void;

export interface ExpressMiddlewareOptions {
  guard?: Guard;
  source?: Source;
  inputField?: string;
  blockStatus?: number;
}

export function expressMiddleware(opts?: ExpressMiddlewareOptions) {
  const guard = opts?.guard ?? createGuard();
  const source: Source = opts?.source ?? 'user';
  const inputField = opts?.inputField ?? 'input';
  const blockStatus = opts?.blockStatus ?? 400;

  return async (req: ExpressReq, res: ExpressRes, next: ExpressNext): Promise<void> => {
    const body = req?.body;
    const text =
      body && typeof body === 'object' ? (body as Record<string, unknown>)[inputField] : undefined;
    if (typeof text !== 'string') {
      next();
      return;
    }
    const result = await guard.check(text, { source });
    if (result.verdict === 'block') {
      res.status(blockStatus).json({
        error: 'Input blocked by security guard',
        reasons: result.reasons.map((r) => r.code),
      });
      return;
    }
    if (body && typeof body === 'object') {
      (body as Record<string, unknown>)[inputField] = result.sanitized;
    }
    next();
  };
}
