// opensentry/hono — Hono middleware adapter.
// Scans a JSON body field through the guard; blocks (400) or stores the sanitized result
// in the Hono context and calls next(). Uses structural typing so no @types/hono
// dependency is needed. Edge-compatible (Hono runs on Workers/Deno/Bun/Node).

import { createGuard } from '../index.js';
import type { Guard, Source } from '../types.js';

interface HonoContext {
  req: { json(): Promise<unknown> };
  json(body: unknown, status?: number): unknown;
  set(key: string, value: unknown): void;
}
type HonoNext = () => Promise<void> | void;

export interface HonoMiddlewareOptions {
  guard?: Guard;
  source?: Source;
  inputField?: string;
  blockStatus?: number;
}

export function honoMiddleware(opts?: HonoMiddlewareOptions) {
  const guard = opts?.guard ?? createGuard();
  const source: Source = opts?.source ?? 'user';
  const inputField = opts?.inputField ?? 'input';
  const blockStatus = opts?.blockStatus ?? 400;

  return async (c: HonoContext, next: HonoNext): Promise<void> => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      await next();
      return;
    }
    const text =
      body && typeof body === 'object' ? (body as Record<string, unknown>)[inputField] : undefined;
    if (typeof text !== 'string') {
      await next();
      return;
    }
    const result = await guard.check(text, { source });
    if (result.verdict === 'block') {
      c.json(
        { error: 'Input blocked by security guard', reasons: result.reasons.map((r) => r.code) },
        blockStatus,
      );
      return;
    }
    c.set('opensentryResult', result);
    await next();
  };
}
