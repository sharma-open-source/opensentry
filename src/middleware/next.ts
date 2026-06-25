// opensentry/next — Next.js App Router middleware adapter.
// Scans a JSON body field through the guard. Returns a 400 Response if blocked, or null
// if allowed (the caller continues to the route handler). Uses Web Request/Response
// (edge-compatible). For Pages Router, use opensentry/express (same req/res/next shape).

import { createGuard } from '../index.js';
import type { Guard, Source } from '../types.js';

export interface NextMiddlewareOptions {
  guard?: Guard;
  source?: Source;
  inputField?: string;
  blockStatus?: number;
}

export function nextMiddleware(opts?: NextMiddlewareOptions) {
  const guard = opts?.guard ?? createGuard();
  const source: Source = opts?.source ?? 'user';
  const inputField = opts?.inputField ?? 'input';
  const blockStatus = opts?.blockStatus ?? 400;

  return async (req: { json(): Promise<unknown> }): Promise<Response | null> => {
    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return null;
    }
    const text =
      body && typeof body === 'object' ? (body as Record<string, unknown>)[inputField] : undefined;
    if (typeof text !== 'string') return null;
    const result = await guard.check(text, { source });
    if (result.verdict === 'block') {
      return new Response(
        JSON.stringify({
          error: 'Input blocked by security guard',
          reasons: result.reasons.map((r) => r.code),
        }),
        { status: blockStatus, headers: { 'Content-Type': 'application/json' } },
      );
    }
    return null;
  };
}
