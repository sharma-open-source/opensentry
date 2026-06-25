# Middleware

Framework adapters that scan request bodies through the guard. **Zero framework
dependencies** — structural typing only, so the adapters work without importing
`@types/express` / `@types/hono` etc. Each scans a JSON body field, blocks (400) on a
`block` verdict, and either sanitizes the body or surfaces the result for the next
handler.

All middleware defaults to `source: 'user'` and `inputField: 'input'`, and creates a
zero-config `createGuard()` if you don't pass one. Override any of these.

---

## Express — `opensentry/express`

```ts
import { expressMiddleware } from 'opensentry/express';
import { createGuard } from 'opensentry';

const guard = createGuard();
app.use(expressMiddleware({ guard, inputField: 'prompt' }));
// block → 400 JSON { error, reasons }; allow/flag → sanitized body + next()
```

- On `block`: responds `{ error: 'Input blocked by security guard', reasons: [...] }`
  with status `blockStatus` (default `400`) and does **not** call `next()`.
- On `allow`/`flag`: overwrites `req.body[inputField]` with `result.sanitized` and calls
  `next()`.

Also works with **Next.js Pages Router** (same `req`/`res`/`next` shape).

### Options

```ts
interface ExpressMiddlewareOptions {
  guard?: Guard;        // default createGuard()
  source?: Source;      // default 'user'
  inputField?: string;  // default 'input'
  blockStatus?: number; // default 400
}
```

If the body field isn't a string (or the body is missing), it calls `next()` without
scanning.

---

## Hono — `opensentry/hono`

Edge-compatible (Hono runs on Workers/Deno/Bun/Node).

```ts
import { honoMiddleware } from 'opensentry/hono';
import { createGuard } from 'opensentry';

const guard = createGuard();
app.use('*', honoMiddleware({ guard, inputField: 'input' }));
// block → 400 JSON { error, reasons }; allow → c.set('opensentryResult', result) + next()
```

- On `block`: responds `{ error, reasons }` with status `blockStatus` (default `400`).
- On `allow`/`flag`: stores the result on the Hono context via `c.set('opensentryResult', result)`
  and calls `next()`. Retrieve it downstream with `c.get('opensentryResult')`.

### Options

```ts
interface HonoMiddlewareOptions {
  guard?: Guard;        // default createGuard()
  source?: Source;      // default 'user'
  inputField?: string;  // default 'input'
  blockStatus?: number; // default 400
}
```

If the body isn't valid JSON or the field isn't a string, it calls `next()` without
scanning.

---

## Next.js App Router — `opensentry/next`

Uses Web `Request`/`Response` (edge-compatible). For the Pages Router, use
`opensentry/express` (same `req`/`res`/`next` shape).

```ts
import { nextMiddleware } from 'opensentry/next';
import { createGuard } from 'opensentry';

const guard = createGuard();
const check = nextMiddleware({ guard, inputField: 'input' });

export async function POST(req: Request) {
  const blocked = await check(req);
  if (blocked) return blocked;  // 400 Response
  // continue processing... (remember to read the sanitized body yourself,
  // or use guard.check() inline before your handler)
}
```

- Returns a `Response` (400 JSON `{ error, reasons }`) if blocked.
- Returns `null` if allowed — the caller continues to the route handler.

### Options

```ts
interface NextMiddlewareOptions {
  guard?: Guard;        // default createGuard()
  source?: Source;      // default 'user'
  inputField?: string;  // default 'input'
  blockStatus?: number; // default 400
}
```

If the body isn't valid JSON or the field isn't a string, returns `null` (caller
continues).

---

## Notes

- The middleware adapters run `guard.check` (the async pipeline), so any configured
  Tier 1/Tier 2 detectors are engaged. If you only configured Tier 0 (`checkSync`),
  prefer calling `guard.checkSync` inline in your handler for the sync sub-ms path.
- The sanitized text is written back into the request body (Express) or surfaced via
  context (Hono) — make sure your downstream handler uses the sanitized value, not a
  re-read of the raw body where applicable.
- For richer control (custom sources per route, `highRiskAction`, `onBlock` fallbacks),
  skip the middleware and call `guard.check` directly in your handler — see the
  [recipes](./recipes.md).
