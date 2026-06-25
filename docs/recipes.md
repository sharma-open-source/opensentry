# Recipes

Common integration patterns. Each is copy-pasteable and shows the idiomatic shape for
the scenario.

---

## 1. Zero-config drop-in (Tier 0 only)

The simplest useful integration — sub-ms Tier 0, zero deps, flag passes through, block
throws:

```ts
import { createGuard } from 'opensentry';

const guard = createGuard();
const safeCallLLM = guard.wrap(callLLM); // flag => passthrough sanitized, block => GuardBlockError

const answer = await safeCallLLM(userPrompt);
```

---

## 2. RAG with source-aware trust

Score each input by its source. Retrieved/web content is untrusted and defaults to
`alwaysEscalate: true` (escalates to ML/remote when configured):

```ts
const guard = createGuard({
  detectors: [
    { kind: 'heuristics' },
    { kind: 'localModel', runtime: 'wasm', quantized: true, warmOnBoot: true },
  ],
});

const results = await guard.checkMessages([
  { role: 'system', content: systemPrompt },     // skipped (trusted)
  { role: 'user', content: userQuery },          // scored
  { role: 'retrieved', content: ragChunk },      // scored + alwaysEscalates to ML
]);

// Block on any attack; always pass sanitized downstream.
const safe = results.map((r) => r.sanitized);
```

For stronger channel separation, use the [prompt assembler](./companions.md#prompt-assembler-opensentryprompt)
to datamark + role-strip the untrusted content before it reaches the model.

---

## 3. Agentic tool-call gating

`guard.checkToolCall` enforces a tool-name allowlist **before execution** and scans the
args through the full pipeline. `highRiskAction` is forced, so the uncertain band fails
closed:

```ts
const guard = createGuard({
  detectors: [
    { kind: 'heuristics' },
    { kind: 'localModel', runtime: 'node' },
  ],
});

const result = await guard.checkToolCall(
  { name: 'sendEmail', args: { to: 'user@example.com', body: emailBody } },
  { allow: { sendEmail: {}, readFile: {}, searchWeb: {} } },
);
if (result.verdict === 'block') return refuse(result.reasons);
// proceed with the tool call
```

A tool name outside `policy.allow` always blocks (`agentic_tool_hijack`); a name inside
the allowlist still has its `args` scanned. The privilege model itself (what a tool is
actually allowed to do) stays in your runtime.

### With indirect-injection defense (taint tracking)

Catch untrusted-origin text reaching a privileged tool — even if the args themselves
don't trip the classifier:

```ts
import { createTaintTracker } from 'opensentry/taint';

const tracker = createTaintTracker();
const ragDoc = tracker.mark(retrievedDoc, 'retrieved'); // mark + use inline

// ...later, the agent decides to sendEmail with args built from ragDoc...
const result = await guard.checkToolCall(
  { name: 'sendEmail', args: { body: agentComposedBody } },
  { allow: { sendEmail: {} } },
  { tracker }, // untrusted-origin text in args → tainted_data_flow + fail-closed
);
```

This is **policy, not a classifier** — low false-positive. It flags *data flow into
privileged actions*, not content. See [Companions → Taint](./companions.md#taint-opensentrytaint).

---

## 4. Streaming output / chunked tool content

`createStreamScanner` buffers across chunk boundaries so split injection tokens
(`"<|im_st" + "art|>"`) are caught. Supports early-abort:

```ts
const scanner = guard.createStreamScanner({ source: 'tool' });
let output = '';
for await (const chunk of modelStream) {
  const { partial, abort } = scanner.push(chunk);
  if (abort) {
    // block detected mid-stream — stop generation
    break;
  }
  output += chunk;
  // ...yield chunk to client...
}
const final = scanner.end(); // full GuardResult on the accumulated buffer
```

Use the same scanner for model output (egress) and for chunked tool output. For a
full egress filter (URL allowlist, secrets, PII), see
[Companions → Egress](./companions.md#egress-filter-opensentryegress).

---

## 5. Multi-turn / Crescendo defense

The core guard is stateless (`conversationId` is only a cache/metric key). For
Crescendo / Bad Likert Judge / many-shot — which exceed ~70% success because no single
turn is flaggable — wrap it in a session guard:

```ts
import { createGuard } from 'opensentry';
import { createSessionGuard } from 'opensentry/session';

const guard = createGuard({ detectors: [{ kind: 'heuristics' }, { kind: 'localModel', runtime: 'wasm' }] });
const sg = createSessionGuard(guard, { decay: 0.8, escalationDelta: 0.3 });

// Per turn:
const r = await sg.check(userTurn, { conversationId: 'conv-123', source: 'user' });
if (r.verdict === 'block') return refuse(r.reasons);
// r.reasons may include cumulative_risk / session_escalation / manyshot_density

sg.reset('conv-123'); // clear state when the conversation ends
```

Session signals are flag-weighted, decaying, and can only escalate — a single spike
won't poison a long benign conversation. For distributed deployments, implement the
`SessionStore` interface against Redis/DB. See
[Companions → Session](./companions.md#session-opensentrysession).

---

## 6. Shadow → soft → enforce rollout

Graduated enforcement on measured live FPR + latency:

```ts
// 1) Shadow: compute verdicts, never block — log wouldVerdict to measure FPR
const shadowGuard = createGuard({
  mode: 'shadow',
  detectors: [{ kind: 'heuristics' }, { kind: 'localModel', runtime: 'wasm', warmOnBoot: true }],
  onMetric: (m) => metrics.record({ wouldVerdict: m.wouldVerdict, verdict: m.verdict, latencyMs: m.latencyMs }),
});

// 2) Soft: once shadow metrics meet FPR + latency budgets, downgrade block→flag
const softGuard = createGuard({ mode: 'soft', /* ... */ });

// 3) Enforce: once you're confident, turn on blocking
const guard = createGuard({ mode: 'enforce', /* ... */ });
```

`result.verdict` is always `allow` in shadow; `result.wouldVerdict` shows the real
decision. Watch appeal rate, task-completion, and CSAT alongside ASR as you ramp.

---

## 7. Human-in-the-loop for high-risk actions

`highRiskAction` is the *signal*, not the UI. Pair it with `failMode: 'closed'` so the
uncertain band escalates to block (→ route to a reviewer) rather than passing silently:

```ts
const guard = createGuard({
  policy: { perSource: { tool: { failMode: 'closed' } } },
});

const result = await guard.check(toolArgs, { source: 'tool', highRiskAction: true });
if (result.verdict === 'block') {
  // route to a human reviewer with result.reasons
  return routeToReviewer(result);
}
```

`onBlock` / `GuardBlockError` carry the structured decision to your reviewer workflow.

---

## 8. Prompt assembly with canary leak detection

Assemble prompts from typed fields (channel separation) + inject a canary for
deterministic system-prompt-leak detection:

```ts
import { assemble } from 'opensentry/prompt';
import { createCanary, detectCanaryLeak } from 'opensentry/canary';

const canary = createCanary();
const { messages } = assemble({
  system: 'You are a helpful assistant.',
  untrusted: [{ source: 'web', content: webpage }],
  canary, // auto-injected into the system message
});

const modelOutput = await callLLM(messages);

// Deterministic leak check on egress:
const leak = detectCanaryLeak(modelOutput, [canary]);
if (leak.leaked) {
  // confirmed extraction — canary_leak is a hard-block reason
  alertSecurityTeam(leak);
}
```

---

## 9. Full defense-in-depth stack

Combine the guard + companions for the highest coverage:

```ts
import { createGuard } from 'opensentry';
import { createSessionGuard } from 'opensentry/session';
import { createTaintTracker } from 'opensentry/taint';
import { createCanary } from 'opensentry/canary';
import { assemble } from 'opensentry/prompt';
import { egressFilter } from 'opensentry/egress';

const baseGuard = createGuard({
  mode: 'enforce',
  normalize: { neutralizeEncoded: 'strip', scanAdversarialSuffix: true },
  detectors: [
    { kind: 'heuristics' },
    { kind: 'localModel', runtime: 'wasm', quantized: true, warmOnBoot: true, minConfidence: 0.87 },
  ],
});
const guard = createSessionGuard(baseGuard, { decay: 0.8, escalationDelta: 0.3 });
const tracker = createTaintTracker();
const canary = createCanary();

// Input side: assemble with channel separation + canary
const { messages } = assemble({
  system: systemPrompt,
  untrusted: [
    { source: 'retrieved', content: tracker.mark(ragChunk, 'retrieved') },
    { source: 'web', content: tracker.mark(webpage, 'web') },
  ],
  canary,
});

const r = await guard.check(latestUserTurn, { conversationId, source: 'user' });
if (r.verdict === 'block') return refuse(r.reasons);

// ...model call...

// Output side: egress filter for exfil/secrets/PII + canary leak check
const egress = egressFilter(modelOutput, { allowlist: URL_ALLOWLIST, scanSecrets: true });
const leak = detectCanaryLeak(modelOutput, [canary]);
```

This is the shape the design recommends — `opensentry` is **one layer** among the
companions. Also ship least-privilege tool scoping and human approval for genuinely
high-risk actions in your runtime; consider the dual-LLM / quarantined-privileged
pattern for agentic systems (the injectable model holds no authority).
