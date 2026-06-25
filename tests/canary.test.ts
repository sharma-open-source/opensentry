import { test, expect, describe } from 'vitest';
import { createCanary, injectCanary, detectCanaryLeak } from '../src/canary/index.js';
import { assemble } from '../src/prompt/index.js';

describe('canary — createCanary', () => {
  test('produces a unique, prefixed, unguessable nonce', () => {
    const a = createCanary();
    const b = createCanary();
    expect(a.startsWith('opensentry-canary-')).toBe(true);
    expect(b.startsWith('opensentry-canary-')).toBe(true);
    expect(a).not.toBe(b);
    // 128 bits of entropy = 32 hex chars + prefix length.
    expect(a.length).toBe('opensentry-canary-'.length + 32);
  });
});

describe('canary — injectCanary', () => {
  test('appends the canary to the system prompt', () => {
    const c = createCanary();
    const p = injectCanary('You are a helpful assistant.', c);
    expect(p).toContain('You are a helpful assistant.');
    expect(p).toContain(c);
  });

  test('is idempotent (re-injecting the same canary does not duplicate)', () => {
    const c = createCanary();
    const once = injectCanary('Be concise.', c);
    const twice = injectCanary(once, c);
    expect(twice).toBe(once);
    expect(twice.split(c).length).toBe(2); // appears exactly once
  });

  test('empty canary is a no-op', () => {
    expect(injectCanary('Hello', '')).toBe('Hello');
  });
});

describe('canary — detectCanaryLeak', () => {
  test('output echoing the canary → leaked, with span', () => {
    const c = createCanary();
    const output = `Sure! My instructions are: ${c} ...`;
    const r = detectCanaryLeak(output, [c]);
    expect(r.leaked).toBe(true);
    expect(r.canary).toBe(c);
    expect(r.span).toBeDefined();
    expect(r.span?.[0]).toBe(output.indexOf(c));
  });

  test('benign output without the canary → not leaked', () => {
    const c = createCanary();
    const r = detectCanaryLeak('The capital of France is Paris.', [c]);
    expect(r.leaked).toBe(false);
    expect(r.canary).toBeUndefined();
  });

  test('multiple canaries: detects whichever leaked', () => {
    const c1 = createCanary();
    const c2 = createCanary();
    const r = detectCanaryLeak(`leaked: ${c2}`, [c1, c2]);
    expect(r.leaked).toBe(true);
    expect(r.canary).toBe(c2);
  });

  test('near-zero FP: a random 128-bit prefixed nonce does not appear in benign prose', () => {
    const c = createCanary();
    // A long benign output that mentions "canary" the word but not the nonce.
    const benign = 'The canary in the coal mine is a metaphor for early warning signs.';
    expect(detectCanaryLeak(benign, [c]).leaked).toBe(false);
  });
});

describe('assemble — canary auto-injection (plan #4)', () => {
  test('canary is injected into the system message and surfaced in the result', () => {
    const c = createCanary();
    const r = assemble({
      system: 'You are a helpful assistant.',
      untrusted: [{ source: 'retrieved', content: 'Paris is the capital of France.' }],
      canary: c,
    });
    expect(r.canary).toBe(c);
    expect(r.messages[0]?.role).toBe('system');
    expect(r.messages[0]?.content).toContain(c);
  });

  test('without a canary, assemble behaves exactly as before', () => {
    const r = assemble({
      system: 'You are a helpful assistant.',
      untrusted: [{ source: 'retrieved', content: 'Paris is the capital of France.' }],
    });
    expect(r.canary).toBeUndefined();
    expect(r.messages[0]?.content).toBe('You are a helpful assistant.');
  });
});
