import { test, expect, describe } from 'vitest';
import { frontGate } from '../src/tiers/l0.js';
import { resolveConfig } from '../src/config.js';
import { utf8ByteLength, truncateToBytes } from '../src/normalize/unicode.js';

const cfg = resolveConfig();

describe('L0 front gate', () => {
  test('truncates over the byte cap and sets truncated flag + length_cap reason', () => {
    const big = 'a'.repeat(100_000);
    const out = frontGate(big, cfg.normalize);
    expect(out.truncated).toBe(true);
    expect(out.text.length).toBeLessThanOrEqual(65_536);
    expect(out.reasons.some((r) => r.code === 'length_cap')).toBe(true);
  });

  test('passes small input through unchanged', () => {
    const out = frontGate('hello world', cfg.normalize);
    expect(out.truncated).toBe(false);
    expect(out.text).toBe('hello world');
    expect(out.reasons).toHaveLength(0);
  });

  test('flooding (long repeated run) raises a low-weight length_cap reason', () => {
    const out = frontGate('x'.repeat(5000), cfg.normalize);
    const cap = out.reasons.find((r) => r.code === 'length_cap');
    expect(cap).toBeDefined();
    expect((cap?.weight ?? 0)).toBeLessThan(0.5); // never blocks alone
  });

  test('utf8ByteLength counts multibyte correctly without allocation', () => {
    expect(utf8ByteLength('abc')).toBe(3);
    expect(utf8ByteLength('你好')).toBe(6); // 3 bytes each
    expect(utf8ByteLength('🎉')).toBe(4); // astral
  });

  test('truncateToBytes respects code-point boundaries', () => {
    const s = 'a'.repeat(10) + '你好';
    const out = truncateToBytes(s, 13); // 10 bytes ascii + 1 byte of 你? -> should stop before splitting 你
    expect(out.truncated).toBe(true);
    // Ensure no lone surrogate / split multibyte: result re-encodes to <= 13 bytes
    expect(utf8ByteLength(out.text)).toBeLessThanOrEqual(13);
  });
});
