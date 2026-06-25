import { test, expect, describe } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const srcDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) {
      walk(full, out);
    } else if (name.endsWith('.ts')) {
      out.push(full);
    }
  }
  return out;
}

// Tier 0 core has ZERO Node builtins and runs identically on
// Node/Deno/Bun/Workers. Enforce it statically so an accidental `node:fs` / `Buffer`
// / `process` usage in src can never land.
//
// Exception: src/onnx/ is a Node-only subpath (uses onnxruntime-node for native ML).
// It is excluded from the edge-safety check — edge users import opensentry/wasm instead.
const EDGE_UNSAFE_DIRS = ['onnx'];

const FORBIDDEN: RegExp[] = [
  /\bfrom\s+['"]node:/, // node: imports
  /\brequire\s*\(/, // CJS require
  /\bBuffer\b/, // Node Buffer global
  /\bprocess\./, // process.env / process.cwd etc.
  /\b__dirname\b/,
  /\b__filename\b/,
  /\bsetImmediate\b/, // Node-only scheduler
];

describe('Tier 0 core edge-safety — no Node builtins in src', () => {
  const allFiles = walk(srcDir);
  // Filter out Node-only subpaths (src/onnx/ uses onnxruntime-node).
  const files = allFiles.filter((f) => {
    const rel = path.relative(srcDir, f);
    return !EDGE_UNSAFE_DIRS.some((d) => rel.startsWith(`${d}${path.sep}`));
  });
  test('src/ contains the expected files', () => {
    expect(files.length).toBeGreaterThan(5);
  });

  for (const file of files) {
    const rel = path.relative(srcDir, file);
    test(`${rel} has no Node builtins`, () => {
      const src = readFileSync(file, 'utf8');
      for (const re of FORBIDDEN) {
        // eslint-disable-next-line no-console
        expect(src, `${rel} matches forbidden pattern ${re}`).not.toMatch(re);
      }
    });
  }
});
