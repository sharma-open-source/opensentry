import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'confusables/index': 'src/confusables/index.ts',
    'spotlight/index': 'src/spotlight/index.ts',
    'egress/index': 'src/egress/index.ts',
    'prompt/index': 'src/prompt/index.ts',
    'canary/index': 'src/canary/index.ts',
    'taint/index': 'src/taint/index.ts',
    'session/index': 'src/session/index.ts',
    'express/index': 'src/middleware/express.ts',
    'hono/index': 'src/middleware/hono.ts',
    'next/index': 'src/middleware/next.ts',
    'onnx/index': 'src/onnx/index.ts',
    'wasm/index': 'src/wasm/index.ts',
    'remote/index': 'src/remote/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
  target: 'es2022',
  platform: 'neutral',
  keepNames: false,
  banner: {
    js: '// opensentry — Tier 0 core: zero-dep, Node + edge identical',
  },
});
