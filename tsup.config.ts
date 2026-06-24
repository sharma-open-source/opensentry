import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'confusables/index': 'src/confusables/index.ts',
  },
  format: ['esm'],
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
