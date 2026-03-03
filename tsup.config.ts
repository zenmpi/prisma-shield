import { defineConfig } from 'tsup'

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    sourcemap: true,
    clean: true,
    outDir: 'dist',
  },
  {
    entry: ['src/adapters/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    sourcemap: true,
    outDir: 'dist/adapters',
  },
  {
    entry: ['src/cli.ts'],
    format: ['cjs'],
    outDir: 'dist',
    banner: { js: '#!/usr/bin/env node' },
  },
])
