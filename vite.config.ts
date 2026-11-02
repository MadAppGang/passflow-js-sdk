import { readFileSync } from 'node:fs';
import path from 'path';
import { defineConfig } from 'vitest/config'; // Import from 'vitest/config'
import tsconfigPaths from 'vite-tsconfig-paths';

// Read once, not `require()`d: this config is ESM (`"type": "module"`).
const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default defineConfig(({ command }) => {
  // Only use tsconfig.build.json for build, use default for tests
  const tsconfigPathsOptions = command === 'build' 
    ? { projects: ['tsconfig.build.json'] }
    : {};

  return {
    plugins: [
      tsconfigPaths(tsconfigPathsOptions),
    ],
    build: {
      lib: {
        entry: path.resolve(__dirname, 'lib/index.ts'),
        name: 'Passflow JS SDK',
        formats: ['es', 'cjs'],
        // Explicit extensions, not `.js`. This package is `"type": "module"`, so Node parses
        // every `.js` inside it as ESM — a CJS bundle named `index.js` is evaluated as an ES
        // module, silently yielding an empty namespace to `require()`. `.cjs` pins the format.
        fileName: (format) => (format === 'es' ? 'index.mjs' : 'index.cjs'),
      },
      rolldownOptions: {
        // Externalize dependencies to reduce bundle size
        external: [...Object.keys(pkg.dependencies || {}), ...Object.keys(pkg.peerDependencies || {})],
        // Exclude test files from build
        input: {
          index: path.resolve(__dirname, 'lib/index.ts')
        },
        output: {
          // Rolldown's default ('auto') copies only source directives, so the CJS bundle
          // lost the `"use strict"` Rollup always emitted. The ESM source assumes strict
          // semantics, so restore it.
          strict: true,
        },
      },
      sourcemap: true,
      target: 'es2020',
    },
    test: {
      globals: true,
      environment: 'jsdom', // or 'node' based on your needs
      setupFiles: './vitest-setup.ts',
    },
  };
});
