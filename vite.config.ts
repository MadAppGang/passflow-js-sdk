import path from 'path';
import { defineConfig } from 'vitest/config'; // Import from 'vitest/config'
import tsconfigPaths from 'vite-tsconfig-paths';

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
        fileName: (format) => (format === 'es' ? 'index.mjs' : 'index.js'),
      },
      rollupOptions: {
        // Externalize dependencies to reduce bundle size
        external: [
          ...Object.keys(require('./package.json').dependencies || {}),
          ...Object.keys(require('./package.json').peerDependencies || {}),
        ],
        // Exclude test files from build
        input: {
          index: path.resolve(__dirname, 'lib/index.ts')
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
