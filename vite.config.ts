import path from 'path';
import { defineConfig } from 'vitest/config'; // Import from 'vitest/config'
import tsconfigPaths from 'vite-tsconfig-paths';
import dts from 'vite-plugin-dts';

export default defineConfig({
  plugins: [
    tsconfigPaths(),
    dts({
      insertTypesEntry: true,
      rollupTypes: true,
      outDir: './dist',
      entryRoot: './lib',
      tsconfigPath: './tsconfig.json'
    })
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
    },
    sourcemap: true,
    target: 'es2020',
  },
  test: {
    globals: true,
    environment: 'jsdom', // or 'node' based on your needs
    setupFiles: './vitest-setup.ts',
  },
});
