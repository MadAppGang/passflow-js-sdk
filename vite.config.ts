import { defineConfig } from 'vite';
import path from 'path';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()],
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
});