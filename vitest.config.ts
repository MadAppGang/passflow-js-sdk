/// <reference types="vitest" />
import { defineConfig } from 'vitest/config'
import path from 'path'
import tsconfigPaths from 'vite-tsconfig-paths'

export default defineConfig({
  plugins: [
    // Ensure tests use the main tsconfig, not the build one
    tsconfigPaths({ projects: ['tsconfig.json'] }),
  ],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./tests/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      include: [
        'lib/services/**/*.ts',
        'lib/passflow.ts',
        'lib/storage/**/*.ts',
        'lib/token/**/*.ts',
        'lib/store.ts',
      ],
      exclude: [
        '**/node_modules/**',
        '**/dist/**',
        '**/tests/**',
        '**/*.test.ts',
        '**/index.ts',
      ],
      thresholds: {
        lines: 70,
        functions: 60, // Lower threshold for functions - passflow.ts has many delegation methods
        branches: 65,
        statements: 70,
      },
    },
    testTimeout: 10000,
    hookTimeout: 10000,
    include: ['**/tests/**/*.test.ts'],
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './lib'),
    }
  }
})
