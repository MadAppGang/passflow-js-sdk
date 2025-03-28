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
      reporter: ['text', 'lcov'],
      include: ['lib/services/**/*.ts'],
      exclude: ['**/node_modules/**', '**/dist/**']
    },
    include: ['**/tests/**/*.test.ts'],
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './lib'),
    }
  }
})
