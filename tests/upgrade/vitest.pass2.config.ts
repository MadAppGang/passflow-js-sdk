import { defineConfig } from 'vitest/config';

// Run from the JS package root after transplantation. The normal setup.ts replaces
// standards globals and assumes window exists; these non-visual tests need real URL/Request.
export default defineConfig({
  test: {
    environment: 'node',
    setupFiles: [],
    include: [
      'tests/upgrade/token-application.test.ts',
      'tests/upgrade/controller-lifecycle.test.ts',
      'tests/upgrade/axios-snapshot.test.ts',
      'tests/upgrade/commit-session-policy.test.ts',
      'tests/upgrade/adapter-parity.test.ts',
      'tests/upgrade/joined-operations.test.ts',
    ],
    testTimeout: 10000,
    restoreMocks: true,
  },
});
