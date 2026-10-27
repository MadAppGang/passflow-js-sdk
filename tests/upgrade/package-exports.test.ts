/// <reference types="vitest" />

/**
 * Guards the upgrade module's PUBLIC reachability, not its behaviour.
 *
 * This file exists because `@passflow/core@0.14.0` shipped without its headline
 * feature. `lib/upgrade/` was complete and fully tested, but `lib/index.ts`
 * never re-exported it, so the bundler tree-shook the whole module out of both
 * `dist/index.js` and `dist/index.mjs`. The suite stayed green throughout:
 * every upgrade test imports by relative path (`../../lib/upgrade/challenge`),
 * which reaches the source directly and proves exactly nothing about what the
 * package actually ships to consumers.
 *
 * So the import below MUST come from the package entry point and nowhere else.
 * That single distinction is the entire point of this file — rewriting these
 * imports to `../../lib/upgrade/*` would keep every assertion passing while
 * silently restoring the bug it was written to catch.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import {
  DEFAULT_UPGRADE_FACTORS,
  INSUFFICIENT_USER_AUTHENTICATION,
  UPGRADE_REQUIRED,
  UpgradeCancelledError,
  UpgradeController,
  UpgradeFactorError,
  UpgradeUnsatisfiableError,
  factorRegistry,
  parseChallengeBody,
  parseChallengeHeader,
  parseUpgradeChallenge,
  passkeyFactor,
  recoveryCodesFactor,
  selectFactors,
  totpFactor,
} from '../../lib/index';
import type {
  UpgradeAssertContext,
  UpgradeAssertion,
  UpgradeChallenge,
  UpgradeControllerOptions,
  UpgradeFactor,
  UpgradeFactorInput,
  UpgradeFactorType,
  UpgradePrepared,
  UpgradePromptHandler,
  UpgradePromptRequest,
  UpgradePromptResult,
  UpgradeTransport,
} from '../../lib/index';

describe('package entry point exposes the upgrade module', () => {
  test('exports the controller and its error types', () => {
    expect(UpgradeController).toBeTypeOf('function');
    expect(UpgradeCancelledError).toBeTypeOf('function');
    expect(UpgradeUnsatisfiableError).toBeTypeOf('function');

    // Constructible through the entry point, not merely present as a binding.
    expect(new UpgradeCancelledError().name).toBe('UpgradeCancelledError');
    expect(new UpgradeUnsatisfiableError().name).toBe('UpgradeUnsatisfiableError');
  });

  test('exports the challenge parsers and their protocol constants', () => {
    expect(parseUpgradeChallenge).toBeTypeOf('function');
    expect(parseChallengeHeader).toBeTypeOf('function');
    expect(parseChallengeBody).toBeTypeOf('function');
    expect(INSUFFICIENT_USER_AUTHENTICATION).toBe('insufficient_user_authentication');
    expect(UPGRADE_REQUIRED).toBe('upgrade_required');
  });

  test('exports the factor registry, the built-in factors and their error type', () => {
    expect(factorRegistry).toBeTypeOf('function');
    expect(UpgradeFactorError).toBeTypeOf('function');
    expect(DEFAULT_UPGRADE_FACTORS.map((f) => f.type)).toEqual(['totp', 'passkey', 'recovery_codes']);
    expect([totpFactor.type, passkeyFactor.type, recoveryCodesFactor.type]).toEqual(['totp', 'passkey', 'recovery_codes']);
  });

  test('exports the selection function', () => {
    expect(selectFactors).toBeTypeOf('function');
  });

  // A consumer's first call is parse -> select -> registry lookup. Running it
  // end to end proves the exported bindings are wired to each other, not just
  // that names resolve.
  test('the parse -> select -> lookup path works through the entry point alone', () => {
    const challenge = parseChallengeHeader('Bearer error="insufficient_user_authentication", acr_values="2"', 401);
    expect(challenge).toBeDefined();

    const offered = selectFactors(DEFAULT_UPGRADE_FACTORS, challenge as UpgradeChallenge);
    expect(offered[0]!.type).toBe('passkey');

    expect(factorRegistry(offered).get('totp')).toBe(totpFactor);
  });

  // Types erase at runtime, so the only way to assert they are exported is to
  // use them: this block fails `tsc --noEmit` if any name stops resolving.
  test('exports the public types', () => {
    const challenge: UpgradeChallenge = {
      acrValues: '2',
      requiredLevel: 2,
      maxAge: undefined,
      status: 401,
      channels: ['header'],
    };
    const factorType: UpgradeFactorType = 'totp';
    const input: UpgradeFactorInput = 'code';
    const factor: UpgradeFactor = totpFactor;
    const prepared: UpgradePrepared = { challengeId: 'c1', method: 'totp', expiresAt: '2026-01-01T00:00:00Z' };
    const assertion: UpgradeAssertion = { challenge_id: 'c1', code: '000000' };
    const ctx: UpgradeAssertContext = { code: '000000', platform: {} as UpgradeAssertContext['platform'] };
    const promptRequest: UpgradePromptRequest = { challenge, factors: [factor], onFactorSelected: () => {} };
    const promptResult: UpgradePromptResult = { type: 'submit', factor: factorType };
    const prompt: UpgradePromptHandler = async () => promptResult;
    const transport: UpgradeTransport = {
      prepare: async () => prepared,
      commit: async () => undefined,
    };
    const options: UpgradeControllerOptions = { transport, prompt, platform: ctx.platform };

    expect(input).toBe('code');
    expect(promptRequest.factors).toHaveLength(1);
    expect(assertion.code).toBe('000000');
    expect(options.transport).toBe(transport);
  });
});

/**
 * Everything above this line imports from `../../lib/index`, which Vitest resolves to
 * TypeScript SOURCE. That proves a symbol is exported by the source and nothing more.
 *
 * A package can export a symbol in its source, emit it into the bundle, and STILL hand
 * `require()` consumers an empty object. `@passflow/core` did exactly that for several
 * releases:
 *
 *   node -e "console.log(Object.keys(require('@passflow/core')).length)"  ->  0
 *   grep -c 'exports.CLIAuthAPI' dist/index.js                            ->  1
 *
 * The symbol was in the bundle. The bundle was CommonJS. But `package.json` declares
 * `"type": "module"`, so Node parsed `dist/index.js` as ESM — and a CommonJS body under
 * ESM parsing yields a namespace with zero names, with no error and no warning. Bundlers
 * take the `import` condition and got the working `.mjs`, which is why nobody noticed.
 * The fix is the `.cjs` extension: it pins the format regardless of the `type` field.
 *
 * So these tests shell out to a real `node` process and resolve the package the way a
 * consumer does — BY PACKAGE NAME, through the exports map. That resolution is the thing
 * that broke. An in-process `import` would pass just as happily with the bug restored,
 * exactly as the source-level suite above did.
 */

/**
 * Walks up from the Vitest cwd to the `@passflow/core` package root. Deliberately not
 * `import.meta.url`: the jsdom environment swaps in a `URL` shim that cannot take it as
 * a base, and deliberately not a bare `process.cwd()`, which is only correct when Vitest
 * is invoked from the repo root.
 */
const findRepoRoot = (): string => {
  let dir = process.cwd();
  for (let depth = 0; depth < 10; depth += 1) {
    const manifest = resolve(dir, 'package.json');
    if (existsSync(manifest) && JSON.parse(readFileSync(manifest, 'utf8')).name === '@passflow/core') {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(`could not locate the @passflow/core package root from ${process.cwd()}`);
};

const repoRoot = findRepoRoot();
const distDir = resolve(repoRoot, 'dist');
const cjsBundle = resolve(distDir, 'index.cjs');
const esmBundle = resolve(distDir, 'index.mjs');

/**
 * `pnpm test` must not fail merely because someone ran Vitest before `pnpm build`.
 *
 * But this guard must NOT key on `dist/index.cjs`, because that file's absence IS the
 * regression: a build that emits `dist/index.js` instead would then skip these tests
 * rather than fail them, and the suite would go quiet on the exact defect it exists to
 * catch. So "built" means only "a bundle of some name was emitted" — whether it is the
 * RIGHT one is left to the assertions below.
 */
const distIsBuilt = existsSync(distDir) && readdirSync(distDir).some((file) => /^index\.(js|cjs|mjs)$/.test(file));
if (!distIsBuilt) {
  console.warn(
    '[package-exports] dist/ is not built — skipping the built-artifact entry point tests. Run `pnpm build` to enable them.',
  );
}

/** Runs `source` in a real Node process, resolving from the repo root so self-reference works. */
const runNode = (source: string, esm = false): string => {
  const args = esm ? ['--input-type=module', '-e', source] : ['-e', source];
  return execFileSync(process.execPath, args, { cwd: repoRoot, encoding: 'utf8' }).trim();
};

// Symbols spanning several sub-modules, so a partial or tree-shaken bundle is caught too.
const KNOWN_EXPORTS = ['Passflow', 'CLIAuthAPI', 'UpgradeController', 'parseUpgradeChallenge', 'TwoFactorService', 'M2MClient'];

describe.skipIf(!distIsBuilt)('the built package serves both entry conditions', () => {
  test('ships a `.cjs` bundle and no `.js` bundle for Node to misparse', () => {
    expect(existsSync(cjsBundle)).toBe(true);
    expect(existsSync(esmBundle)).toBe(true);

    // The trap file. Under `"type": "module"` a `dist/index.js` holding CommonJS is
    // unloadable by definition, so its absence is part of the contract.
    expect(existsSync(resolve(repoRoot, 'dist/index.js'))).toBe(false);
  });

  test('the exports map points `require` at the `.cjs` file and `import` at the `.mjs` file', () => {
    const pkg = JSON.parse(readFileSync(resolve(repoRoot, 'package.json'), 'utf8'));

    expect(pkg.main).toBe('./dist/index.cjs');
    expect(pkg.exports['.'].require.default).toBe('./dist/index.cjs');
    expect(pkg.exports['.'].import.default).toBe('./dist/index.mjs');

    // Both `types` conditions must resolve to a file that exists; a dangling path
    // silently degrades consumers to `any` instead of failing loudly.
    expect(existsSync(resolve(repoRoot, pkg.exports['.'].require.types))).toBe(true);
    expect(existsSync(resolve(repoRoot, pkg.exports['.'].import.types))).toBe(true);
  });

  test('the CJS bundle is genuinely CommonJS', () => {
    const source = readFileSync(cjsBundle, 'utf8');

    expect(source).toContain('use strict');
    expect(source).toMatch(/\bexports\./);
    // If this ever contains ESM syntax the `.cjs` extension turns a silent empty
    // namespace into a hard SyntaxError, which is a different but equally broken package.
    expect(source).not.toMatch(/^\s*export\s+(?:default|\{|const|function|class)\b/m);
  });

  test('`require("@passflow/core")` yields a populated namespace — the actual regression', () => {
    const namespace = JSON.parse(
      runNode('const m = require("@passflow/core"); console.log(JSON.stringify(Object.keys(m)));'),
    ) as string[];

    // The bug produced exactly this, with no error thrown, so the count is the assertion.
    expect(namespace).not.toHaveLength(0);
    expect(namespace.length).toBeGreaterThan(50);

    for (const name of KNOWN_EXPORTS) {
      expect(namespace).toContain(name);
    }
  });

  test('`import("@passflow/core")` yields a populated namespace', () => {
    const namespace = JSON.parse(
      runNode('import("@passflow/core").then((m) => console.log(JSON.stringify(Object.keys(m))));', true),
    ) as string[];

    expect(namespace.length).toBeGreaterThan(50);

    for (const name of KNOWN_EXPORTS) {
      expect(namespace).toContain(name);
    }
  });

  test('both entry conditions expose an identical export surface', () => {
    const { cjsKeys, esmKeys } = JSON.parse(
      runNode(`
        const cjs = require('@passflow/core');
        import('@passflow/core').then((esm) => {
          console.log(
            JSON.stringify({
              cjsKeys: Object.keys(cjs).sort(),
              esmKeys: Object.keys(esm).filter((k) => k !== 'default').sort(),
            }),
          );
        });
      `),
    ) as { cjsKeys: string[]; esmKeys: string[] };

    // Not just equal counts: the same names. A CJS consumer and an ESM consumer must
    // not see different SDKs.
    expect(cjsKeys).toEqual(esmKeys);
  });

  test('the upgrade module in particular is reachable through the CJS entry point', () => {
    // The source-level suite above already proved `lib/index.ts` re-exports these.
    // This proves the shipped CommonJS bundle actually hands them to a consumer.
    const probe = runNode(`
      const { UpgradeController, UpgradeCancelledError, parseChallengeHeader, DEFAULT_UPGRADE_FACTORS } = require('@passflow/core');
      const challenge = parseChallengeHeader('Bearer error="insufficient_user_authentication", acr_values="2"', 401);
      console.log(
        JSON.stringify({
          controller: typeof UpgradeController,
          cancelledName: new UpgradeCancelledError().name,
          acrValues: challenge.acrValues,
          factors: DEFAULT_UPGRADE_FACTORS.map((f) => f.type),
        }),
      );
    `);

    expect(JSON.parse(probe)).toEqual({
      controller: 'function',
      cancelledName: 'UpgradeCancelledError',
      acrValues: '2',
      factors: ['totp', 'passkey', 'recovery_codes'],
    });
  });
});
