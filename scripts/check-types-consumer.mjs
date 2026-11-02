#!/usr/bin/env node
/**
 * Type-checks the packed package the way a consumer sees it.
 *
 * 0.19.0 and 0.20.0 shipped declarations with extensionless relative specifiers, which do not
 * resolve under node16 or nodenext. Nothing caught it, because the repo itself compiles with
 * bundler resolution. This script checks the tarball instead of the source tree:
 *
 *   1. `pnpm build`, unless `--skip-build` or `--tarball` is given.
 *   2. `pnpm pack` into a temp dir, unless `--tarball <path.tgz>` names one to check instead
 *      (an old release as a negative control, or a registry tarball after publish).
 *   3. Shape assertions on the tarball: both `dist/index.d.ts` and `dist/index.d.cts` exist,
 *      nothing under `dist/lib/` ships, and the shipped `.d.ts` has no relative specifier.
 *   4. Copies the fixture in `scripts/types-consumer/` to a temp dir and installs the tarball
 *      there with npm (`--ignore-scripts`: nothing installed runs; only `.d.ts` are read).
 *   5. Runs the repo's own `tsc` with `skipLibCheck: false` under node16, nodenext and
 *      bundler (ESM, `src/esm.ts`) and node16 CJS (`src/cjs.cts`, the `require` condition).
 *      The CJS leg uses node16 on purpose: nodenext accepts `require` of ESM types and would
 *      hide a `require.types` that points at an ESM-only file.
 *
 * Shape and compile failures are reported together, then the script exits 1 if any failed.
 *
 * Usage: node scripts/check-types-consumer.mjs [--skip-build] [--tarball <path.tgz>]
 * Env:   TSC=<path to a tsc JS entry> checks with another TypeScript (e.g. 5.9).
 *        KEEP_CONSUMER=1 keeps the temp dir for inspection.
 * Node 20 or later, no dependencies.
 */

import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const REPO = fileURLToPath(new URL('..', import.meta.url));
const FIXTURE = path.join(REPO, 'scripts', 'types-consumer');
const DEFAULT_TSC = path.join(REPO, 'node_modules', 'typescript', 'bin', 'tsc');
const CONFIGS = ['node16', 'nodenext', 'bundler', 'node16-cjs'];
const REQUIRED_FILES = ['package/dist/index.d.ts', 'package/dist/index.d.cts'];
const FORBIDDEN_PREFIX = 'package/dist/lib/';
const SHIPPED_DTS = 'package/dist/index.d.ts';
// `from './x'`, `from "../x"`, `import('./x')`: any of these breaks node16 resolution.
const RELATIVE_SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(\s*)['"]\.\.?\//;
const SHOWN_ERRORS = 5;

const print = (line) => process.stdout.write(`${line}\n`);

/** Raised for a failure to run the check at all (bad usage, a failed build or install). */
class CheckSetupError extends Error {}

const parseArgs = (argv) => {
  const options = { skipBuild: false, tarball: undefined };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--skip-build') {
      options.skipBuild = true;
    } else if (arg === '--tarball') {
      const value = argv[++i];
      if (!value) throw new CheckSetupError('--tarball needs a path to a .tgz file');
      options.tarball = path.resolve(value);
    } else {
      throw new CheckSetupError(`unknown argument: ${arg}`);
    }
  }
  return options;
};

/** Runs a command without a shell; throws with its output when it fails. */
const run = (command, args, cwd, label) => {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.error) throw new CheckSetupError(`${label}: ${result.error.message}`);
  if (result.status !== 0) {
    throw new CheckSetupError(`${label} failed (exit ${result.status})\n${result.stdout}${result.stderr}`);
  }
  return result.stdout;
};

const packTarball = (workDir) => {
  const dest = path.join(workDir, 'pack');
  // `--pack-destination`, not `--out`: it behaves the same on pnpm 10 and 12.
  run('pnpm', ['pack', '--pack-destination', dest], REPO, 'pnpm pack');
  const tarballs = readdirSync(dest).filter((name) => name.endsWith('.tgz'));
  if (tarballs.length !== 1) throw new CheckSetupError(`expected one .tgz in ${dest}, found ${tarballs.length}`);
  return path.join(dest, tarballs[0]);
};

/** Returns a list of shape problems; an empty list means the tarball layout is right. */
const checkShape = (tarball) => {
  const entries = run('tar', ['-tzf', tarball], REPO, 'tar -tzf').split('\n').filter(Boolean);
  const problems = [];
  for (const file of REQUIRED_FILES) {
    if (!entries.includes(file)) problems.push(`missing ${file}`);
  }
  const libEntries = entries.filter((entry) => entry.startsWith(FORBIDDEN_PREFIX));
  if (libEntries.length > 0) problems.push(`ships ${libEntries.length} files under ${FORBIDDEN_PREFIX}`);
  if (entries.includes(SHIPPED_DTS)) {
    const dts = run('tar', ['-xzOf', tarball, SHIPPED_DTS], REPO, 'tar -xzOf');
    const relative = dts.split('\n').filter((line) => RELATIVE_SPECIFIER.test(line));
    if (relative.length > 0)
      problems.push(`${SHIPPED_DTS} has ${relative.length} relative specifiers, e.g. ${relative[0].trim()}`);
  }
  return problems;
};

const installConsumer = (workDir, tarball) => {
  const consumer = path.join(workDir, 'consumer');
  cpSync(FIXTURE, consumer, { recursive: true });
  // npm, not pnpm: the temp dir is outside the workspace, and a flat npm node_modules is what
  // most consumers have.
  run(
    'npm',
    ['install', '--no-audit', '--no-fund', '--no-package-lock', '--ignore-scripts', '--prefer-offline', tarball],
    consumer,
    'npm install <tarball>',
  );
  return consumer;
};

/** Runs tsc for one config and returns `{ ok, errors }`, where `errors` are the `error TS` lines. */
const typeCheck = (tsc, consumer, config) => {
  const result = spawnSync(process.execPath, [tsc, '-p', path.join(consumer, `tsconfig.${config}.json`), '--pretty', 'false'], {
    cwd: consumer,
    encoding: 'utf8',
  });
  if (result.error) throw new CheckSetupError(`tsc (${config}): ${result.error.message}`);
  const output = `${result.stdout}${result.stderr}`;
  const errors = output.split('\n').filter((line) => line.includes('error TS'));
  return { ok: result.status === 0, errors, output };
};

const main = () => {
  const options = parseArgs(process.argv.slice(2));
  const tsc = process.env.TSC ? path.resolve(process.env.TSC) : DEFAULT_TSC;
  if (!existsSync(tsc)) throw new CheckSetupError(`tsc not found at ${tsc}; run pnpm install or set TSC`);
  if (options.tarball && !existsSync(options.tarball)) throw new CheckSetupError(`no such tarball: ${options.tarball}`);

  const workDir = mkdtempSync(path.join(tmpdir(), 'passflow-types-consumer-'));
  let failed = false;
  try {
    if (!options.tarball && !options.skipBuild) {
      print('Building (pnpm build)...');
      run('pnpm', ['build'], REPO, 'pnpm build');
    }
    const tarball = options.tarball ?? packTarball(workDir);
    print(`Checking ${tarball}`);

    // Shape problems do not stop the run: the compile output is the more useful evidence.
    const problems = checkShape(tarball);
    if (problems.length === 0) {
      print('PASS shape');
    } else {
      failed = true;
      print(`FAIL shape (${problems.length} problems)`);
      for (const problem of problems) print(`  ${problem}`);
    }

    const consumer = installConsumer(workDir, tarball);
    for (const config of CONFIGS) {
      const { ok, errors, output } = typeCheck(tsc, consumer, config);
      if (ok) {
        print(`PASS ${config}`);
        continue;
      }
      failed = true;
      print(`FAIL ${config} (${errors.length} errors)`);
      const shown = errors.length > 0 ? errors : output.trim().split('\n');
      // Paths are relative to the temp consumer; keep only the part after node_modules/ or consumer/.
      for (const line of shown.slice(0, SHOWN_ERRORS)) print(`  ${line.replace(/^.*?(node_modules|consumer)\//, '')}`);
      if (shown.length > SHOWN_ERRORS) print(`  ... ${shown.length - SHOWN_ERRORS} more`);
    }
  } finally {
    if (process.env.KEEP_CONSUMER === '1') {
      print(`Kept ${workDir}`);
    } else {
      rmSync(workDir, { recursive: true, force: true });
    }
  }

  print(failed ? 'Types consumer check FAILED' : 'Types consumer check passed');
  return failed ? 1 : 0;
};

try {
  process.exitCode = main();
} catch (error) {
  if (!(error instanceof CheckSetupError)) throw error;
  process.stderr.write(`check-types-consumer: ${error.message}\n`);
  process.exitCode = 2;
}
