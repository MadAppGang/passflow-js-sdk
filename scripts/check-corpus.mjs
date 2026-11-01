#!/usr/bin/env node
/**
 * Checks the vendored contract corpus against the mirror commit it was copied from.
 *
 * `tests/upgrade/testdata/corpus/` holds byte-for-byte copies of two files from
 * `madappgang/passflow-go`, and its `SOURCE` file names the mirror commit they came from.
 * To update the copies: copy the files from that repository at a commit, write the full
 * commit SHA to `SOURCE`, and run this script.
 *
 * The comparison is pinned to `SOURCE`, so later changes on the mirror never fail an old
 * branch; those only print a notice. `SOURCE` holds the literal `pending` until the mirror
 * is published, and a published mirror with `pending` still in place fails.
 *
 * The only skips, both while `SOURCE` is still `pending`, are a 404 for the repository itself
 * and a repository with no commits yet. With a commit in `SOURCE` that 404 fails, because the
 * pinned mirror was deleted, renamed or made private. Every other failure to compare fails too,
 * so a rate limit never passes as "absent". Node 20 or later, no dependencies.
 */

import { Buffer } from 'node:buffer';
import { readFile } from 'node:fs/promises';
import process from 'node:process';

const REPOSITORY = 'madappgang/passflow-go';
const MIRROR_CORPUS_PATH = 'auth/testdata/corpus';
const VENDORED_FILES = ['challenges.json', 'acr-levels.json'];
const VENDORED_DIR = new URL('../tests/upgrade/testdata/corpus/', import.meta.url);

const PENDING_SOURCE = 'pending';
const COMMIT_SHA = /^[0-9a-f]{40}$/;
const REQUEST_TIMEOUT_MS = 30_000;
const USER_AGENT = 'passflow-js-sdk-corpus-check';

const print = (line) => process.stdout.write(`${line}\n`);

/** Raised for every outcome that must fail the check. Its message is the whole report. */
class CorpusCheckError extends Error {}

const get = (url, headers) => fetch(url, { headers, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });

/** Reads the `message` field GitHub puts in an error body. Any other body has none. */
const readErrorMessage = async (response) => {
  const text = await response.text();
  try {
    const { message } = JSON.parse(text);
    return typeof message === 'string' ? message : 'no message in the response body';
  } catch {
    return 'no message in the response body';
  }
};

/**
 * `GITHUB_TOKEN`, when set, goes to these API requests only: CI runners share an IP address,
 * so the anonymous rate limit would otherwise fail unrelated builds.
 */
const apiHeaders = () => {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': USER_AGENT };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  return headers;
};

/**
 * Probes the repository.
 * @returns {Promise<string | undefined>} GitHub's message, when the repository answers 404
 */
const readAbsentReason = async () => {
  const response = await get(`https://api.github.com/repos/${REPOSITORY}`, apiHeaders());
  if (response.status === 404) {
    return readErrorMessage(response);
  }
  if (response.status !== 200) {
    throw new CorpusCheckError(`could not read ${REPOSITORY}: HTTP ${response.status}, ${await readErrorMessage(response)}`);
  }
  return undefined;
};

/**
 * A repository created ahead of its first sync has nothing published yet. GitHub answers 409
 * for the commit list of a repository with no commits.
 * @returns {Promise<string | undefined>} GitHub's message, when the repository has no commits
 */
const readEmptyReason = async () => {
  const response = await get(`https://api.github.com/repos/${REPOSITORY}/commits?per_page=1`, apiHeaders());
  if (response.status === 409) {
    return readErrorMessage(response);
  }
  if (response.status !== 200) {
    throw new CorpusCheckError(
      `could not read ${REPOSITORY} commits: HTTP ${response.status}, ${await readErrorMessage(response)}`,
    );
  }
  return undefined;
};

const fetchMirrorFile = async (revision, file) => {
  const url = `https://raw.githubusercontent.com/${REPOSITORY}/${revision}/${MIRROR_CORPUS_PATH}/${file}`;
  const response = await get(url, { 'User-Agent': USER_AGENT });
  if (response.status !== 200) {
    return { status: response.status };
  }
  return { status: 200, bytes: Buffer.from(await response.arrayBuffer()) };
};

/** Every vendored file must match the pinned commit. Reports all mismatches, not just the first. */
const compareAtSource = async (source, vendored) => {
  const failures = [];
  for (const [file, bytes] of vendored) {
    const mirror = await fetchMirrorFile(source, file);
    if (mirror.status !== 200) {
      failures.push(`${file}: HTTP ${mirror.status} at ${source}`);
    } else if (!bytes.equals(mirror.bytes)) {
      failures.push(`${file}: differs from ${source}`);
    }
  }
  if (failures.length > 0) {
    throw new CorpusCheckError(`vendored corpus does not match SOURCE:\n  ${failures.join('\n  ')}`);
  }
};

/** Advisory: nothing here can fail the check, including a network failure. */
const noticeMovedOnMain = async (vendored) => {
  for (const [file, bytes] of vendored) {
    try {
      const mirror = await fetchMirrorFile('main', file);
      if (mirror.status !== 200) {
        print(`NOTICE: could not compare ${file} at main (HTTP ${mirror.status})`);
      } else if (!bytes.equals(mirror.bytes)) {
        print(`NOTICE: corpus moved on main since SOURCE (${file})`);
      }
    } catch (error) {
      print(`NOTICE: could not compare ${file} at main (${error.message})`);
    }
  }
};

const readVendored = async () => {
  const source = (await readFile(new URL('SOURCE', VENDORED_DIR), 'utf8')).trim();
  // A branch name here would quietly turn the pinned comparison into a moving one.
  if (source !== PENDING_SOURCE && !COMMIT_SHA.test(source)) {
    throw new CorpusCheckError(`SOURCE must be a full commit SHA or "${PENDING_SOURCE}", found "${source}"`);
  }
  const vendored = new Map();
  for (const file of VENDORED_FILES) {
    vendored.set(file, await readFile(new URL(file, VENDORED_DIR)));
  }
  return { source, vendored };
};

const main = async () => {
  const { source, vendored } = await readVendored();

  const absentReason = await readAbsentReason();
  if (absentReason !== undefined) {
    if (source === PENDING_SOURCE) {
      print(`SKIP: mirror repository absent or private (${absentReason})`);
      return;
    }
    throw new CorpusCheckError(
      `could not read ${REPOSITORY}: HTTP 404, ${absentReason}. SOURCE pins ${source}, so the pinned mirror must be publicly readable`,
    );
  }

  if (source === PENDING_SOURCE) {
    const emptyReason = await readEmptyReason();
    if (emptyReason !== undefined) {
      print(`SKIP: mirror repository has no commits yet (${emptyReason})`);
      return;
    }
    throw new CorpusCheckError(
      `${REPOSITORY} is published but SOURCE is still "${PENDING_SOURCE}": write the mirror commit SHA`,
    );
  }

  await compareAtSource(source, vendored);
  await noticeMovedOnMain(vendored);
  print(`OK: vendored corpus matches ${REPOSITORY}@${source}`);
};

main().catch((error) => {
  process.stderr.write(`FAIL: ${error.message}\n`);
  process.exitCode = 1;
});
