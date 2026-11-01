import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import { readAcrValues } from '../../lib/upgrade/acr';
import { parseChallengeHeader, readUpgradeChallenge } from '../../lib/upgrade/challenge';

function corpus<T>(file: string): T {
  // HOME-MAP: vitest runs from the js-sdk root; jsdom's import.meta.url is not a file URL.
  const data = JSON.parse(readFileSync(resolve('tests/upgrade/testdata/corpus', file), 'utf8')) as T & {
    corpus_version: number;
  };
  expect(data.corpus_version).toEqual(1);
  return data;
}
type JSChallenge = { acr_values: string | null; max_age: number | null; required_level: number | null };
type ChallengeRow = { id?: string; reason?: string; header: string; status: number; js_sdk: JSChallenge | null };
type Challenges = { cases: ChallengeRow[]; authentication_failures: ChallengeRow[] };

// REQ-20: these are parser expectations, not the scalar server_level column.
describe('resource-server challenge corpus', () => {
  const data = corpus<Challenges>('challenges.json');
  for (const row of [...data.cases, ...data.authentication_failures]) {
    test(row.id ?? row.reason ?? 'unnamed row', () => {
      const expected =
        row.js_sdk === null
          ? undefined
          : {
              acrValues: row.js_sdk.acr_values ?? undefined,
              maxAge: row.js_sdk.max_age ?? undefined,
              status: row.status,
            };
      expect(parseChallengeHeader(row.header, row.status)).toEqual(expected);
      const reading = readUpgradeChallenge(
        {
          status: row.status,
          getHeader: (name: string) => (name.toLowerCase() === 'www-authenticate' ? row.header : undefined),
        },
        undefined,
      ); // No body key, no header-required option.
      if (row.js_sdk === null) {
        expect(reading).toEqual({ diagnostics: [] });
        expect(reading.challenge).toEqual(undefined);
      } else {
        expect(reading.challenge).toEqual({
          ...expected,
          requiredLevel: row.js_sdk.required_level ?? undefined,
          channels: ['header'],
        });
      }
      expect(reading.diagnostics).toEqual([]);
    });
  }
});

type ACRCorpus = {
  cases: {
    acr: unknown;
    js_sdk: { level: number | null; unorderable: boolean; zero: boolean } | null;
  }[];
};
// REQ-20: list-minimum, sign/whitespace and rounded JS-number outcomes are pinned unchanged.
describe('resource-server ACR corpus js_sdk column', () => {
  for (const [index, row] of corpus<ACRCorpus>('acr-levels.json').cases.entries()) {
    if (typeof row.acr !== 'string') continue; // n/a rows bind extraction in the libraries.
    const value = row.acr;
    test(`row ${index}: ${JSON.stringify(value)}`, () => {
      if (row.js_sdk === null) throw new Error('string ACR row missing js_sdk expectation');
      const reading = readAcrValues(value);
      expect(reading.level).toEqual(row.js_sdk.level ?? undefined);
      expect(reading.unorderable).toEqual(row.js_sdk.unorderable);
      expect(reading.zero).toEqual(row.js_sdk.zero);
    });
  }
});
