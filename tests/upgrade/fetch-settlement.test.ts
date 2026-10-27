// @vitest-environment node
// Coverage map: REQ-10 (NFR-cancel), REQ-41 (C27), REQ-70 (C24e)
import { expect, test } from 'vitest';
import {
  UpgradeCancelledError,
  UpgradeSessionChangedError,
  UpgradeUnavailableError,
  UpgradeUnsatisfiableError,
  isUpgradeCancelled,
  isUpgradeSessionChanged,
  isUpgradeTransportFailure,
  isUpgradeUnavailable,
  isUpgradeUnsatisfiable,
} from '../../lib/index';
import { upgradeFetch } from '../../lib/upgrade/fetch-adapter';
import { challengeResponse, options } from './fetch-fixtures';

test.each([
  ['cancelled', () => new UpgradeCancelledError(), isUpgradeCancelled],
  ['unsatisfiable', () => new UpgradeUnsatisfiableError(), isUpgradeUnsatisfiable],
  ['unavailable', () => new UpgradeUnavailableError(), isUpgradeUnavailable],
  ['session changed', () => new UpgradeSessionChangedError(), isUpgradeSessionChanged],
] as const)(
  'REQ-C27 fetch portion: %s settles with the original denied response and its identity predicate',
  async (_, error, predicate) => {
    const original = challengeResponse();
    let dispatched = 0;
    const wrapped = upgradeFetch(
      async () => {
        dispatched++;
        return original;
      },
      options({
        elevate: async () => {
          throw error();
        },
      }),
    );
    const result = await wrapped('https://app.example/api/x');
    expect(result).toBe(original);
    expect(result.ok).toBe(false);
    expect(result.bodyUsed).toBe(false);
    expect(predicate(result)).toBe(true);
    expect(predicate(result.clone())).toBe(false);
    expect(dispatched).toBe(1);
  },
);

// A code-tagged Error from another copy/realm is deliberately not instanceof any
// local class. §13.3 requires the literal code to survive that boundary.
test('REQ-C24e fetch non-retryable 400 is discriminable, settles, and never replays', async () => {
  const original = challengeResponse();
  let dispatched = 0;
  const failure = Object.assign(new Error('unsupported factor'), {
    name: 'UpgradeTransportError',
    code: 'upgrade_transport',
    status: 400,
    retryable: false,
  });
  const wrapped = upgradeFetch(
    async () => {
      dispatched++;
      return original;
    },
    options({
      elevate: async () => {
        throw failure;
      },
    }),
  );
  const result = await wrapped('https://app.example/api/x');
  expect(result).toBe(original);
  expect(isUpgradeTransportFailure(result)).toBe(true);
  expect(result.bodyUsed).toBe(false);
  expect(dispatched).toBe(1);
});
