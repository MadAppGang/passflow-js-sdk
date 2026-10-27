// @vitest-environment node
// Actual bound protected operations complement the controller's report-protocol tests.
import { expect, test, vi } from 'vitest';
import { UpgradeController } from '../../lib/upgrade/controller';
import { isUpgradeInsufficient } from '../../lib/upgrade/core';
import { upgradeFetch } from '../../lib/upgrade/fetch-adapter';
import { createMockPlatform } from '../helpers/mock-platform';
import { challengeResponse, deferred, options } from './fetch-fixtures';
import { promptDriver } from './pass2-fixtures';

test('REQ-59 REQ-60 REQ-66 REQ-100 REQ-101 C18a C18b C24a late stronger caller alone gets insufficient; retry starts sequentially', async () => {
  const driver = promptDriver();
  const summaries: { terminal: string; waiters: { url?: string; outcome: string }[] }[] = [];
  let obtained = 2;
  let commits = 0;
  let registrations = 0;
  const controller = new UpgradeController({
    platform: createMockPlatform(),
    prompt: driver.prompt,
    transport: {
      prepare: async () => undefined,
      commit: async () => {
        commits++;
      },
    },
    readObtainedBar: () => ({ level: obtained, acrValues: String(obtained) }),
    onFlightSettled: (summary) => {
      summaries.push(summary);
    },
  });
  const traffic: string[] = [];
  const perUrl = new Map<string, number>();
  const weakSuccess = new Response('weak-operation-result');
  const strongSuccess = new Response('strong-operation-result');
  const deniedStrong = challengeResponse(401, 'Bearer error="insufficient_user_authentication", acr_values="3"');
  const wrapped = upgradeFetch(
    async (input) => {
      const url = String(input);
      traffic.push(url);
      const visit = (perUrl.get(url) ?? 0) + 1;
      perUrl.set(url, visit);
      if (url.endsWith('/weak')) return visit === 1 ? challengeResponse() : weakSuccess;
      if (visit === 1) return challengeResponse(401, 'Bearer error="insufficient_user_authentication", acr_values="3"');
      return obtained >= 3 ? strongSuccess : deniedStrong;
    },
    options({
      elevate: (c, w) => {
        registrations++;
        return controller.elevate(c, w);
      },
      readObtainedBar: () => ({ level: obtained }),
    }),
  );

  const a = wrapped('https://app.example/weak');
  await vi.waitFor(() => expect(driver.requests).toHaveLength(1));
  driver.select(); // deliberately select before the stronger request, but do not submit yet
  const b = wrapped('https://app.example/strong');
  await vi.waitFor(() => expect(registrations).toBe(2));
  expect(traffic).toHaveLength(2);
  driver.submit();
  expect(await a).toBe(weakSuccess);
  const strongResult = await b;
  expect(strongResult).toBe(deniedStrong);
  expect(isUpgradeInsufficient(strongResult)).toBe(true);
  expect(isUpgradeInsufficient(weakSuccess)).toBe(false);
  await vi.waitFor(() => expect(controller.active).toBe(false));
  expect(summaries[0]).toMatchObject({
    terminal: 'insufficient',
    waiters: [
      { url: 'https://app.example/weak', outcome: 'replayed' },
      { url: 'https://app.example/strong', outcome: 'insufficient' },
    ],
  });
  expect(driver.requests).toHaveLength(1);
  expect(commits).toBe(1);

  // Caller retries only after the first flight has fully settled. Return a fresh challenge first.
  perUrl.set('https://app.example/strong', 0);
  const retry = wrapped('https://app.example/strong');
  await vi.waitFor(() => expect(driver.requests).toHaveLength(2));
  expect(driver.requests[1]!.challenge.requiredLevel).toBe(3);
  obtained = 3;
  driver.select(1);
  driver.submit(1);
  expect(await retry).toBe(strongSuccess);
  await vi.waitFor(() => expect(controller.active).toBe(false));
  expect(commits).toBe(2);
  expect(perUrl.get('https://app.example/weak')).toBe(2);
  expect(summaries[1]!.terminal).toBe('success');
});

test.each([2, 3])('REQ-62 REQ-103 C18d T-J5 replay-window join at level %i cannot open a second prompt', async (required) => {
  const driver = promptDriver();
  const replayEntered = deferred<void>();
  const release = deferred<void>();
  const controller = new UpgradeController({
    platform: createMockPlatform(),
    prompt: driver.prompt,
    transport: { prepare: async () => undefined, commit: async () => {} },
    readObtainedBar: () => ({ level: 2 }),
  });
  const visits = new Map<string, number>();
  const wrapped = upgradeFetch(
    async (input) => {
      const url = String(input);
      const visit = (visits.get(url) ?? 0) + 1;
      visits.set(url, visit);
      const level = url.endsWith('/third') ? required : 2;
      if (visit === 1)
        return challengeResponse(401, 'Bearer error="insufficient_user_authentication", acr_values="' + level + '"');
      if (url.endsWith('/first') || url.endsWith('/second')) {
        replayEntered.resolve();
        await release.promise;
      }
      return level > 2
        ? challengeResponse(401, 'Bearer error="insufficient_user_authentication", acr_values="3"')
        : new Response(url);
    },
    options({ elevate: (c, w) => controller.elevate(c, w), readObtainedBar: () => ({ level: 2 }) }),
  );
  const first = wrapped('https://app.example/first');
  const second = wrapped('https://app.example/second');
  await vi.waitFor(() => expect(driver.requests).toHaveLength(1));
  driver.select();
  driver.submit();
  await replayEntered.promise;
  expect(controller.currentState).toBe('replaying');

  const third = await wrapped('https://app.example/third');
  expect(third.ok).toBe(required === 2);
  expect(isUpgradeInsufficient(third)).toBe(required === 3);
  expect(driver.requests).toHaveLength(1);
  expect(controller.active).toBe(true); // first and second replays still pending
  release.resolve();
  expect((await first).ok).toBe(true);
  expect((await second).ok).toBe(true);
  await vi.waitFor(() => expect(controller.active).toBe(false));
  expect(driver.requests).toHaveLength(1);
});
