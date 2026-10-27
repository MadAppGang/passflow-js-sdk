// @vitest-environment node
import { describe, expect, test, vi } from 'vitest';
import type { AssuranceBar } from '../../lib/upgrade/challenge';
import { UpgradeController, barMeets } from '../../lib/upgrade/controller';
import type { UpgradeFlightSummary } from '../../lib/upgrade/controller';
import { isUpgradeInsufficient } from '../../lib/upgrade/core';
import { UpgradeTransportError } from '../../lib/upgrade/errors';
import { createUpgradeFacade } from '../../lib/upgrade/facade';
import { upgradeFetch } from '../../lib/upgrade/fetch-adapter';
import { createMockPlatform } from '../helpers/mock-platform';
import { challengeResponse, options } from './fetch-fixtures';
import { challenge, observed, promptDriver } from './pass2-fixtures';

function fixture(obtained: AssuranceBar = { level: 2, acrValues: '2' }) {
  const driver = promptDriver();
  const summaries: UpgradeFlightSummary[] = [];
  const commits: unknown[] = [];
  const controller = new UpgradeController({
    platform: createMockPlatform(),
    prompt: driver.prompt,
    factors: [
      { type: 'totp', requiresPrepare: false, input: 'code', assert: async ({ code }) => ({ code }) },
      { type: 'passkey', requiresPrepare: false, input: 'none', assert: async () => ({}) },
    ],
    transport: {
      prepare: async () => undefined,
      commit: async (factor, assertion) => {
        commits.push({ factor, assertion });
      },
    },
    readObtainedBar: () => obtained,
    onFlightSettled: (summary) => {
      summaries.push(summary);
    },
  });
  return { controller, driver, summaries, commits };
}
const request = (name: string) => ({ kind: 'request' as const, url: 'https://app.example/' + name, method: 'GET' });

describe('UNKNOWN assurance is not authorization', () => {
  test.each([{}, { acrValues: 'opaque' }, { maxAge: 10 }])(
    'REQ-56 REQ-98 C42 T-S7 barMeets(%j, level 2) is false',
    (obtained) => {
      expect(barMeets(obtained, { level: 2, acrValues: '2' })).toBe(false);
    },
  );

  test('REQ-56 REQ-98 C42 T-S7 UNKNOWN still attempts elevation and server replay decides insufficient', async () => {
    const f = fixture({});
    const responses = [challengeResponse(), challengeResponse()];
    let sent = 0;
    const wrapped = upgradeFetch(
      async () => responses[sent++],
      options({
        elevate: (c, w) => f.controller.elevate(c, w),
        readObtainedBar: () => ({}),
      }),
    );
    const result = wrapped('https://app.example/private');
    await vi.waitFor(() => expect(f.driver.requests).toHaveLength(1));
    f.driver.select();
    f.driver.submit();

    const response = await result;
    expect(response).toBe(responses[1]);
    expect(response.ok).toBe(false);
    expect(response.bodyUsed).toBe(false);
    expect(isUpgradeInsufficient(response)).toBe(true);
    expect(sent).toBe(2);
    expect(f.commits).toHaveLength(1);
    await vi.waitFor(() => expect(f.summaries).toHaveLength(1));
    expect(f.summaries[0]).toMatchObject({
      terminal: 'insufficient',
      waiters: [{ outcome: 'insufficient', required: { level: 2 } }],
    });
    expect(f.controller.currentState).toBe('idle');
  });
});

describe('joining and replay settlement', () => {
  test('REQ-6 REQ-31 C17 ten concurrent waiters share one proof and remain active until all report', async () => {
    const f = fixture();
    const pending = Array.from({ length: 10 }, (_, i) => f.controller.elevate(challenge(), request(String(i))));
    await vi.waitFor(() => expect(f.driver.requests).toHaveLength(1));
    f.driver.select();
    f.driver.submit();
    const entries = await Promise.all(pending);
    expect(new Set(entries.map((e) => e.waiter)).size).toBe(10);
    expect(f.commits).toHaveLength(1);
    expect(f.controller.currentState).toBe('replaying');
    entries.slice(0, 9).forEach((e) => e.waiter.report({ outcome: 'replayed' }));
    expect(f.controller.active).toBe(true);
    expect(f.summaries).toEqual([]);
    entries[9].waiter.report({ outcome: 'replayed' });

    await vi.waitFor(() => expect(f.controller.currentState).toBe('idle'));
    expect(f.summaries).toHaveLength(1);
    expect(f.summaries[0].terminal).toBe('success');
    expect(f.summaries[0].waiters).toHaveLength(10);
    expect(f.summaries[0].waiters.every((w) => w.outcome === 'replayed')).toBe(true);
  });

  test('REQ-32 REQ-99 C18 T-J1 pre-selection stronger join raises and reranks the same prompt', async () => {
    const f = fixture({ level: 3, acrValues: '3' });
    const a = f.controller.elevate(challenge(2), request('a'));
    await vi.waitFor(() => expect(f.driver.requests).toHaveLength(1));
    const raised: { challenge: ReturnType<typeof challenge>; factors: readonly { type: string }[] }[] = [];
    f.driver.requests[0].onRequirementRaised = (next) => {
      raised.push(next);
    };
    const b = f.controller.elevate(challenge(3), request('b'));
    await vi.waitFor(() => expect(raised).toHaveLength(1));
    expect(raised[0].challenge.requiredLevel).toBe(3);
    expect(raised[0].factors[0].type).toBe('passkey');
    expect(f.driver.requests).toHaveLength(1);
    f.driver.select(0, 'passkey');
    f.driver.submit(0, 'passkey');
    const entries = await Promise.all([a, b]);
    entries.forEach((e) => e.waiter.report({ outcome: 'replayed' }));
    await vi.waitFor(() => expect(f.controller.active).toBe(false));
    expect(f.commits).toHaveLength(1);
    expect(f.summaries[0].terminal).toBe('success');
  });

  test('REQ-59 REQ-63 REQ-66 REQ-100 C18a C18e C24a T-J2 selected-but-unsubmitted never reranks; mixed results stay per-waiter', async () => {
    const f = fixture();
    const a = f.controller.elevate(challenge(2), request('a'));
    await vi.waitFor(() => expect(f.driver.requests).toHaveLength(1));
    const raised: unknown[] = [];
    f.driver.requests[0].onRequirementRaised = (next) => {
      raised.push(next);
    };
    f.driver.select(); // selection, not submission, is the boundary
    const b = f.controller.elevate(challenge(3), request('b'));
    expect(f.controller.currentState).toBe('proving');
    expect(raised).toEqual([]);
    expect(f.driver.requests).toHaveLength(1);
    expect(f.commits).toEqual([]);
    f.driver.submit();
    const [ea, eb] = await Promise.all([a, b]);
    expect(raised).toEqual([]);
    ea.waiter.report({ outcome: 'replayed' });
    eb.waiter.report({ outcome: 'insufficient', obtained: { level: 2 }, required: { level: 3 } });
    await vi.waitFor(() => expect(f.controller.currentState).toBe('idle'));

    expect(f.summaries[0]).toMatchObject({
      terminal: 'insufficient',
      waiters: [
        { url: 'https://app.example/a', outcome: 'replayed' },
        { url: 'https://app.example/b', outcome: 'insufficient', obtained: { level: 2 }, required: { level: 3 } },
      ],
    });
    expect(f.commits).toHaveLength(1);
  });

  test('REQ-62 REQ-103 C18d T-J5 replay-window request joins without a new prompt or commit', async () => {
    const f = fixture();
    const first = f.controller.elevate(challenge(2), request('a'));
    await vi.waitFor(() => expect(f.driver.requests).toHaveLength(1));
    f.driver.select();
    f.driver.submit();
    const a = await first;
    expect(f.controller.currentState).toBe('replaying');
    const b = await f.controller.elevate(challenge(2), request('b'));
    expect(f.driver.requests).toHaveLength(1);
    expect(f.commits).toHaveLength(1);
    expect(b.obtained).toMatchObject({ level: 2 });
    expect(f.summaries).toEqual([]);
    a.waiter.report({ outcome: 'replayed' });
    b.waiter.report({ outcome: 'replayed' });
    await vi.waitFor(() => expect(f.controller.active).toBe(false));
    expect(f.summaries[0].waiters).toHaveLength(2);
  });

  test('REQ-102 T-J4 after final settlement a stronger request opens a fresh flight', async () => {
    const f = fixture();
    const first = f.controller.elevate(challenge(2), request('a'));
    await vi.waitFor(() => expect(f.driver.requests).toHaveLength(1));
    f.driver.select();
    f.driver.submit();
    (await first).waiter.report({ outcome: 'replayed' });
    await vi.waitFor(() => expect(f.controller.currentState).toBe('idle'));
    const second = observed(f.controller.elevate(challenge(3), request('b')));
    await vi.waitFor(() => expect(f.driver.requests).toHaveLength(2));
    expect(f.driver.requests[1].challenge.requiredLevel).toBe(3);
    f.driver.cancel(1);
    expect(await second).toMatchObject({ ok: false, error: { code: 'upgrade_cancelled' } });
    await vi.waitFor(() => expect(f.controller.active).toBe(false));
  });

  test('REQ-67 REQ-69 REQ-104 C24b C24d T-J6 only the imperative waiter with an unmet stated bar rejects', async () => {
    const driver = promptDriver();
    const facade = createUpgradeFacade({
      platform: createMockPlatform(),
      passflowDomain: null,
      canCommit: () => ({ ok: true }),
      startUpgrade: async () => {
        throw new Error('TOTP prepare');
      },
      commitRefresh: async () => {},
      readObtainedBar: () => ({ level: 2, acrValues: '2' }),
    });
    const disable = facade.enable({ prompt: driver.prompt, interceptFetch: false });
    try {
      const plain = observed(facade());
      await vi.waitFor(() => expect(driver.requests).toHaveLength(1));
      driver.select();
      const stronger = observed(facade({ acrValues: '3' }));
      driver.submit();
      expect(await stronger).toMatchObject({
        ok: false,
        error: { code: 'upgrade_insufficient', obtained: { level: 2 }, required: { level: 3 } },
      });
      expect(await plain).toMatchObject({ ok: true, value: { status: 'elevated' } });
      expect(driver.requests).toHaveLength(1);
    } finally {
      disable();
    }
  });

  test('REQ-12 REQ-60 REQ-101 C18b T-J3 retry gets fresh prepare ids and a fresh attempt budget', async () => {
    const driver = promptDriver();
    const summaries: UpgradeFlightSummary[] = [];
    let nextChallenge = 0;
    const spent: string[] = [];
    let fail = true;
    const controller = new UpgradeController({
      platform: createMockPlatform(),
      prompt: driver.prompt,
      maxAttempts: 2,
      // A contract-conforming custom factor makes challenge consumption observable without WebAuthn.
      factors: [
        {
          type: 'passkey',
          requiresPrepare: true,
          input: 'none',
          assert: async ({ prepared }) => ({ challenge_id: prepared!.challengeId }),
        },
      ],
      transport: {
        prepare: async () => ({
          challengeId: 'challenge-' + ++nextChallenge,
          method: 'passkey',
          expiresAt: '2099-01-01T00:00:00Z',
        }),
        commit: async (_factor, assertion) => {
          spent.push(assertion.challenge_id!);
          if (fail) throw new UpgradeTransportError({ kind: 'wrong_code', status: 401 });
        },
      },
      readObtainedBar: () => ({ level: 3 }),
      onFlightSettled: (summary) => {
        summaries.push(summary);
      },
    });
    const exhausted = observed(controller.elevate(challenge(2), request('a')));
    for (let i = 0; i < 2; i++) {
      await vi.waitFor(() => expect(driver.requests).toHaveLength(i + 1));
      driver.select(i, 'passkey');
      driver.submit(i, 'passkey');
    }
    expect(await exhausted).toMatchObject({ ok: false, error: { code: 'upgrade_transport' } });
    await vi.waitFor(() => expect(controller.active).toBe(false));
    fail = false;
    const retry = controller.elevate(challenge(3), request('retry'));
    await vi.waitFor(() => expect(driver.requests).toHaveLength(3));
    expect(driver.requests[2].previousError).toBeUndefined();
    driver.select(2, 'passkey');
    driver.submit(2, 'passkey');
    (await retry).waiter.report({ outcome: 'replayed' });
    await vi.waitFor(() => expect(controller.active).toBe(false));
    expect(spent).toEqual(['challenge-1', 'challenge-2', 'challenge-3']);
    expect(summaries).toHaveLength(2);
    expect(summaries[1].terminal).toBe('success');
  });
});
