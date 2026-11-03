import { afterEach, describe, expect, test } from 'vitest';
import { PassflowEvent, totpFactor, UpgradeCommitInterruptedError, UpgradeSessionChangedError } from '../../lib/index';
import {
  BASE,
  errors,
  expectNoEnd,
  expectRefreshOrder,
  http,
  observe,
  type PublicTab,
  pair,
  successor,
  world,
} from './public-fixture';

const installations: (() => void)[] = [];
afterEach(() => {
  for (const disable of installations.splice(0)) disable();
});

export function enableProof(tab: PublicTab): void {
  let submitted = false;
  installations.push(
    tab.sdk.upgrade.enable({
      factors: [totpFactor],
      maxAttempts: 1,
      prompt: async (request) => {
        if (submitted) return { type: 'cancel' };
        submitted = true;
        request.onFactorSelected('totp');
        return { type: 'submit', factor: 'totp', code: '123456' };
      },
    }),
  );
}

function causes(error: unknown): unknown[] {
  const chain: unknown[] = [];
  for (let current = error; current && !chain.includes(current); ) {
    chain.push(current);
    current = typeof current === 'object' ? (current as { cause?: unknown }).cause : undefined;
  }
  return chain;
}

describe('step-up commit through the public upgrade facade', () => {
  test.each([
    { id: 'error.2fa.code.invalid', status: 401 },
    { id: 'error.token.blocked', status: 400 },
    { id: 'error.http.503', status: 503 },
    { id: 'error.qa.unrecognized_proof', status: 401 },
  ])('REQ-13 REQ-22 TEST-60 failed commit $id keeps tokens without refresh policy side effects', async ({ id, status }) => {
    const failure = http(id, status);
    const w = world(() => ({ error: failure }));
    const initial = pair(undefined, { expired: false });
    w.seed(initial);
    const a = w.open('A', { refreshStrikes: 1 });
    await w.ready();
    enableProof(a);
    const result = observe(a.sdk.upgrade());
    await w.run();
    expect(result.status).toBe('rejected');
    expect(w.requests).toHaveLength(1);
    expect(w.requests[0]).toMatchObject({
      token: initial.refresh_token,
      upgrade: { type: 'totp', assertion: { code: '123456' } },
    });
    expect(errors(a)).toEqual([expect.objectContaining({ operation: 'upgrade.commit', source: 'upgrade' })]);
    expect(errors(a)[0]?.refresh?.classification).toBeUndefined();
    expect(a.of(PassflowEvent.RefreshFailing)).toEqual([]);
    expect(a.of(PassflowEvent.RefreshRecovered)).toEqual([]);
    expect(a.sdk.getCachedTokens()).toEqual(initial);
    expect(await w.stored()).toEqual(initial);
    await w.run(120_000);
    expect(w.requests).toHaveLength(1);
    expectNoEnd(a);
  });

  test('REQ-15 REQ-22 TEST-61 commit adopts stored successor first but always sends proof with it', async () => {
    const w = world(() => 'hold', { watchStorage: false });
    const initial = pair(undefined, { expired: false });
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    const stored = successor(initial.refresh_token);
    w.seed(stored);
    enableProof(a);
    const result = observe(a.sdk.upgrade());
    await w.run();
    expect(w.requests.map((r) => r.token)).toEqual([stored.refresh_token]);
    expect(w.requests[0]?.upgrade).toEqual({ type: 'totp', assertion: { code: '123456' } });
    const issued = successor(stored.refresh_token);
    w.requests[0]!.resolve(issued);
    await w.run();
    expect(result).toMatchObject({ status: 'resolved', value: { status: 'elevated' } });
    expect(a.of(PassflowEvent.Refresh).map((e) => e.source)).toEqual(['adopted', 'upgrade']);
    expect(b.of(PassflowEvent.Refresh).map((e) => e.source)).toContain('adopted');
    expect(a.sdk.getCachedTokens()).toEqual(issued);
    expect(b.sdk.getCachedTokens()).toEqual(issued);
    expectRefreshOrder(a);
    expectRefreshOrder(b);
    expectNoEnd(a, b);
  });

  test('REQ-10 REQ-14 REQ-22 TEST-62 another tab commit yields out of backoff and immediately recovers all tabs', async () => {
    const w = world((request) => (request.upgrade ? 'success' : { error: http() }));
    w.seed(pair());
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run(20_000);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);
    enableProof(b);
    const commit = observe(b.sdk.upgrade());
    await w.run();
    expect(commit.status).toBe('resolved');
    expect(w.requests[4]).toMatchObject({ at: 20_000, upgrade: { type: 'totp' } });
    expect(b.of(PassflowEvent.Refresh).map((e) => e.source)).toContain('upgrade');
    expect(a.of(PassflowEvent.Refresh).map((e) => e.source)).toContain('adopted');
    expect(a.of(PassflowEvent.RefreshRecovered)).toEqual([{ since: BASE, origin: 'other-tab' }]);
    expect(b.of(PassflowEvent.RefreshRecovered)).toEqual([{ since: BASE, origin: 'this-tab' }]);
    await w.run(90_000);
    expect(w.requests).toHaveLength(5);
    expectNoEnd(a, b);
    // A new failure after the commit uses the first step, not the previous 60-second step.
    observe(a.sdk.refreshToken());
    await w.run();
    expect(errors(a)[errors(a).length - 1]?.refresh?.nextRetryAt).toBe(BASE + 111_000);
  });

  test('REQ-10 REQ-22 TEST-63 failed priority commit hands over the original nextAt and attempt count', async () => {
    const proofFailure = http('error.qa.wrong-proof', 401);
    const w = world((request) => ({ error: request.upgrade ? proofFailure : http() }));
    w.seed(pair());
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run(20_000);
    enableProof(b);
    const result = observe(b.sdk.upgrade());
    await w.run();
    expect(result.status).toBe('rejected');
    expect(w.requests[4]).toMatchObject({ at: 20_000, upgrade: { type: 'totp' } });
    await w.run(23_999);
    expect(w.requests).toHaveLength(5);
    await w.run(1);
    expect(w.requests[5]).toMatchObject({ at: 44_000, upgrade: undefined });
    expect(b.of(PassflowEvent.RefreshStart)).toHaveLength(2);
    expect(errors(b)[errors(b).length - 1]?.refresh?.nextRetryAt).toBe(BASE + 104_000);
    await w.run(60_000);
    expect(w.requests[6]).toMatchObject({ at: 104_000, upgrade: undefined });
    expectNoEnd(a, b);
  });

  test('REQ-22 TEST-64 commit waits for in-flight holder at most ten seconds without sending', async () => {
    const w = world(() => 'hold');
    w.seed(pair(undefined, { expired: false }));
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    enableProof(b);
    const result = observe(b.sdk.upgrade());
    await w.run(9_999);
    expect(result.status).toBe('pending');
    expect(w.requests).toHaveLength(1);
    await w.run(1);
    expect(result.status).toBe('rejected');
    const interrupted = causes(result.error).find((error) => error instanceof UpgradeCommitInterruptedError);
    expect(interrupted).toMatchObject({ reason: 'lock-timeout' });
    expect(w.requests).toHaveLength(1);
    expect(b.of(PassflowEvent.RefreshStart)).toEqual([]);
    expectNoEnd(a, b);
  });

  test.each(['same-lineage', 'new-user', 'new-session'] as const)(
    'REQ-22 TEST-65 commit cannot resolve adopted when storage moves to %s before answer',
    async (change) => {
      const w = world(() => 'hold', { mode: 'none' });
      const initial = pair(undefined, { expired: false });
      w.seed(initial);
      const a = w.open('A');
      await w.ready();
      enableProof(a);
      const result = observe(a.sdk.upgrade());
      await w.run();
      const current =
        change === 'same-lineage'
          ? successor(initial.refresh_token)
          : pair(undefined, {
              sub: change === 'new-user' ? 'new-user' : 'qa-user',
              sid: 'new-session',
              expired: false,
            });
      w.seed(current);
      w.requests[0]!.resolve(successor(initial.refresh_token, 20));
      await w.run();
      expect(result.status).toBe('rejected');
      if (change === 'same-lineage') {
        expect(
          causes(result.error).some((error) => error instanceof UpgradeCommitInterruptedError && error.reason === 'superseded'),
        ).toBe(true);
      } else {
        expect(causes(result.error).some((error) => error instanceof UpgradeSessionChangedError)).toBe(true);
      }
      expect(await w.stored()).toEqual(current);
      expect(a.of(PassflowEvent.Refresh).some((event) => event.source === 'upgrade')).toBe(false);
      expectNoEnd(a);
    },
  );
});
