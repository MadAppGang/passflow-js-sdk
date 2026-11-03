/**
 * PFL-792 acceptance scenarios (architecture §2.13, §9.3) on real `Passflow` instances as tabs.
 *
 * Shared storage, a per-tab fake coordinator on one virtual clock (random = 0), HTTP through
 * `vi.spyOn(AuthAPI.prototype, 'refreshToken')` (tests/refresh/sdk-tabs.ts). Logout (#8, #16) is
 * in sign-out.test.ts; new sign-ins after an end (A1) in session-started.test.ts.
 */
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { PassflowError } from '../../lib/api/model';
import { Passflow } from '../../lib/passflow';
import { PassflowRefreshError, RefreshErrorId, UpgradeCommitInterruptedError } from '../../lib/refresh';
import { StorageManager } from '../../lib/storage';
import { type ErrorPayload, PassflowEvent } from '../../lib/store';
import type { Tokens } from '../../lib/types';
import { TEST_CONFIG } from '../helpers/fixtures';
import {
  blocked,
  createSdkWorld,
  endsOf,
  httpError,
  invalid,
  networkError,
  OUTAGE_SCHEDULE,
  outage,
  pairOf,
  rateLimited,
  rotationOf,
  type SdkWorld,
  type Tab,
} from './sdk-tabs';

let world: SdkWorld | undefined;
const start = (answer?: Parameters<typeof createSdkWorld>[0]): SdkWorld => {
  world = createSdkWorld(answer);
  return world;
};

afterEach(() => {
  world?.dispose();
  world = undefined;
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const errorsOf = (tab: Tab) => tab.of<ErrorPayload>(PassflowEvent.Error);
const noEnds = (tab: Tab) => expect(endsOf(tab).map((e) => e.event)).toEqual([]);
const UPGRADE = { challenge_id: 'challenge-1', code: '123456' } as never;
const commit = (tab: Tab) =>
  (tab.passflow as unknown as { authService: { refreshToken: (u: unknown) => Promise<unknown> } }).authService.refreshToken(
    UPGRADE,
  );

type Adapter = (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>;
/** Stubs the user API's HTTP adapter of a tab, returning the configs it sent. */
const stubUserApi = (tab: Tab): InternalAxiosRequestConfig[] => {
  const sent: InternalAxiosRequestConfig[] = [];
  const client = (tab.passflow as unknown as { userApi: { axiosClient: { instance: { defaults: { adapter: Adapter } } } } })
    .userApi.axiosClient;
  client.instance.defaults.adapter = async (config) => {
    sent.push(config);
    return { data: [], status: 200, statusText: 'OK', headers: {}, config };
  };
  return sent;
};

describe('one refresh per browser (§2.13 #1)', () => {
  test('four tabs call refreshToken() together: one request, all resolve, tab 0 refreshes and tabs 1-3 adopt', async () => {
    const w = start();
    w.seed(pairOf());
    const tabs = ['t0', 't1', 't2', 't3'].map((id) => w.open(id));
    await w.ready();

    const calls = tabs.map((tab) => w.track(tab.passflow.refreshToken()));
    await w.run(1_000);

    expect(w.requests).toHaveLength(1);
    expect(w.requests[0]?.tab).toBe('t0');
    expect(calls.map((c) => c.status)).toEqual(['resolved', 'resolved', 'resolved', 'resolved']);
    const stored = w.stored();
    expect(stored?.refresh_token).not.toBe(w.requests[0]?.refreshToken);
    for (const call of calls) expect(call.value).toMatchObject({ refresh_token: stored?.refresh_token });
    for (const tab of tabs) expect(tab.passflow.getCachedTokens()?.refresh_token).toBe(stored?.refresh_token);

    expect(tabs[0]?.names()).toEqual([PassflowEvent.RefreshStart, PassflowEvent.Refresh, PassflowEvent.TokenCacheExpired]);
    expect(tabs[0]?.of(PassflowEvent.Refresh)[0]).toMatchObject({ source: 'refresh' });
    for (const tab of tabs.slice(1)) {
      expect(tab.names()).toEqual([PassflowEvent.Refresh, PassflowEvent.TokenCacheExpired]);
      expect(tab.of(PassflowEvent.Refresh)[0]).toMatchObject({ source: 'adopted' });
    }
    for (const tab of tabs) noEnds(tab);
  });
});

describe('a 3-minute 503 outage across two tabs (§2.13 #2)', () => {
  test('requests at 0, 1, 4, 14, 44, 104, 164 s from the holder only; tokens kept; one RefreshFailing per tab; a call at 50 s joins', async () => {
    const w = start((r) => (r.at < 180_000 ? { error: outage() } : 'rotate'));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    const before = w.snapshot();

    const firstA = w.track(a.passflow.refreshToken());
    const firstB = w.track(b.passflow.refreshToken());
    await w.run(50_000);
    expect(w.requests.map((r) => r.at)).toEqual(OUTAGE_SCHEDULE.slice(0, 5));

    // Holder's own call rejects with its request's error; the waiter's with error.refresh.unavailable.
    expect(firstA.status).toBe('rejected');
    expect(firstA.error).toBeInstanceOf(PassflowError);
    expect((firstA.error as PassflowError).status).toBe(503);
    expect((firstB.error as PassflowRefreshError).id).toBe(RefreshErrorId.unavailable);

    // t = 50 s: a refreshToken() in either tab sends nothing and settles with the 104 s attempt.
    const lateA = w.track(a.passflow.refreshToken());
    const lateB = w.track(b.passflow.refreshToken());
    await w.run(53_999);
    expect(lateA.status).toBe('pending');
    expect(lateB.status).toBe('pending');
    expect(w.requests).toHaveLength(5);
    await w.run(1);
    expect(lateA.status).toBe('rejected');
    expect(lateB.status).toBe('rejected');
    expect(lateA.at).toBe(104_000);
    expect(lateB.at).toBe(104_000);
    expect((lateB.error as PassflowRefreshError).id).toBe(RefreshErrorId.unavailable);
    expect((lateB.error as PassflowRefreshError).nextRetryAt).toBe(164_000);

    await w.run(75_999); // t = 179.999 s
    expect(w.requests.map((r) => r.at)).toEqual(OUTAGE_SCHEDULE);
    expect(w.sentBy(a)).toHaveLength(7);
    expect(w.sentBy(b)).toHaveLength(0);

    expect(w.snapshot()).toEqual(before);
    for (const tab of [a, b]) expect(tab.passflow.getCachedTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    expect(a.of(PassflowEvent.RefreshFailing)).toEqual([{ since: 0, nextRetryAt: 1_000, origin: 'this-tab' }]);
    expect(b.of(PassflowEvent.RefreshFailing)).toEqual([{ since: 0, nextRetryAt: 1_000, origin: 'other-tab' }]);
    expect(errorsOf(a)).toHaveLength(7);
    for (const error of errorsOf(a)) {
      expect(error).toMatchObject({ operation: 'refresh', refresh: { classification: 'transient', willRetry: true } });
    }
    expect(errorsOf(b)).toEqual([]);
    noEnds(a);
    noEnds(b);
    expect(w.postedTypes()).not.toContain('takeover');
  });
});

describe('recovery mid-wait (§2.13 #3)', () => {
  test('healthy from 120 s: nothing between 104 and 164 s, one success at 164 s recovers both tabs and every caller', async () => {
    const w = start((r) => (r.at >= 120_000 ? 'rotate' : { error: outage() }));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    w.track(a.passflow.refreshToken());
    w.track(b.passflow.refreshToken());
    await w.run(130_000);
    expect(w.requests.map((r) => r.at)).toEqual(OUTAGE_SCHEDULE.slice(0, 6));

    const pending = [
      w.track(a.passflow.getTokens(true)),
      w.track(b.passflow.getTokens(true)),
      w.track(b.passflow.refreshToken()),
      w.track(a.passflow.getTokensWithRefresh()),
    ];
    await w.run(33_999);
    expect(w.requests).toHaveLength(6);
    expect(pending.map((p) => p.status)).toEqual(['pending', 'pending', 'pending', 'pending']);
    await w.run(1);

    expect(w.requests.map((r) => r.at)).toEqual(OUTAGE_SCHEDULE);
    expect(pending.map((p) => p.status)).toEqual(['resolved', 'resolved', 'resolved', 'resolved']);
    const stored = w.stored();
    expect(pending[0]?.value).toMatchObject({ refresh_token: stored?.refresh_token });
    expect(pending[1]?.value).toMatchObject({ refresh_token: stored?.refresh_token });
    expect(pending[2]?.value).toMatchObject({ refresh_token: stored?.refresh_token });
    expect(a.of(PassflowEvent.Refresh).map((r) => r.source)).toEqual(['refresh']);
    expect(a.of(PassflowEvent.RefreshRecovered)).toEqual([{ since: 0, origin: 'this-tab' }]);
    expect(b.of(PassflowEvent.Refresh).map((r) => r.source)).toEqual(['adopted']);
    expect(b.of(PassflowEvent.RefreshRecovered)).toEqual([{ since: 0, origin: 'other-tab' }]);
    for (const tab of [a, b]) expect(tab.passflow.getCachedTokens()?.refresh_token).toBe(stored?.refresh_token);

    await w.run(600_000);
    expect(w.requests).toHaveLength(7);
    noEnds(a);
    noEnds(b);
  });
});

describe('holder closed mid-outage (§2.13 #4)', () => {
  test('the other tab takes the lock and sends its first request at the shared nextAt (44 s), not before', async () => {
    const w = start(() => ({ error: outage() }));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    w.track(a.passflow.refreshToken());
    await w.run();
    w.track(b.passflow.getTokensWithRefresh());
    await w.run(20_000);
    expect(w.sentBy(a).map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);

    w.kill(a);
    await w.run(23_999);
    expect(w.sentBy(b)).toEqual([]);
    await w.run(1);
    expect(w.sentBy(b).map((r) => r.at)).toEqual([44_000]);
    await w.run(60_000);
    expect(w.sentBy(b).map((r) => r.at)).toEqual([44_000, 104_000]);
    expect(b.of(PassflowEvent.RefreshFailing)).toHaveLength(1);
    expect(errorsOf(b)).toHaveLength(2);
    noEnds(b);
  });
});

describe('429 with Retry-After (§2.13 #5)', () => {
  test('Retry-After: 30 is shared: no attempt in any tab before 30 s, no takeover, then every tab adopts', async () => {
    const w = start((r) => (r.at === 0 ? { error: rateLimited(30) } : 'rotate'));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    w.track(a.passflow.refreshToken());
    await w.run();
    const callB = w.track(b.passflow.getTokens(true));
    await w.run(29_999);
    expect(w.requests).toHaveLength(1);
    expect(callB.status).toBe('pending');
    await w.run(1);

    expect(w.requests.map((r) => [r.tab, r.at])).toEqual([
      ['a', 0],
      ['a', 30_000],
    ]);
    expect(w.postedTypes()).not.toContain('takeover');
    expect(errorsOf(a)[0]).toMatchObject({
      operation: 'refresh',
      refresh: { classification: 'transient', willRetry: true, nextRetryAt: 30_000 },
    });
    expect(callB.status).toBe('resolved');
    expect(b.passflow.getCachedTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    expect(b.of(PassflowEvent.RefreshRecovered)).toEqual([{ since: 0, origin: 'other-tab' }]);
  });
});

describe('error.token.blocked never kills (§2.13 #6)', () => {
  test("no strike, storage untouched, nothing posted; another tab's broadcast within 20 s is adopted and callers resolve", async () => {
    const w = start((r) => (r.tab === 'a' ? { error: blocked() } : 'rotate'));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    await w.ready();
    const before = w.snapshot();

    const callA = w.track(a.passflow.getTokens(true));
    await w.run(2_000);
    expect(errorsOf(a)).toEqual([
      expect.objectContaining({
        operation: 'refresh',
        refresh: expect.objectContaining({ classification: 'blocked', willRetry: false, strikes: 0 }),
      }),
    ]);
    expect(w.snapshot()).toEqual(before);
    expect(w.hub.posted.filter((m) => m.from === 'a')).toEqual([]);
    expect(callA.status).toBe('pending');

    w.track(b.passflow.refreshToken());
    await w.run();
    expect(callA.status).toBe('resolved');
    expect(a.passflow.getCachedTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    expect(a.names()).toEqual([
      PassflowEvent.RefreshStart,
      PassflowEvent.Error,
      PassflowEvent.Refresh,
      PassflowEvent.TokenCacheExpired,
    ]);
    expect(a.of(PassflowEvent.Refresh)[0]).toMatchObject({ source: 'adopted' });
    await w.run(30_000);
    noEnds(a);
    noEnds(b);
  });

  test('with no successor within 20 s: SessionExpired{successor_timeout} in this tab only; storage and the other tab untouched', async () => {
    const w = start(() => ({ error: blocked() }));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    await w.ready();
    const before = w.snapshot();
    const cachedB = b.passflow.getCachedTokens();

    const callA = w.track(a.passflow.refreshToken());
    await w.run(19_999);
    expect(callA.status).toBe('pending');
    noEnds(a);
    await w.run(1);

    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
    expect(endsOf(a)[0]?.cached).toBeUndefined();
    expect((callA.error as PassflowRefreshError).id).toBe(RefreshErrorId.successorTimeout);
    expect(a.passflow.getCachedTokens()).toBeUndefined();
    expect(b.events).toEqual([]);
    expect(b.passflow.getCachedTokens()).toEqual(cachedB);
    expect(w.snapshot()).toEqual(before);
    expect(w.postedTypes()).not.toContain('session-ended');
    expect(w.requests).toHaveLength(1);
  });
});

describe('three auth strikes end every tab of the lineage (§2.13 #7)', () => {
  test.each([
    ['error.token.invalid.error', 400],
    ['error.not.found', 500],
  ])(
    '%s (%i): requests at 0, 1, 4 s; holder SessionExpired{this-tab}, storage deleted, other tab SessionExpired{other-tab}',
    async (id, status) => {
      const w = start(() => ({ error: httpError(id, status) }));
      w.seed(pairOf());
      const a = w.open('a');
      const b = w.open('b');
      const c = w.open('c');
      const dead = w.stored();
      w.track(a.passflow.refreshToken());
      await w.run();
      // B joins after A's first strike: it settles on A's next attempt (strikes left) with the kept tokens.
      const callB = w.track(b.passflow.getTokens(true));
      await w.run(10_000);

      expect(w.requests.map((r) => [r.tab, r.at])).toEqual([
        ['a', 0],
        ['a', 1_000],
        ['a', 4_000],
      ]);
      expect(errorsOf(a).map((e) => [e.refresh?.classification, e.refresh?.willRetry, e.refresh?.strikes])).toEqual([
        ['auth', true, 1],
        ['auth', true, 2],
        ['auth', false, 3],
      ]);
      expect(endsOf(a).map((e) => [e.event, e.payload, e.cached])).toEqual([
        [PassflowEvent.SessionExpired, { reason: 'refresh_failed', origin: 'this-tab' }, undefined],
      ]);
      for (const other of [b, c]) {
        expect(endsOf(other).map((e) => [e.event, e.payload, e.cached])).toEqual([
          [PassflowEvent.SessionExpired, { reason: 'refresh_failed', origin: 'other-tab' }, undefined],
        ]);
        expect(errorsOf(other)).toEqual([]);
      }
      expect(w.stored()).toBeUndefined();
      expect(callB.status).toBe('resolved');
      expect(callB.at).toBe(1_000);
      expect(callB.value).toMatchObject({ refresh_token: dead?.refresh_token });
      // After the end, getTokens(true) resolves undefined and sends nothing.
      expect(await b.passflow.getTokens(true)).toBeUndefined();

      await w.run(120_000);
      expect(w.requests).toHaveLength(3);
      for (const tab of [a, b, c]) expect(endsOf(tab)).toHaveLength(1);
    },
  );

  test('strikes count across a transient failure: invalid, 503, invalid, invalid ends at the fourth answer (§2.13 #12)', async () => {
    const answers = [invalid(), outage(), invalid(), invalid()];
    const w = start((r) => ({ error: answers[w.requests.indexOf(r)] ?? invalid() }));
    w.seed(pairOf());
    const a = w.open('a');
    w.track(a.passflow.refreshToken());
    await w.run(13_999);
    expect(w.requests).toHaveLength(3);
    noEnds(a);
    await w.run(1);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);
    expect(errorsOf(a).map((e) => e.refresh?.strikes)).toEqual([1, 1, 2, 3]);
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
  });
});

describe('compare-and-set save (§2.9.6)', () => {
  test('a 200 whose sent token storage no longer holds is not saved; the fresh caller resolves with the stored successor, no second request', async () => {
    const w = start(() => 'hold');
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    await w.ready();
    const call = w.track(a.passflow.refreshToken());
    await w.run();
    const sent = w.requests[0];
    // Another writer (an uncoordinated tab, a setTokens) stores a newer pair while A's request is out.
    const other = rotationOf(sent?.refreshToken ?? '');
    w.seed(other);
    await w.run();
    sent?.resolve(rotationOf(sent.refreshToken));
    await w.run(60_000);

    expect(w.stored()?.refresh_token).toBe(other.refresh_token);
    expect(call.status).toBe('resolved');
    expect(call.value).toMatchObject({ refresh_token: other.refresh_token });
    expect(w.requests).toHaveLength(1);
    expect(a.names()).toEqual([PassflowEvent.RefreshStart, PassflowEvent.Refresh, PassflowEvent.TokenCacheExpired]);
    expect(a.of(PassflowEvent.Refresh)[0]).toMatchObject({ source: 'adopted' });
    expect(b.passflow.getCachedTokens()?.refresh_token).toBe(other.refresh_token);
    noEnds(a);
    noEnds(b);
  });

  test('an auth failure after storage moved forward is superseded: no Error, no strike, the caller resolves', async () => {
    const w = start(() => 'hold');
    w.seed(pairOf());
    const a = w.open('a');
    await w.ready();
    const call = w.track(a.passflow.refreshToken());
    await w.run();
    const sent = w.requests[0];
    const other = rotationOf(sent?.refreshToken ?? '');
    w.seed(other);
    await w.run();
    sent?.reject(invalid());
    await w.run(60_000);

    expect(call.status).toBe('resolved');
    expect(call.value).toMatchObject({ refresh_token: other.refresh_token });
    expect(errorsOf(a)).toEqual([]);
    expect(w.requests).toHaveLength(1);
    expect(w.stored()?.refresh_token).toBe(other.refresh_token);
    noEnds(a);
  });
});

describe('a stuck holder and its late answer (§2.13 #9)', () => {
  test("a takeover steals from a silent holder; the stolen holder's late 200 is not saved", async () => {
    const w = start((r) => (r.tab === 'a' ? 'hold' : 'rotate'));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    w.track(a.passflow.refreshToken());
    await w.run();
    expect(w.sentBy(a)).toHaveLength(1);
    // A's page freezes mid-request: no heartbeat, no answer.
    w.clock.freeze('a');
    w.hub.freeze('a');

    const callB = w.track(b.passflow.refreshToken());
    await w.run(19_999);
    expect(w.sentBy(b)).toHaveLength(0);
    await w.run(1);
    expect(w.postedTypes()).toContain('takeover');
    expect(w.sentBy(b)).toHaveLength(1);
    expect(callB.status).toBe('resolved');
    const saved = w.stored();
    expect(saved?.refresh_token).toBe((callB.value as Tokens).refresh_token);

    // A thaws and its request finally answers with a rotation of the token it sent.
    w.clock.thaw('a');
    w.hub.thaw('a');
    w.sentBy(a)[0]?.resolve(rotationOf(w.sentBy(a)[0]?.refreshToken ?? ''));
    await w.run(1_000);

    expect(w.stored()).toEqual(saved);
    expect(a.passflow.getCachedTokens()?.refresh_token).toBe(saved?.refresh_token);
    expect(b.passflow.getCachedTokens()?.refresh_token).toBe(saved?.refresh_token);
    noEnds(a);
    noEnds(b);
  });
});

describe('upgrade commit (§2.13 #10, #11)', () => {
  test('a 401 rejects unchanged, keeps the tokens, one Error{upgrade.commit}, no SessionExpired, no RefreshFailing', async () => {
    const wrong = httpError('error.upgrade.code.invalid', 401);
    const w = start(() => ({ error: wrong }));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    await w.ready();
    const before = w.snapshot();

    const call = w.track(commit(a));
    await w.run(30_000);
    expect(call.error).toBe(wrong);
    expect(w.requests).toHaveLength(1);
    expect(w.requests[0]?.upgrade).toBe(UPGRADE);
    expect(w.snapshot()).toEqual(before);
    expect(a.passflow.getCachedTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    expect(errorsOf(a)).toEqual([expect.objectContaining({ operation: 'upgrade.commit', originalError: wrong })]);
    for (const tab of [a, b]) {
      expect(tab.names()).not.toContain(PassflowEvent.RefreshFailing);
      noEnds(tab);
    }
    expect(b.events).toEqual([]);
  });

  test('a successful commit: Refresh{upgrade} in the committing tab, Refresh{adopted} in the others', async () => {
    const w = start();
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    const call = w.track(commit(a));
    await w.run();
    expect(call.status).toBe('resolved');
    expect(a.of(PassflowEvent.Refresh).map((r) => r.source)).toEqual(['upgrade']);
    expect(b.of(PassflowEvent.Refresh).map((r) => r.source)).toEqual(['adopted']);
    expect(b.passflow.getCachedTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
  });

  test('a commit in the non-holder tab during an outage is sent at once; a 200 recovers both tabs', async () => {
    const w = start((r) => (r.upgrade !== undefined ? 'rotate' : { error: outage() }));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    w.track(a.passflow.getTokensWithRefresh());
    await w.run(20_000);
    expect(w.sentBy(a).map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);

    const call = w.track(commit(b));
    await w.run(10);
    expect(w.sentBy(b).map((r) => r.at)).toEqual([20_000]);
    expect(call.status).toBe('resolved');
    expect(b.of(PassflowEvent.RefreshRecovered)).toEqual([{ since: 0, origin: 'this-tab' }]);
    expect(a.of(PassflowEvent.RefreshRecovered)).toEqual([{ since: 0, origin: 'other-tab' }]);
    expect(a.passflow.getCachedTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    await w.run(120_000);
    expect(w.requests).toHaveLength(5);
  });

  test('a commit answered 401 during an outage: rejects unchanged and the next plain attempt still goes at 44 s', async () => {
    const wrong = httpError('error.upgrade.code.invalid', 401);
    const w = start((r) => ({ error: r.upgrade !== undefined ? wrong : outage() }));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    w.track(a.passflow.getTokensWithRefresh());
    await w.run(20_000);
    const call = w.track(commit(b));
    await w.run(10);
    expect(call.error).toBe(wrong);
    await w.run(23_989);
    expect(w.requests).toHaveLength(5);
    await w.run(1);
    expect(w.requests.at(-1)).toMatchObject({ tab: 'b', at: 44_000 });
    for (const tab of [a, b]) noEnds(tab);
  });

  test('a commit waiting more than 10 s behind a holder mid-request rejects UpgradeCommitInterruptedError{lock-timeout}', async () => {
    const w = start((r) => (r.upgrade === undefined ? 'hold' : 'rotate'));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    w.track(a.passflow.refreshToken());
    await w.run();
    const call = w.track(commit(b));
    await w.run(9_999);
    expect(call.status).toBe('pending');
    await w.run(1);
    expect(call.error).toBeInstanceOf(UpgradeCommitInterruptedError);
    expect((call.error as UpgradeCommitInterruptedError).reason).toBe('lock-timeout');
    expect(w.sentBy(b)).toEqual([]);
  });
});

describe('a revoked session ends tab by tab (§2.13 #13)', () => {
  test('each tab that needs a refresh sends once and ends 20 s later; storage keeps the dead pair; a new tab does the same', async () => {
    const w = start(() => ({ error: blocked() }));
    const dead = pairOf();
    w.seed(dead);
    const a = w.open('a');
    const b = w.open('b');
    const before = w.snapshot();

    w.track(a.passflow.getTokens(true));
    await w.run(5_000);
    w.track(b.passflow.getTokens(true));
    await w.run(15_000);
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
    noEnds(b);
    await w.run(5_000);
    expect(b.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
    expect(w.requests.map((r) => [r.tab, r.at])).toEqual([
      ['a', 0],
      ['b', 5_000],
    ]);
    expect(w.snapshot()).toEqual(before);

    const c = w.open('c');
    expect(c.passflow.getCachedTokens()?.refresh_token).toBe(dead.refresh_token);
    w.track(c.passflow.getTokensWithRefresh());
    await w.run(20_000);
    expect(w.sentBy(c)).toHaveLength(1);
    expect(c.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
    expect(w.snapshot()).toEqual(before);
    for (const tab of [a, b, c]) expect(endsOf(tab)).toHaveLength(1);
  });
});

describe('revival of an ended tab (§2.13 #14)', () => {
  test.each([
    ['the same user', 'user-1'],
    ['another user', 'user-2'],
  ])(
    "B ended by A's logOut; A signs in as %s: B emits SignIn{other-tab} with A's tokens and B's next refresh works",
    async (_label, sub) => {
      vi.spyOn(AuthAPI.prototype, 'logOut').mockResolvedValue({ status: 'ok' } as never);
      const w = start();
      w.seed(pairOf());
      const a = w.open('a');
      const b = w.open('b');

      const loggingOut = w.track(a.passflow.logOut());
      await w.run(3_000);
      expect(loggingOut.status).toBe('resolved');
      expect(b.of(PassflowEvent.SignOut)).toEqual([{ origin: 'other-tab', userId: 'user-1' }]);

      const next = pairOf(sub, { sid: 's2' });
      a.passflow.setTokens(next);
      await w.run();
      expect(b.of(PassflowEvent.SignIn)).toEqual([expect.objectContaining({ origin: 'other-tab' })]);
      expect((b.of(PassflowEvent.SignIn)[0] as { tokens?: Tokens }).tokens?.refresh_token).toBe(next.refresh_token);
      expect(b.passflow.getCachedTokens()?.refresh_token).toBe(next.refresh_token);

      const call = w.track(b.passflow.refreshToken());
      await w.run();
      expect(call.status).toBe('resolved');
      expect(w.sentBy(b).map((r) => r.refreshToken)).toEqual([next.refresh_token]);
      expect(a.passflow.getCachedTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    },
  );
});

describe('SDK API calls during an outage join the pending retry (pre-request)', () => {
  test('expired access tokens: API calls in both tabs send no refresh request of their own and reject with the attempt', async () => {
    const w = start(() => ({ error: outage() }));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    const sentA = stubUserApi(a);
    const sentB = stubUserApi(b);
    w.track(a.passflow.refreshToken());
    await w.run(2_000);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000]);

    const callsA = [w.track(a.passflow.getUserPasskeys()), w.track(a.passflow.getUserPasskeys())];
    const callsB = [w.track(b.passflow.getUserPasskeys()), w.track(b.passflow.getUserPasskeys())];
    await w.run(1_999);
    expect(w.requests).toHaveLength(2);
    for (const call of [...callsA, ...callsB]) expect(call.status).toBe('pending');
    await w.run(1);

    expect(w.requests.map((r) => [r.tab, r.at])).toEqual([
      ['a', 0],
      ['a', 1_000],
      ['a', 4_000],
    ]);
    for (const call of callsA) {
      expect(call.status).toBe('rejected');
      expect((call.error as PassflowError).status).toBe(503);
    }
    for (const call of callsB) {
      expect(call.status).toBe('rejected');
      expect((call.error as PassflowRefreshError).id).toBe(RefreshErrorId.unavailable);
    }
    expect(sentA).toEqual([]);
    expect(sentB).toEqual([]);
    for (const tab of [a, b]) {
      expect(tab.passflow.getCachedTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
      noEnds(tab);
    }
    // The waiting tab reports no refresh Error; the API call's own failure is reported once (one error object).
    expect(errorsOf(b).filter((e) => e.operation === 'refresh')).toEqual([]);
    expect(errorsOf(b)).toEqual([expect.objectContaining({ operation: 'passkey.list', originalError: callsB[0]?.error })]);
    expect(errorsOf(a).filter((e) => e.operation !== 'refresh')).toEqual([]);
  });

  test('a not-yet-expired access token during the outage: the call goes out at once with the current bearer, no extra request', async () => {
    const w = start(() => ({ error: outage() }));
    // Access token valid for 10 more s (inside the 30 s pre-request window).
    const tokens = pairOf();
    const soon = Math.floor(Date.now() / 1000) + 10;
    const access = tokens.access_token?.split('.') ?? [];
    const claims = JSON.parse(Buffer.from(access[1] ?? '', 'base64url').toString('utf-8')) as Record<string, unknown>;
    const nearExpiry = {
      ...tokens,
      access_token: `${access[0]}.${Buffer.from(JSON.stringify({ ...claims, exp: soon })).toString('base64url')}.sig`,
    };
    w.seed(nearExpiry);
    const a = w.open('a');
    const b = w.open('b');
    const sentB = stubUserApi(b);
    w.track(a.passflow.refreshToken());
    await w.run(500);

    await b.passflow.getUserPasskeys();
    await b.passflow.getUserPasskeys();
    expect(sentB.map((c) => c.headers?.Authorization)).toEqual([
      `Bearer ${nearExpiry.access_token}`,
      `Bearer ${nearExpiry.access_token}`,
    ]);
    expect(w.requests).toHaveLength(1);
  });
});

describe("fallback 'none' (§2.11, R9)", () => {
  const seedLocal = (tokens: Tokens) => new StorageManager({ storage: localStorage }).saveTokens(tokens);
  const openLocal = (config: Record<string, unknown> = {}) => {
    const passflow = new Passflow({ ...TEST_CONFIG, ...config });
    const events: { event: PassflowEvent; payload: unknown }[] = [];
    passflow.subscribe({ onAuthChange: (event, payload) => events.push({ event, payload }) });
    return { passflow, events };
  };

  test('a browser page lacking navigator.locks: each tab retries on its own, the save checks keep the newer pair, one warning per instance', async () => {
    vi.useFakeTimers({ now: 0 });
    vi.spyOn(Math, 'random').mockReturnValue(0);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    expect((globalThis.navigator as { locks?: unknown }).locks).toBeUndefined();
    localStorage.clear();
    seedLocal(pairOf());

    const held: { at: number; token: string; resolve: (t: Tokens) => void; reject: (e: unknown) => void }[] = [];
    vi.spyOn(AuthAPI.prototype, 'refreshToken').mockImplementation(
      (token: string) =>
        new Promise((resolve, reject) => {
          held.push({ at: Date.now(), token, resolve: (t) => resolve({ ...t } as never), reject });
        }) as never,
    );
    const a = openLocal();
    const b = openLocal();
    expect(warn).not.toHaveBeenCalled();
    try {
      // Both tabs refresh on their own (no coordination): two requests with the same stored token.
      const callA = a.passflow.refreshToken().catch((error: unknown) => error);
      const callB = b.passflow.refreshToken().catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(0);
      expect(held.map((h) => h.at)).toEqual([0, 0]);
      expect(held[0]?.token).toBe(held[1]?.token);
      expect(warn.mock.calls.map((c) => c[0])).toEqual([
        expect.stringMatching(/^\[passflow\]/),
        expect.stringMatching(/^\[passflow\]/),
      ]);

      // B's answer lands first and is saved; A's later answer for the same sent token is not (CAS).
      const fromB = rotationOf(held[1]?.token ?? '');
      held[1]?.resolve(fromB);
      await vi.advanceTimersByTimeAsync(0);
      held[0]?.resolve(rotationOf(held[0]?.token ?? ''));
      await vi.advanceTimersByTimeAsync(0);
      expect(new StorageManager({ storage: localStorage }).getTokens()?.refresh_token).toBe(fromB.refresh_token);
      expect(await callB).toMatchObject({ refresh_token: fromB.refresh_token });
      expect(await callA).toMatchObject({ refresh_token: fromB.refresh_token });
      expect(
        a.events.filter((e) => e.event === PassflowEvent.Refresh).map((e) => (e.payload as { source: string }).source),
      ).toEqual(['adopted']);

      // An outage: each instance keeps its own schedule (single-tab retries), tokens kept.
      const failing = a.passflow.refreshToken().catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(0);
      held.at(-1)?.reject(outage());
      expect(await failing).toBeInstanceOf(PassflowError);
      await vi.advanceTimersByTimeAsync(999);
      expect(held).toHaveLength(3);
      await vi.advanceTimersByTimeAsync(1);
      expect(held).toHaveLength(4);
      expect(held.at(-1)?.at).toBe(1_000);
      expect(a.events.filter((e) => e.event === PassflowEvent.RefreshFailing)).toHaveLength(1);
      expect(b.events.filter((e) => e.event === PassflowEvent.RefreshFailing)).toHaveLength(0);
      expect(a.passflow.getCachedTokens()?.refresh_token).toBe(fromB.refresh_token);
      expect(warn).toHaveBeenCalledTimes(2);
    } finally {
      a.passflow.dispose();
      b.passflow.dispose();
    }
  });

  test("explicit 'none' writes no warning", async () => {
    vi.useFakeTimers({ now: 0 });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    localStorage.clear();
    seedLocal(pairOf());
    vi.spyOn(AuthAPI.prototype, 'refreshToken').mockImplementation(async (token: string) => rotationOf(token) as never);
    const a = openLocal({ refreshCoordination: 'none' });
    try {
      await a.passflow.refreshToken();
      expect(warn).not.toHaveBeenCalled();
    } finally {
      a.passflow.dispose();
    }
  });
});

describe('network failures are transient', () => {
  test('a network error keeps the tokens and retries on the schedule', async () => {
    const w = start(() => ({ error: networkError() }));
    w.seed(pairOf());
    const a = w.open('a');
    w.track(a.passflow.refreshToken());
    await w.run(14_000);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);
    expect(a.passflow.getCachedTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    noEnds(a);
  });
});

describe('classification table on a single tab (§2.13 #15)', () => {
  test.each([
    ['row 1: error.token.blocked', () => httpError('error.token.blocked', 400), 'blocked', false, 'successor_timeout'],
    ['row 2: error.token.invalid.error 400', () => httpError('error.token.invalid.error', 400), 'auth', true, 'refresh_failed'],
    [
      'row 2: error.api.token.parse.error 400',
      () => httpError('error.api.token.parse.error', 400),
      'auth',
      true,
      'refresh_failed',
    ],
    ['row 2: error.api.user.blocked 403', () => httpError('error.api.user.blocked', 403), 'auth', true, 'refresh_failed'],
    ['row 2: error.2fa.required_by_app 400', () => httpError('error.2fa.required_by_app', 400), 'auth', true, 'refresh_failed'],
    [
      'row 2: error.validation.token.invalid.subject 500',
      () => httpError('error.validation.token.invalid.subject', 500),
      'auth',
      true,
      'refresh_failed',
    ],
    ['row 2: error.not.found 500', () => httpError('error.not.found', 500), 'auth', true, 'refresh_failed'],
    ['row 3: 429', () => rateLimited(1), 'transient', true, undefined],
    ['row 4: network', networkError, 'transient', true, undefined],
    ['row 5: unknown id 503', () => httpError('error.something', 503), 'transient', true, undefined],
    ['row 6: unknown id 404', () => httpError('error.something', 404), 'auth', true, 'refresh_failed'],
  ] as const)('%s → %s', async (_row, error, classification, willRetry, endReason) => {
    const w = start(() => ({ error: error() }));
    w.seed(pairOf());
    const a = w.open('a');
    w.track(a.passflow.refreshToken());
    await w.run();
    expect(errorsOf(a)[0]).toMatchObject({ operation: 'refresh', refresh: { classification, willRetry, maxStrikes: 3 } });

    await w.run(60_000);
    if (endReason) {
      expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: endReason, origin: 'this-tab' }]);
      expect(w.requests).toHaveLength(classification === 'blocked' ? 1 : 3);
    } else {
      noEnds(a);
      expect(w.requests.length).toBeGreaterThan(3);
    }
  });
});

describe('subscribe() after load (reported by the portal review)', () => {
  test('a held tab keeps its newer cached pair through later subscribe() calls', async () => {
    const w = start();
    const older = pairOf('user-1', { fresh: true });
    w.seed(older);
    const a = w.open('A');
    await w.ready();

    const newer = rotationOf(older.refresh_token ?? '');
    a.passflow.setTokens(newer);
    // Storage moves back to the older pair of the same session: the tab is held.
    w.seed(older);

    a.passflow.subscribe(() => undefined);
    a.passflow.subscribe(() => undefined, [PassflowEvent.Refresh]);

    expect(a.passflow.getCachedTokens()).toEqual(newer);
  });

  test('repeated subscribe() with an expired access token reports the expiry once', async () => {
    const w = start('hold');
    w.seed(pairOf('user-1'));
    const a = w.open('A');
    await w.ready();

    a.passflow.subscribe(() => undefined);
    a.passflow.subscribe(() => undefined);
    a.passflow.subscribe(() => undefined);

    expect(a.of(PassflowEvent.TokenCacheExpired)).toEqual([]);
  });
});
