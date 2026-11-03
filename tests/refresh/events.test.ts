/**
 * Exact per-tab event sequences on real `Passflow` tabs (PFL-792 architecture §2.4, §2.5).
 *
 * Re-records the portal's `passflow-events.sdk.test.ts` against the new contract: one `Error` per
 * failure with an `operation` (and, for refreshes, `source` and `refresh`), `Refresh.source`,
 * the token cache already updated when `Refresh` fires and already cleared when `SignOut` or
 * `SessionExpired` fires, and `RefreshFailing`/`RefreshRecovered` once per episode.
 */
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { PassflowEvent } from '../../lib/store';
import type { Tokens } from '../../lib/types';
import {
  blocked,
  createSdkWorld,
  invalid,
  outage,
  pairOf,
  type RecordedEvent,
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
  vi.restoreAllMocks();
});

const E = PassflowEvent;
/** [event, payload] pairs with token payloads reduced to the refresh token, for exact sequences. */
const sequence = (tab: Tab): [PassflowEvent, unknown][] =>
  tab.events.map(({ event, payload }) => {
    if (event === E.Refresh || event === E.SignIn) {
      const { tokens, parsedTokens, ...rest } = payload as { tokens?: Tokens; parsedTokens?: unknown };
      return [event, { ...rest, refresh_token: tokens?.refresh_token, parsed: parsedTokens !== undefined }];
    }
    if (event === E.Error) {
      const { message, originalError, ...rest } = payload as { message?: string; originalError?: unknown };
      return [event, { ...rest, message: typeof message }];
    }
    return [event, payload];
  });
const at = (tab: Tab, event: PassflowEvent): RecordedEvent[] => tab.events.filter((e) => e.event === event);

type Adapter = (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>;
const stubUserApi = (tab: Tab): void => {
  const client = (tab.passflow as unknown as { userApi: { axiosClient: { instance: { defaults: { adapter: Adapter } } } } })
    .userApi.axiosClient;
  client.instance.defaults.adapter = async (config) => ({ data: [], status: 200, statusText: 'OK', headers: {}, config });
};

describe('a successful refresh', () => {
  test('holder: RefreshStart, Refresh{refresh}, TokenCacheExpired{false}; other tab: Refresh{adopted}, TokenCacheExpired{false}; the cache is already updated', async () => {
    const w = start();
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    await w.ready();

    await Promise.all([a.passflow.refreshToken(), w.run()]);
    await w.run();
    const next = w.stored()?.refresh_token;

    expect(sequence(a)).toEqual([
      [E.RefreshStart, {}],
      [E.Refresh, { source: 'refresh', refresh_token: next, parsed: true }],
      [E.TokenCacheExpired, { isExpired: false }],
    ]);
    expect(sequence(b)).toEqual([
      [E.Refresh, { source: 'adopted', refresh_token: next, parsed: true }],
      [E.TokenCacheExpired, { isExpired: false }],
    ]);
    for (const tab of [a, b]) {
      const refresh = at(tab, E.Refresh)[0];
      expect(refresh?.cached?.refresh_token).toBe(next);
      expect(tab.passflow.getParsedTokens()?.refresh_token).toBeDefined();
    }
  });
});

describe('a transient episode', () => {
  test('exact sequences through two 503s and the recovery, in the holder, a waiting tab and an idle tab', async () => {
    const w = start((r) => (r.at < 4_000 ? { error: outage() } : 'rotate'));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    const c = w.open('c');
    await w.ready();
    const before = w.stored()?.refresh_token;

    w.track(a.passflow.refreshToken());
    await w.run();
    w.track(b.passflow.getTokens(true));
    await w.run(4_000);
    const next = w.stored()?.refresh_token;
    expect(next).not.toBe(before);

    const transient = (source: string, nextRetryAt: number) => [
      E.Error,
      {
        operation: 'refresh',
        source,
        code: 'error.http.503',
        message: 'string',
        refresh: { classification: 'transient', willRetry: true, nextRetryAt, strikes: 0, maxStrikes: 3 },
      },
    ];
    expect(sequence(a)).toEqual([
      [E.RefreshStart, {}],
      transient('refresh-token', 1_000),
      [E.RefreshFailing, { since: 0, nextRetryAt: 1_000, origin: 'this-tab' }],
      [E.RefreshStart, {}],
      transient('retry', 4_000),
      [E.RefreshStart, {}],
      [E.Refresh, { source: 'refresh', refresh_token: next, parsed: true }],
      [E.TokenCacheExpired, { isExpired: false }],
      [E.RefreshRecovered, { since: 0, origin: 'this-tab' }],
    ]);
    // Waiting and idle tabs: no Error, one RefreshFailing, then the adoption and one RefreshRecovered.
    for (const tab of [b, c]) {
      expect(sequence(tab)).toEqual([
        [E.RefreshFailing, { since: 0, nextRetryAt: 1_000, origin: 'other-tab' }],
        [E.Refresh, { source: 'adopted', refresh_token: next, parsed: true }],
        [E.TokenCacheExpired, { isExpired: false }],
        [E.RefreshRecovered, { since: 0, origin: 'other-tab' }],
      ]);
    }
    // While failing, every tab kept its tokens.
    for (const tab of [a, b, c]) expect(at(tab, E.RefreshFailing)[0]?.cached?.refresh_token).toBe(before);
  });

  test('one Error per failure: the rejected refreshToken(), getTokens(true) and an API call add none of their own', async () => {
    const w = start(() => ({ error: outage() }));
    w.seed(pairOf());
    const a = w.open('a');
    stubUserApi(a);
    await w.ready();

    const first = w.track(a.passflow.refreshToken());
    await w.run();
    const failure = first.error;
    expect(failure).toBeDefined();
    // Both join the retry pending at 1 s and settle with that attempt.
    const session = w.track(a.passflow.getTokens(true));
    const call = w.track(a.passflow.getUserPasskeys());
    await w.run(1_000);
    expect(session.value).toMatchObject({ refresh_token: w.stored()?.refresh_token });
    expect(call.status).toBe('rejected');
    const retryError = at(a, E.Error)[1]?.payload as { originalError?: unknown } | undefined;
    expect(call.error).toBe(retryError?.originalError);

    const errors = at(a, E.Error).map((e) => e.payload as { operation?: string; originalError?: unknown; source?: string });
    expect(errors.map((e) => [e.operation, e.source])).toEqual([
      ['refresh', 'refresh-token'],
      ['refresh', 'retry'],
    ]);
    expect(errors[0]?.originalError).toBe(failure);
    expect(at(a, E.RefreshFailing)).toHaveLength(1);
  });
});

describe('Error.source names the trigger', () => {
  test.each([
    ['refresh-token', (tab: Tab) => tab.passflow.refreshToken()],
    ['session', (tab: Tab) => tab.passflow.getTokens(true)],
    ['token-check', (tab: Tab) => tab.passflow.getTokensWithRefresh()],
    ['pre-request', (tab: Tab) => tab.passflow.getUserPasskeys()],
  ])('%s', async (source, trigger) => {
    const w = start(() => ({ error: outage() }));
    w.seed(pairOf());
    const a = w.open('a');
    stubUserApi(a);
    await w.ready();
    w.track(trigger(a));
    await w.run();
    expect(at(a, E.Error).map((e) => e.payload)).toEqual([
      expect.objectContaining({ operation: 'refresh', source, code: 'error.http.503' }),
    ]);
  });

  test('upgrade: a failed commit reports operation upgrade.commit, source upgrade, and no refresh info', async () => {
    const wrong = new Error('wrong code');
    const w = start(() => ({ error: wrong }));
    w.seed(pairOf());
    const a = w.open('a');
    await w.ready();
    const commit = (
      a.passflow as unknown as { authService: { refreshToken: (u: unknown) => Promise<unknown> } }
    ).authService.refreshToken({ challenge_id: 'c', code: '1' });
    w.track(commit);
    await w.run();
    expect(sequence(a)).toEqual([
      [E.RefreshStart, {}],
      [E.Error, expect.objectContaining({ operation: 'upgrade.commit', source: 'upgrade', message: 'string' })],
    ]);
  });
});

describe('a superseded request', () => {
  test('RefreshStart, Refresh{adopted}, TokenCacheExpired: no Error, the stored pair is the outcome', async () => {
    const w = start(() => 'hold');
    w.seed(pairOf());
    const a = w.open('a');
    await w.ready();
    w.track(a.passflow.refreshToken());
    await w.run();
    const sent = w.requests[0];
    const other = rotationOf(sent?.refreshToken ?? '');
    w.seed(other);
    sent?.resolve(rotationOf(sent.refreshToken));
    await w.run();
    expect(sequence(a)).toEqual([
      [E.RefreshStart, {}],
      [E.Refresh, { source: 'adopted', refresh_token: other.refresh_token, parsed: true }],
      [E.TokenCacheExpired, { isExpired: false }],
    ]);
  });
});

describe('session ends', () => {
  test('last auth strike: Error{auth, willRetry:false, strikes:3}, then SessionExpired{refresh_failed} with the cache cleared, in every tab', async () => {
    const w = start(() => ({ error: invalid() }));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    await w.ready();
    w.track(a.passflow.refreshToken());
    await w.run(5_000);

    const auth = (source: string, willRetry: boolean, strikes: number, nextRetryAt?: number) => [
      E.Error,
      {
        operation: 'refresh',
        source,
        code: 'error.token.invalid.error',
        message: 'string',
        refresh: {
          classification: 'auth',
          willRetry,
          strikes,
          maxStrikes: 3,
          ...(nextRetryAt !== undefined ? { nextRetryAt } : {}),
        },
      },
    ];
    expect(sequence(a)).toEqual([
      [E.RefreshStart, {}],
      auth('refresh-token', true, 1, 1_000),
      [E.RefreshStart, {}],
      auth('retry', true, 2, 4_000),
      [E.RefreshStart, {}],
      auth('retry', false, 3),
      [E.SessionExpired, { reason: 'refresh_failed', origin: 'this-tab' }],
    ]);
    expect(sequence(b)).toEqual([[E.SessionExpired, { reason: 'refresh_failed', origin: 'other-tab' }]]);
    for (const tab of [a, b]) expect(at(tab, E.SessionExpired)[0]?.cached).toBeUndefined();
  });

  test('blocked, then a successor: Error{blocked} and later an unpaired Refresh{adopted}', async () => {
    const w = start((r) => (r.tab === 'a' ? { error: blocked() } : 'rotate'));
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    await w.ready();
    w.track(a.passflow.refreshToken());
    await w.run(3_000);
    w.track(b.passflow.refreshToken());
    await w.run();
    const next = w.stored()?.refresh_token;

    expect(sequence(a)).toEqual([
      [E.RefreshStart, {}],
      [
        E.Error,
        {
          operation: 'refresh',
          source: 'refresh-token',
          code: 'error.token.blocked',
          message: 'string',
          refresh: { classification: 'blocked', willRetry: false, strikes: 0, maxStrikes: 3 },
        },
      ],
      [E.Refresh, { source: 'adopted', refresh_token: next, parsed: true }],
      [E.TokenCacheExpired, { isExpired: false }],
    ]);
    expect(at(a, E.Refresh)[0]?.cached?.refresh_token).toBe(next);
  });

  test("another user's tokens in storage: SessionExpired{identity_changed} with the cache cleared, then SignIn{other-tab} with the new tokens", async () => {
    const w = start();
    w.seed(pairOf('user-1'));
    const a = w.open('a');
    await w.ready();
    const other = pairOf('user-2', { fresh: true, sid: 's9' });
    w.seed(other);
    await w.run();

    expect(sequence(a)).toEqual([
      [E.SessionExpired, { reason: 'identity_changed', origin: 'this-tab' }],
      [E.SignIn, { origin: 'other-tab', refresh_token: other.refresh_token, parsed: true }],
    ]);
    expect(at(a, E.SessionExpired)[0]?.cached).toBeUndefined();
    expect(at(a, E.SignIn)[0]?.cached?.refresh_token).toBe(other.refresh_token);
  });

  test('storage emptied with no explaining message: SignOut{other-tab} after 2 s, the cache cleared', async () => {
    const w = start();
    w.seed(pairOf());
    const a = w.open('a');
    await w.ready();
    for (const key of [...w.shared.items.keys()]) {
      if (key !== 'passflowDeviceId') w.shared.view('seed').removeItem(key);
    }
    await w.run(1_999);
    expect(a.events).toEqual([]);
    await w.run(1);
    expect(sequence(a)).toEqual([[E.SignOut, { origin: 'other-tab', userId: 'user-1' }]]);
    expect(at(a, E.SignOut)[0]?.cached).toBeUndefined();
  });

  test('logOut(): one SignOut{this-tab} here and one SignOut{other-tab} in the other tab, both after the cache is cleared', async () => {
    vi.spyOn(AuthAPI.prototype, 'logOut').mockResolvedValue({ status: 'ok' } as never);
    const w = start();
    w.seed(pairOf());
    const a = w.open('a');
    const b = w.open('b');
    await w.ready();
    w.track(a.passflow.logOut());
    await w.run(3_000);
    expect(sequence(a)).toEqual([[E.SignOut, { origin: 'this-tab', userId: 'user-1' }]]);
    expect(sequence(b)).toEqual([[E.SignOut, { origin: 'other-tab', userId: 'user-1' }]]);
    for (const tab of [a, b]) expect(at(tab, E.SignOut)[0]?.cached).toBeUndefined();
  });
});
