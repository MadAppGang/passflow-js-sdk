// Architecture §5 (state machine), §2.4 events, §2.6 classification effects, §2.7 schedule,
// §2.8 callers. Port of the portal's token-refresh.test.ts, adapted: the 5-step schedule with no
// give-up for transient failures replaces [1000, 3000] + give-up after 3; auth strikes still end;
// nextRefresh / tolerateRateLimit / hasPendingRefresh (portal-only API) are dropped. One tab with
// the local coordinator unless a test says otherwise.
import { describe, expect, it } from 'vitest';
import { PassflowRefreshError, RefreshErrorId, UpgradeCommitInterruptedError } from '../../lib/refresh/errors';
import { blockedError, createWorld, invalidError, rateLimited, rotate, track, unavailable } from './harness';
import { pair } from './jwt';

const SCHEDULE = [0, 1_000, 4_000, 14_000, 44_000, 104_000, 164_000];

describe('refresh controller: single flight and save', () => {
  it('sends one request for concurrent callers, saves it, and emits RefreshStart, Refresh{refresh}, TokenCacheExpired', async () => {
    const w = createWorld({ coordinated: false });
    const [tab] = w.tabs;
    const before = w.stored();
    const a = track(tab.controller.refresh({ trigger: 'token-check' }));
    const b = track(tab.controller.refresh({ trigger: 'session' }));
    await w.run();

    expect(w.requests).toHaveLength(1);
    expect(w.requests[0].refreshToken).toBe(before?.refresh_token);
    expect(a.status).toBe('resolved');
    expect(b.status).toBe('resolved');
    expect(w.stored()?.refresh_token).not.toBe(before?.refresh_token);
    expect(tab.cache.getTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    expect(a.value?.refresh_token).toBe(w.stored()?.refresh_token);
    expect(tab.names()).toEqual(['refresh:start', 'refresh', 'token-cache-expired']);
    expect(tab.of('refresh')[0].source).toBe('refresh');
    expect(tab.of('token-cache-expired')[0]).toEqual({ isExpired: false });
  });

  it('keeps the stored scopes on the saved pair', async () => {
    const w = createWorld({ coordinated: false });
    await w.run();
    track(w.tabs[0].controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run();
    expect(w.stored()?.scopes).toEqual(['id', 'offline']);
  });

  it('resets tokenExpiredFlag and restarts the token check on every Refresh', async () => {
    const w = createWorld({ coordinated: false });
    const [tab] = w.tabs;
    tab.cache.tokenExpiredFlag = true;
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect(tab.cache.tokenExpiredFlag).toBe(false);
    expect(tab.cache.starts).toBe(1);
  });

  it('rejects with No tokens found and one Error, sending nothing and emitting no RefreshStart, when nothing is stored', async () => {
    const w = createWorld({ coordinated: false, initial: null });
    const [tab] = w.tabs;
    const call = track(tab.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run();
    expect(call.status).toBe('rejected');
    expect((call.error as Error).message).toBe('No tokens found');
    expect(w.requests).toHaveLength(0);
    expect(tab.names()).toEqual(['error']);
    expect(tab.of('error')[0]).toMatchObject({ operation: 'refresh', source: 'refresh-token' });
  });

  it('lets a fresh caller wait for a request sent before its call, then send its own', async () => {
    const w = createWorld({ coordinated: false, answer: () => 'hold' });
    const [tab] = w.tabs;
    const plain = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect(w.requests).toHaveLength(1);
    await w.run(10);
    const fresh = track(tab.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    w.held[0].resolve(rotate(w.held[0].request.refreshToken));
    await w.run();
    expect(plain.status).toBe('resolved');
    expect(fresh.status).toBe('pending');
    expect(w.requests).toHaveLength(2);
    expect(w.requests[1].refreshToken).toBe(w.stored()?.refresh_token);
    w.held[1].resolve(rotate(w.held[1].request.refreshToken));
    await w.run();
    expect(fresh.status).toBe('resolved');
  });
});

describe('refresh controller: transient failures (§2.7 schedule, no give-up)', () => {
  it('retries a 503 on 1, 3, 10, 30, then every 60 s, keeps the tokens, emits one RefreshFailing and one Error per attempt', async () => {
    const w = createWorld({ coordinated: false, answer: () => ({ error: unavailable() }) });
    const [tab] = w.tabs;
    const before = w.stored();
    const call = track(tab.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run(180_000);

    expect(w.requests.map((r) => r.at)).toEqual(SCHEDULE);
    expect(call.status).toBe('rejected');
    expect((call.error as PassflowRefreshError).id).toBe('error.http.503');
    expect(w.stored()).toEqual(before);
    expect(tab.cache.getTokens()).toEqual(before);
    expect(tab.of('refresh:failing')).toEqual([{ since: 0, nextRetryAt: 1_000, origin: 'this-tab' }]);
    const errors = tab.of('error');
    expect(errors).toHaveLength(7);
    expect(errors[0]).toMatchObject({
      operation: 'refresh',
      source: 'refresh-token',
      refresh: { classification: 'transient', willRetry: true, nextRetryAt: 1_000, strikes: 0, maxStrikes: 3 },
    });
    expect(errors[1]).toMatchObject({ source: 'retry', refresh: { nextRetryAt: 4_000 } });
    expect(tab.names()).not.toContain('session:expired');
    expect(tab.names()).not.toContain('signout');
  });

  it('adds jitter of up to 20 % of the step from clock.random, never beyond', async () => {
    const w = createWorld({ coordinated: false, random: () => 0.5, answer: () => ({ error: unavailable() }) });
    track(w.tabs[0].controller.refresh({ trigger: 'token-check' }));
    await w.run(20_000);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_100, 1_100 + 3_300, 1_100 + 3_300 + 11_000]);

    const top = createWorld({ coordinated: false, random: () => 1, answer: () => ({ error: unavailable() }) });
    track(top.tabs[0].controller.refresh({ trigger: 'token-check' }));
    await top.run(2_000);
    expect(top.requests[1].at).toBe(1_199);
  });

  it('makes a caller during the backoff join the pending retry and send nothing', async () => {
    const w = createWorld({ coordinated: false, answer: () => ({ error: unavailable() }) });
    const [tab] = w.tabs;
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run(50_000);
    expect(w.requests).toHaveLength(5);
    const joined = track(tab.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run(53_000);
    expect(w.requests).toHaveLength(5);
    expect(joined.status).toBe('pending');
    await w.run(1_000);
    expect(w.requests).toHaveLength(6);
    expect(w.requests[5].at).toBe(104_000);
    expect(joined.status).toBe('rejected');
  });

  it('recovers on the next scheduled retry: Refresh{refresh}, RefreshRecovered{this-tab}, and the schedule starts over', async () => {
    let healthy = false;
    const w = createWorld({ coordinated: false, answer: () => (healthy ? 'rotate' : { error: unavailable() }) });
    const [tab] = w.tabs;
    const call = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run(5_000);
    healthy = true;
    const joined = track(tab.controller.refresh({ trigger: 'session' }));
    await w.run(10_000);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);
    expect(call.status).toBe('rejected');
    expect(joined.status).toBe('resolved');
    expect(tab.of('refresh:recovered')).toEqual([{ since: 0, origin: 'this-tab' }]);
    const names = tab.names();
    expect(names.slice(-4)).toEqual(['refresh:start', 'refresh', 'token-cache-expired', 'refresh:recovered']);

    healthy = false;
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run(1_500);
    expect(w.requests.map((r) => r.at).slice(3)).toEqual([14_000, 15_000, 16_000]);
    expect(tab.of('refresh:failing')).toHaveLength(2);
  });

  it('honours Retry-After on a 429: the next attempt is no earlier than 30 s later', async () => {
    let calls = 0;
    const w = createWorld({
      coordinated: false,
      answer: () => {
        calls += 1;
        return calls === 1 ? { error: rateLimited(30) } : 'rotate';
      },
    });
    const call = track(w.tabs[0].controller.refresh({ trigger: 'token-check' }));
    await w.run(29_999);
    expect(w.requests).toHaveLength(1);
    await w.run(1);
    expect(w.requests.map((r) => r.at)).toEqual([0, 30_000]);
    expect(call.status).toBe('rejected');
    expect(w.tabs[0].of('error')[0].refresh).toMatchObject({ classification: 'transient', nextRetryAt: 30_000 });
  });

  it('answers a pre-request during the backoff with the current tokens when the access token is not yet expired', async () => {
    const w = createWorld({ coordinated: false, answer: () => ({ error: unavailable() }) });
    const [tab] = w.tabs;
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run(100);
    const stale = track(tab.controller.ensureFresh({ trigger: 'pre-request', allowStale: true }));
    await w.run();
    expect(stale.status).toBe('resolved');
    expect(stale.value).toEqual(tab.cache.getTokens());
    const expired = track(tab.controller.ensureFresh({ trigger: 'pre-request', allowStale: false }));
    await w.run();
    expect(expired.status).toBe('pending');
    expect(w.requests).toHaveLength(1);
  });
});

describe('refresh controller: authentication strikes', () => {
  it('ends the session at the third auth failure (requests at 0, 1, 4 s), deleting the dead tokens', async () => {
    const w = createWorld({ coordinated: false, answer: () => ({ error: invalidError() }) });
    const [tab] = w.tabs;
    const call = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run(30_000);

    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000, 4_000]);
    expect(call.status).toBe('rejected');
    expect(w.stored()).toBeUndefined();
    expect(tab.cache.getTokens()).toBeUndefined();
    const errors = tab.of('error');
    expect(errors.map((e) => e.refresh)).toEqual([
      { classification: 'auth', willRetry: true, nextRetryAt: 1_000, strikes: 1, maxStrikes: 3 },
      { classification: 'auth', willRetry: true, nextRetryAt: 4_000, strikes: 2, maxStrikes: 3 },
      { classification: 'auth', willRetry: false, strikes: 3, maxStrikes: 3 },
    ]);
    expect(tab.of('session:expired')).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
    expect(tab.names().indexOf('session:expired')).toBeGreaterThan(tab.names().lastIndexOf('error'));
    expect(tab.of('refresh:failing')).toEqual([]);

    const after = track(tab.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run();
    expect((after.error as PassflowRefreshError).id).toBe(RefreshErrorId.sessionEnded);
  });

  it('counts strikes since the last success: auth, 503, auth, auth ends at the fourth answer', async () => {
    const answers = [invalidError(), unavailable(), invalidError(), invalidError()];
    const w = createWorld({ coordinated: false, answer: () => ({ error: answers.shift() ?? unavailable() }) });
    const [tab] = w.tabs;
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run(4_000);
    expect(w.requests).toHaveLength(3);
    expect(tab.of('session:expired')).toEqual([]);
    await w.run(10_000);
    expect(w.requests).toHaveLength(4);
    expect(tab.of('session:expired')).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
  });

  it('honours refreshStrikes', async () => {
    const w = createWorld({ coordinated: false, strikes: 1, answer: () => ({ error: invalidError() }) });
    track(w.tabs[0].controller.refresh({ trigger: 'token-check' }));
    await w.run(5_000);
    expect(w.requests).toHaveLength(1);
    expect(w.tabs[0].of('session:expired')).toHaveLength(1);
  });

  it('deletes nothing when another session of the user was stored before the refusal arrived (superseded, no strike)', async () => {
    const w = createWorld({ coordinated: false, strikes: 1, answer: () => 'hold' });
    const [tab] = w.tabs;
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    // Another session of the user signed in meanwhile.
    const other = pair(10, 's2');
    w.storage.saveTokens(other);
    w.held[0].reject(invalidError());
    await w.run();
    expect(w.stored()?.refresh_token).toBe(other.refresh_token);
    expect(w.tabs[0].of('session:expired')).toEqual([]);
  });
});

describe('refresh controller: blocked never kills', () => {
  it('neither strikes nor deletes on error.token.blocked, and adopts the successor another writer stores within 20 s', async () => {
    const w = createWorld({ coordinated: false, answer: () => ({ error: blockedError() }) });
    const [tab] = w.tabs;
    const before = w.stored();
    const call = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run(5_000);
    expect(w.requests).toHaveLength(1);
    expect(w.stored()).toEqual(before);
    expect(tab.of('error')[0].refresh).toEqual({ classification: 'blocked', willRetry: false, strikes: 0, maxStrikes: 3 });
    expect(call.status).toBe('pending');

    const successor = rotate(before?.refresh_token);
    w.storage.saveTokens(successor);
    await w.run();
    expect(call.status).toBe('resolved');
    expect(tab.cache.getTokens()?.refresh_token).toBe(successor.refresh_token);
    expect(tab.names()).toEqual(['refresh:start', 'error', 'refresh', 'token-cache-expired']);
    expect(tab.of('refresh')[0].source).toBe('adopted');
    await w.run(30_000);
    expect(tab.of('session:expired')).toEqual([]);
  });

  it('ends this tab only after 20 s with no successor, deleting nothing', async () => {
    const w = createWorld({ coordinated: false, answer: () => ({ error: blockedError() }) });
    const [tab] = w.tabs;
    const before = w.stored();
    const call = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run(19_999);
    expect(tab.of('session:expired')).toEqual([]);
    await w.run(1);
    expect(tab.of('session:expired')).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
    expect((call.error as PassflowRefreshError).id).toBe(RefreshErrorId.successorTimeout);
    expect(w.stored()).toEqual(before);
    expect(tab.cache.getTokens()).toBeUndefined();
    expect(w.requests).toHaveLength(1);
  });

  it('makes callers during the successor wait join it, sending nothing', async () => {
    const w = createWorld({ coordinated: false, answer: () => ({ error: blockedError() }) });
    const [tab] = w.tabs;
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run(1_000);
    const joined = track(tab.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run(5_000);
    expect(w.requests).toHaveLength(1);
    expect(joined.status).toBe('pending');
  });
});

describe('refresh controller: superseded is success', () => {
  it('drops a 200 whose sent token storage no longer holds, adopts the newer stored pair and emits Refresh{adopted}', async () => {
    const w = createWorld({ coordinated: false, answer: () => 'hold' });
    const [tab] = w.tabs;
    const sent = w.stored();
    const call = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    const newer = rotate(sent?.refresh_token);
    w.storage.saveTokens(newer);
    w.held[0].resolve(rotate(newer.refresh_token));
    await w.run();
    expect(call.status).toBe('resolved');
    expect(w.stored()?.refresh_token).toBe(newer.refresh_token);
    expect(tab.cache.getTokens()?.refresh_token).toBe(newer.refresh_token);
    expect(tab.names()).toEqual(['refresh:start', 'refresh', 'token-cache-expired']);
    expect(tab.of('refresh')[0].source).toBe('adopted');
  });

  it('treats a failure after storage moved forward as superseded: no Error, no strike', async () => {
    const w = createWorld({ coordinated: false, answer: () => 'hold' });
    const [tab] = w.tabs;
    const call = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    w.storage.saveTokens(rotate(w.stored()?.refresh_token));
    w.held[0].reject(invalidError());
    await w.run(10_000);
    expect(call.status).toBe('resolved');
    expect(tab.of('error')).toEqual([]);
    expect(w.requests).toHaveLength(1);
  });
});

describe('refresh controller: generations', () => {
  it('ignores a late answer of a request sent before sessionStarted(): no Error, no retry', async () => {
    const w = createWorld({ coordinated: false, answer: () => 'hold' });
    const [tab] = w.tabs;
    const old = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    const next = pair(500, 's9');
    w.storage.saveTokens(next);
    tab.cache.setTokensCache(next);
    tab.controller.sessionStarted();
    w.held[0].reject(unavailable());
    await w.run(10_000);
    expect(old.status).not.toBe('pending');
    expect(tab.of('error')).toEqual([]);
    expect(tab.of('refresh:failing')).toEqual([]);
    expect(w.requests).toHaveLength(1);
    expect(w.stored()?.refresh_token).toBe(next.refresh_token);
  });
});

describe('refresh controller: held tab (§2.9.8)', () => {
  it('resolves with the cached tokens while storage shows an older token of its session, then after 20 s sends the stored token once; a refused held send keeps the cache', async () => {
    const w = createWorld({ coordinated: false, answer: () => ({ error: blockedError() }) });
    const [tab] = w.tabs;
    const older = w.stored();
    const ahead = rotate(older?.refresh_token);
    tab.cache.setTokensCache(ahead);

    const first = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect(first.status).toBe('resolved');
    expect(w.requests).toHaveLength(0);

    await w.run(20_000);
    const held = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect(w.requests.map((r) => r.refreshToken)).toEqual([older?.refresh_token]);
    expect(held.status).toBe('resolved');
    expect(tab.cache.getTokens()?.refresh_token).toBe(ahead.refresh_token);
    expect(tab.of('error')[0]).toMatchObject({ source: 'held', refresh: { classification: 'blocked', willRetry: false } });
    expect(tab.of('refresh').map((r) => r.source)).toEqual(['adopted']);
    expect(tab.of('session:expired')).toEqual([]);
  });
});

describe('refresh controller: lost sessions and revival', () => {
  it('ends with SignOut{other-tab} 2 s after another tab emptied the storage with no explaining message', async () => {
    const w = createWorld({ coordinated: false });
    const [tab] = w.tabs;
    w.storage.deleteTokens();
    await w.run(1_999);
    expect(tab.of('signout')).toEqual([]);
    await w.run(1);
    expect(tab.of('signout')).toEqual([{ origin: 'other-tab', userId: 'user-1' }]);
    expect(tab.cache.getTokens()).toBeUndefined();
    const call = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect((call.error as PassflowRefreshError).id).toBe(RefreshErrorId.sessionEnded);
  });

  it("ends with SessionExpired{identity_changed} when another user's tokens appear, then revives on them with SignIn{other-tab}", async () => {
    const w = createWorld({ coordinated: false });
    const [tab] = w.tabs;
    const other = pair(300, 'z1', 'user-2');
    w.storage.saveTokens(other);
    await w.run();
    expect(tab.names()).toEqual(['session:expired', 'signin']);
    expect(tab.of('session:expired')).toEqual([{ reason: 'identity_changed', origin: 'this-tab' }]);
    expect(tab.of('signin')[0]).toMatchObject({ origin: 'other-tab', tokens: { refresh_token: other.refresh_token } });
    expect(tab.cache.getTokens()?.refresh_token).toBe(other.refresh_token);
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect(w.requests).toHaveLength(1);
  });

  it('revives an ended tab on a new-lineage pair, never on the token that ended it', async () => {
    const w = createWorld({ coordinated: false, strikes: 1, answer: () => ({ error: invalidError() }) });
    const [tab] = w.tabs;
    const dead = w.stored();
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect(tab.of('session:expired')).toHaveLength(1);
    // A portal tab writes the dead token back: no revival.
    w.storage.saveTokens(dead ?? {});
    await w.run();
    expect(tab.of('signin')).toEqual([]);
    const fresh = pair(900, 's-new');
    w.storage.saveTokens(fresh);
    await w.run();
    expect(tab.of('signin')).toHaveLength(1);
    expect(tab.cache.getTokens()?.refresh_token).toBe(fresh.refresh_token);
  });

  it('starts a new session on sessionStarted() after an end', async () => {
    const w = createWorld({ coordinated: false, strikes: 1, answer: () => ({ error: invalidError() }) });
    const [tab] = w.tabs;
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    const next = pair(700, 's7');
    w.answer = () => 'rotate';
    tab.storage.saveTokens(next);
    tab.cache.setTokensCache(next);
    tab.controller.sessionStarted();
    const call = track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect(call.status).toBe('resolved');
    expect(w.requests).toHaveLength(2);
  });
});

describe('refresh controller: upgrade commit', () => {
  it('sends the stored token with the upgrade and emits Refresh{upgrade} on success', async () => {
    const w = createWorld({ coordinated: false });
    const [tab] = w.tabs;
    const upgrade = { challenge_id: 'c', code: '123456' } as never;
    const call = track(tab.controller.commitUpgrade(upgrade));
    await w.run();
    expect(call.status).toBe('resolved');
    expect(w.requests[0].upgrade).toBe(upgrade);
    expect(tab.of('refresh').map((r) => r.source)).toEqual(['upgrade']);
  });

  it('rejects a 401 unchanged, keeps the tokens, emits one Error{upgrade.commit}, no strike, no RefreshFailing', async () => {
    const wrong = invalidError();
    const w = createWorld({ coordinated: false, answer: () => ({ error: wrong }) });
    const [tab] = w.tabs;
    const before = w.stored();
    const call = track(tab.controller.commitUpgrade({ challenge_id: 'c', code: '0' } as never));
    await w.run(10_000);
    expect(call.error).toBe(wrong);
    expect(w.stored()).toEqual(before);
    expect(tab.of('error')).toHaveLength(1);
    expect(tab.of('error')[0]).toMatchObject({ operation: 'upgrade.commit', source: 'upgrade' });
    expect(tab.names()).not.toContain('refresh:failing');
    expect(tab.names()).not.toContain('session:expired');
    expect(w.requests).toHaveLength(1);
  });

  it('never resolves as superseded: storage moved on before the answer → UpgradeCommitInterruptedError{superseded}', async () => {
    const w = createWorld({ coordinated: false, answer: () => 'hold' });
    const [tab] = w.tabs;
    const call = track(tab.controller.commitUpgrade({ challenge_id: 'c', code: '1' } as never));
    await w.run();
    w.storage.saveTokens(rotate(w.stored()?.refresh_token));
    w.held[0].resolve(rotate(w.held[0].request.refreshToken));
    await w.run();
    expect(call.error).toBeInstanceOf(UpgradeCommitInterruptedError);
    expect((call.error as UpgradeCommitInterruptedError).reason).toBe('superseded');
  });
});

describe('refresh controller: dispose and fallback warning', () => {
  it('rejects pending callers with error.refresh.disposed and cancels its timers', async () => {
    const w = createWorld({ coordinated: false, answer: () => ({ error: unavailable() }) });
    const [tab] = w.tabs;
    track(tab.controller.refresh({ trigger: 'token-check' }));
    await w.run(100);
    const joined = track(tab.controller.refresh({ trigger: 'session' }));
    tab.controller.dispose();
    await w.run(100_000);
    expect((joined.error as PassflowRefreshError).id).toBe(RefreshErrorId.disposed);
    expect(w.requests).toHaveLength(1);
    expect(w.clock.pending('tab-0')).toBe(0);
  });
});
