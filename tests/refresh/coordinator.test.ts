// Architecture §2.9 (cross-tab guarantees), §2.10 (wire protocol), §2.13 (acceptance scenarios),
// §6 (coordinator). N tabs, each a RefreshController with the cross-tab coordinator over one fake
// Web Locks manager, one fake channel hub (never delivers to the sender) and one shared storage,
// on one virtual clock, with clock.random = 0. The fake transport counts every /auth/refresh.
import { describe, expect, it } from 'vitest';
import { REFRESH_LOCK } from '../../lib/refresh/constants';
import { type PassflowRefreshError, RefreshErrorId } from '../../lib/refresh/errors';
import { fingerprint, orderOf } from '../../lib/refresh/lineage';
import { blockedError, createWorld, invalidError, rateLimited, rotate, type Tab, track, unavailable } from './harness';
import { pair } from './jwt';

const OUTAGE_SCHEDULE = [0, 1_000, 4_000, 14_000, 44_000, 104_000, 164_000];

const posted = (w: ReturnType<typeof createWorld>, type: string) =>
  w.hub.posted.filter((m) => (m.data as { type?: string }).type === type);

const sentBy = (w: ReturnType<typeof createWorld>, tab: Tab) => w.requests.filter((r) => r.tab === tab.id);

describe('cross-tab: one refresher per browser', () => {
  it('four tabs calling refreshToken() together send one request and all end on the same tokens (§2.13 #1)', async () => {
    const w = createWorld({ tabs: 4 });
    const calls = w.tabs.map((tab) => track(tab.controller.refresh({ trigger: 'refresh-token', fresh: true })));
    await w.run(1_000);

    expect(w.requests).toHaveLength(1);
    expect(calls.map((c) => c.status)).toEqual(['resolved', 'resolved', 'resolved', 'resolved']);
    const stored = w.stored()?.refresh_token;
    for (const tab of w.tabs) expect(tab.cache.getTokens()?.refresh_token).toBe(stored);
    const holder = w.tabs.find((tab) => tab.id === w.requests[0].tab) as Tab;
    expect(holder.names()).toEqual(['refresh:start', 'refresh', 'token-cache-expired']);
    expect(holder.of('refresh')[0].source).toBe('refresh');
    for (const tab of w.tabs.filter((t) => t !== holder)) {
      expect(tab.names()).toEqual(['refresh', 'token-cache-expired']);
      expect(tab.of('refresh')[0].source).toBe('adopted');
    }
    expect(posted(w, 'tokens-refreshed')).toHaveLength(1);
    const message = posted(w, 'tokens-refreshed')[0].data as Record<string, unknown>;
    expect(message).toMatchObject({ v: 1, tabId: holder.id, to: fingerprint(stored), sentAt: 0 });
    expect(w.locks.isHeld(REFRESH_LOCK)).toBe(false);
    expect(w.locks.queued(REFRESH_LOCK)).toBe(0);
  });

  it('adopts from storage at the grant when another tab already refreshed, sending nothing (§2.9.2)', async () => {
    const w = createWorld({ tabs: 2 });
    const [a, b] = w.tabs;
    // b's view of storage lags and it misses the broadcast: it learns of a's result only at its grant.
    w.shared.lag(b.id);
    w.hub.hold(b.id);
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    w.shared.sync(b.id);
    const call = track(b.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect(w.requests).toHaveLength(1);
    expect(call.status).toBe('resolved');
    expect(b.cache.getTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
  });
});

describe('cross-tab: one pending retry per browser during an outage', () => {
  it('holds a 503 for 3 minutes across 2 tabs: 7 requests from the holder at 0, 1, 4, 14, 44, 104, 164 s (§2.13 #2)', async () => {
    const w = createWorld({ tabs: 2, answer: () => ({ error: unavailable() }) });
    const [a, b] = w.tabs;
    const before = w.stored();
    const callA = track(a.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    const callB = track(b.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run(50_000);
    const lateA = track(a.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    const lateB = track(b.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run(53_999);
    expect(lateA.status).toBe('pending');
    expect(lateB.status).toBe('pending');
    await w.run(1);
    expect(lateA.status).toBe('rejected');
    expect(lateB.status).toBe('rejected');
    expect((lateB.error as PassflowRefreshError).id).toBe(RefreshErrorId.unavailable);
    expect((lateB.error as PassflowRefreshError).nextRetryAt).toBe(164_000);
    await w.run(76_000);

    expect(w.requests.map((r) => r.at)).toEqual(OUTAGE_SCHEDULE);
    const holder = w.requests[0].tab === a.id ? a : b;
    const other = holder === a ? b : a;
    expect(sentBy(w, holder)).toHaveLength(7);
    expect(sentBy(w, other)).toHaveLength(0);
    expect(callA.status).toBe('rejected');
    expect(callB.status).toBe('rejected');
    expect(w.stored()).toEqual(before);
    for (const tab of w.tabs) expect(tab.cache.getTokens()).toEqual(before);
    expect(holder.of('refresh:failing')).toEqual([{ since: 0, nextRetryAt: 1_000, origin: 'this-tab' }]);
    expect(other.of('refresh:failing')).toEqual([{ since: 0, nextRetryAt: 1_000, origin: 'other-tab' }]);
    expect(holder.of('error')).toHaveLength(7);
    expect(holder.of('error').every((e) => e.refresh?.classification === 'transient')).toBe(true);
    expect(other.of('error')).toEqual([]);
    for (const tab of w.tabs) {
      expect(tab.names()).not.toContain('session:expired');
      expect(tab.names()).not.toContain('signout');
    }
    expect(posted(w, 'takeover')).toEqual([]);
  });

  it('recovers mid-wait: no request between 104 and 164 s, one success at 164 s recovers both tabs (§2.13 #3)', async () => {
    const w = createWorld({ tabs: 2, answer: (r) => (r.at >= 120_000 ? 'rotate' : { error: unavailable() }) });
    const [a, b] = w.tabs;
    track(a.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    track(b.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run(130_000);
    const pendingA = track(a.controller.refresh({ trigger: 'session' }));
    const pendingB = track(b.controller.refresh({ trigger: 'session' }));
    await w.run(60_000);
    await w.run(120_000);

    expect(w.requests.map((r) => r.at)).toEqual(OUTAGE_SCHEDULE);
    const holder = w.requests[0].tab === a.id ? a : b;
    const other = holder === a ? b : a;
    expect(pendingA.status).toBe('resolved');
    expect(pendingB.status).toBe('resolved');
    expect(holder.of('refresh').map((r) => r.source)).toEqual(['refresh']);
    expect(holder.of('refresh:recovered')).toEqual([{ since: 0, origin: 'this-tab' }]);
    expect(other.of('refresh').map((r) => r.source)).toEqual(['adopted']);
    expect(other.of('refresh:recovered')).toEqual([{ since: 0, origin: 'other-tab' }]);
    expect(other.cache.getTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    expect(w.locks.isHeld(REFRESH_LOCK)).toBe(false);
  });

  it('continues the schedule in the waiter when the holder closes mid-outage: first request at 44 s, not before (§2.13 #4)', async () => {
    const w = createWorld({ tabs: 2, answer: () => ({ error: unavailable() }) });
    const [a, b] = w.tabs;
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    track(b.controller.refresh({ trigger: 'token-check' }));
    await w.run(20_000);
    expect(sentBy(w, a).map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);
    w.kill(a);
    await w.run(23_999);
    expect(sentBy(w, b)).toEqual([]);
    await w.run(1);
    expect(sentBy(w, b).map((r) => r.at)).toEqual([44_000]);
    await w.run(60_000);
    expect(sentBy(w, b).map((r) => r.at)).toEqual([44_000, 104_000]);
    expect(b.of('refresh:failing')).toHaveLength(1);
    expect(b.of('error')).toHaveLength(2);
  });

  it('extends a waiter’s silence to nextAt + 20 s: a holder frozen in backoff is taken over at 64 s, not 34 s (§2.7)', async () => {
    const w = createWorld({ tabs: 2, answer: () => ({ error: unavailable() }) });
    const [a, b] = w.tabs;
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    track(b.controller.refresh({ trigger: 'token-check' }));
    await w.run(14_500);
    expect(sentBy(w, a).map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);
    // The holder's page freezes in backoff (next attempt due at 44 s): no heartbeat, no attempt.
    w.clock.freeze(a.id);
    w.hub.freeze(a.id);
    await w.run(49_000);
    expect(posted(w, 'takeover')).toEqual([]);
    expect(sentBy(w, b)).toEqual([]);
    await w.run(1_000);
    expect(posted(w, 'takeover')).toHaveLength(1);
    expect(sentBy(w, b).map((r) => r.at)).toEqual([64_000]);
  });

  it('shares a 429 Retry-After of 30 s: no attempt in any tab before 30 s, and no takeover during the wait (§2.13 #5)', async () => {
    let calls = 0;
    const w = createWorld({
      tabs: 2,
      answer: () => {
        calls += 1;
        return calls === 1 ? { error: rateLimited(30) } : 'rotate';
      },
    });
    const [a, b] = w.tabs;
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    const callB = track(b.controller.refresh({ trigger: 'token-check' }));
    await w.run(29_999);
    expect(w.requests).toHaveLength(1);
    await w.run(1);
    expect(w.requests.map((r) => r.at)).toEqual([0, 30_000]);
    expect(w.requests.every((r) => r.tab === a.id)).toBe(true);
    expect(posted(w, 'takeover')).toEqual([]);
    await w.run();
    expect(b.cache.getTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    // b called after the 429 was answered: it joined the pending retry, which succeeded.
    expect(callB.status).toBe('resolved');
    const retry = posted(w, 'retry-scheduled')[0].data as Record<string, unknown>;
    expect(retry).toMatchObject({ kind: 'transient', attempt: 1, nextAt: 30_000, strikes: 0 });
  });
});

describe('cross-tab: blocked never kills (§2.13 #6)', () => {
  it("adopts another tab's broadcast successor within 20 s: no strike, storage untouched by the blocked tab, no broadcast", async () => {
    const w = createWorld({ tabs: 2, answer: (r) => (r.tab === 'tab-0' ? { error: blockedError() } : 'rotate') });
    const [a, b] = w.tabs;
    const before = w.stored();
    const callA = track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run(2_000);
    expect(a.of('error')[0].refresh?.classification).toBe('blocked');
    expect(w.stored()).toEqual(before);
    expect(w.hub.posted.filter((m) => m.from === a.id)).toEqual([]);
    expect(w.locks.isHeld(REFRESH_LOCK)).toBe(false);

    track(b.controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run();
    expect(callA.status).toBe('resolved');
    expect(a.cache.getTokens()?.refresh_token).toBe(w.stored()?.refresh_token);
    expect(a.of('refresh').map((r) => r.source)).toEqual(['adopted']);
    await w.run(30_000);
    expect(a.of('session:expired')).toEqual([]);
  });

  it('ends only the blocked tab after 20 s with no successor; storage and the other tab are untouched', async () => {
    const w = createWorld({ tabs: 2, answer: () => ({ error: blockedError() }) });
    const [a, b] = w.tabs;
    const before = w.stored();
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run(20_000);
    expect(a.of('session:expired')).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
    expect(b.names()).toEqual([]);
    expect(b.cache.getTokens()).toEqual(before);
    expect(w.stored()).toEqual(before);
    expect(posted(w, 'session-ended')).toEqual([]);
  });
});

describe('cross-tab: three auth strikes end every tab of the lineage (§2.13 #7)', () => {
  it('ends the holder with SessionExpired{this-tab}, deletes storage, and ends the other tab with SessionExpired{other-tab}', async () => {
    const w = createWorld({ tabs: 2, answer: () => ({ error: invalidError() }) });
    const [a, b] = w.tabs;
    const dead = w.stored();
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    const callB = track(b.controller.refresh({ trigger: 'token-check' }));
    await w.run(10_000);

    expect(w.requests.map((r) => [r.tab, r.at])).toEqual([
      [a.id, 0],
      [a.id, 1_000],
      [a.id, 4_000],
    ]);
    expect(a.of('session:expired')).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
    expect(b.of('session:expired')).toEqual([{ reason: 'refresh_failed', origin: 'other-tab' }]);
    expect(b.names()).not.toContain('signout');
    expect(w.stored()).toBeUndefined();
    expect(b.cache.getTokens()).toBeUndefined();
    expect(callB.status).toBe('rejected');
    const ended = posted(w, 'session-ended');
    expect(ended).toHaveLength(1);
    const order = orderOf(dead?.refresh_token);
    expect(ended[0].data).toMatchObject({ fp: order?.fp, sub: 'user-1', sid: 's1', iat: order?.iat });
  });
});

describe('cross-tab: stuck holder and late answers', () => {
  it('takes over after 20 s of silence; the stolen holder’s late 200 is not saved (§2.13 #9)', async () => {
    const w = createWorld({ tabs: 2, answer: (r) => (r.tab === 'tab-0' ? 'hold' : 'rotate') });
    const [a, b] = w.tabs;
    const sent = w.stored();
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect(sentBy(w, a)).toHaveLength(1);
    // The holder's page freezes mid-request: no heartbeat.
    w.clock.freeze(a.id);
    w.hub.freeze(a.id);
    const callB = track(b.controller.refresh({ trigger: 'token-check' }));
    await w.run(19_000);
    expect(sentBy(w, b)).toHaveLength(0);
    await w.run(2_000);
    expect(posted(w, 'takeover')).toHaveLength(1);
    expect(sentBy(w, b)).toHaveLength(1);
    expect(callB.status).toBe('resolved');
    const saved = w.stored()?.refresh_token;
    expect(saved).not.toBe(sent?.refresh_token);

    // The old holder thaws; the engine had rotated its request too (a double acceptance).
    w.clock.thaw(a.id);
    w.hub.thaw(a.id);
    w.held[0].resolve(rotate(sent?.refresh_token));
    await w.run(1_000);
    expect(w.stored()?.refresh_token).toBe(saved);
    expect(a.cache.getTokens()?.refresh_token).toBe(saved);
    expect(a.names()).toContain('refresh');
    expect(a.of('session:expired')).toEqual([]);
  });

  it('a waiter whose holder heartbeats keeps waiting past 20 s without a takeover', async () => {
    const w = createWorld({ tabs: 2, answer: (r) => (r.tab === 'tab-0' ? 'hold' : 'rotate') });
    const [a, b] = w.tabs;
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    track(b.controller.refresh({ trigger: 'token-check' }));
    await w.run(45_000);
    expect(posted(w, 'takeover')).toEqual([]);
    expect(posted(w, 'still-refreshing').length).toBeGreaterThanOrEqual(8);
    expect(sentBy(w, b)).toEqual([]);
  });
});

describe('cross-tab: lock-wanted (A3, A4, §2.13 #11)', () => {
  it('a holder in backoff yields to an upgrade commit in another tab, which sends at once; a 200 recovers both tabs', async () => {
    const w = createWorld({
      tabs: 2,
      answer: (r) => (r.upgrade !== undefined ? 'rotate' : { error: unavailable() }),
    });
    const [a, b] = w.tabs;
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run(20_000);
    expect(sentBy(w, a).map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);
    const commit = track(b.controller.commitUpgrade({ challenge_id: 'c', code: '1' } as never));
    await w.run(10);
    expect(posted(w, 'lock-wanted')).toHaveLength(1);
    expect(sentBy(w, b).map((r) => r.at)).toEqual([20_000]);
    expect(commit.status).toBe('resolved');
    expect(b.of('refresh').map((r) => r.source)).toEqual(['upgrade']);
    expect(b.of('refresh:recovered')).toEqual([{ since: 0, origin: 'this-tab' }]);
    expect(a.of('refresh:recovered')).toEqual([{ since: 0, origin: 'other-tab' }]);
    await w.run(60_000);
    expect(w.requests).toHaveLength(5);
  });

  it('a failed commit leaves the committing tab holding the lock in backoff, and the next plain attempt still goes at 44 s', async () => {
    const wrong = invalidError();
    const w = createWorld({
      tabs: 2,
      answer: (r) => (r.upgrade !== undefined ? { error: wrong } : { error: unavailable() }),
    });
    const [a, b] = w.tabs;
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run(20_000);
    const commit = track(b.controller.commitUpgrade({ challenge_id: 'c', code: '0' } as never));
    await w.run(10);
    expect(commit.error).toBe(wrong);
    expect(w.locks.holder(REFRESH_LOCK)).toBe(b.id);
    await w.run(23_989);
    expect(w.requests.map((r) => [r.tab, r.at])).toEqual([
      [a.id, 0],
      [a.id, 1_000],
      [a.id, 4_000],
      [a.id, 14_000],
      [b.id, 20_000],
    ]);
    await w.run(1);
    expect(w.requests.at(-1)).toMatchObject({ tab: b.id, at: 44_000 });
  });

  it('rejects an upgrade commit with UpgradeCommitInterruptedError{lock-timeout} after 10 s when the holder is mid-request', async () => {
    const w = createWorld({ tabs: 2, answer: (r) => (r.tab === 'tab-0' ? 'hold' : 'rotate') });
    const [a, b] = w.tabs;
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    const commit = track(b.controller.commitUpgrade({ challenge_id: 'c', code: '1' } as never));
    await w.run(9_999);
    expect(commit.status).toBe('pending');
    await w.run(1);
    expect(commit.status).toBe('rejected');
    expect((commit.error as { reason?: string }).reason).toBe('lock-timeout');
    expect(sentBy(w, b)).toEqual([]);
    expect(w.locks.queued(REFRESH_LOCK)).toBe(0);
  });
});

describe('cross-tab: the token a session-ended names (portal round 25)', () => {
  it('names the stored S2 it sent, not the cached S1, after its lock was stolen; tabs on the live S1 do not end, and its later sign-out posts no signed-out', async () => {
    const w = createWorld({ tabs: 2, strikes: 1, answer: () => 'hold' });
    const [a, b] = w.tabs;
    const s1 = pair(200, 's1');
    const s2 = pair(100, 'session-again');
    // a and b cache S1; storage shows S2, another sign-in of the same user: a "send" verdict.
    w.storage.saveTokens(s2);
    a.cache.setTokensCache(s1);
    b.cache.setTokensCache(s1);
    await w.run();
    track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    expect(w.requests.map((r) => r.refreshToken)).toEqual([s2.refresh_token]);

    // Another tab's takeover steals the lock while S2 is in flight.
    w.locks.forTab('thief').request(REFRESH_LOCK, { steal: true }, () => new Promise(() => undefined));
    await w.run();
    w.held[0].reject(invalidError());
    await w.run();

    const ended = posted(w, 'session-ended').map((m) => m.data as Record<string, unknown>);
    expect(ended).toHaveLength(1);
    expect(ended[0]).toMatchObject({ fp: fingerprint(s2.refresh_token), sid: 'session-again', sub: 'user-1' });
    expect(JSON.stringify(w.hub.posted)).not.toContain(fingerprint(s1.refresh_token) as string);
    expect(a.of('session:expired')).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
    expect(b.of('session:expired')).toEqual([]);
    expect(b.cache.getTokens()?.refresh_token).toBe(s1.refresh_token);

    track(a.controller.signOut(async () => undefined));
    await w.run(6_000);
    expect(posted(w, 'signed-out')).toEqual([]);
    expect(b.names()).not.toContain('signout');
  });
});

describe('cross-tab: rollout interop with portal-wrapper tabs (§2.10)', () => {
  it("accepts a v-less portal holder's refresh-failed: joiners reject unavailable and RefreshFailing{other-tab} once", async () => {
    const w = createWorld({ tabs: 1 });
    const [a] = w.tabs;
    const portal = w.hub.channel('portal');
    const thief = w.locks.forTab('portal');
    // The portal tab holds the lock, so a only waits.
    thief.request(REFRESH_LOCK, {}, () => new Promise(() => undefined));
    await w.run();
    const call = track(a.controller.refresh({ trigger: 'token-check' }));
    await w.run();
    portal.postMessage({ type: 'still-refreshing', tabId: 'portal' });
    portal.postMessage({
      type: 'refresh-failed',
      tabId: 'portal',
      message: 'down',
      from: fingerprint(w.stored()?.refresh_token),
    });
    portal.postMessage({
      type: 'refresh-failed',
      tabId: 'portal',
      message: 'down',
      from: fingerprint(w.stored()?.refresh_token),
    });
    await w.run();
    expect((call.error as PassflowRefreshError).id).toBe(RefreshErrorId.unavailable);
    expect(a.of('refresh:failing')).toEqual([{ since: 0, origin: 'other-tab' }]);
    expect(w.requests).toEqual([]);

    const next = rotate(w.stored()?.refresh_token);
    portal.postMessage({
      type: 'tokens-refreshed',
      tabId: 'portal',
      tokens: next,
      from: fingerprint(w.stored()?.refresh_token),
      fromIat: orderOf(w.stored()?.refresh_token)?.iat,
      fromSid: 's1',
      to: fingerprint(next.refresh_token),
    });
    w.storage.saveTokens(next);
    await w.run();
    expect(a.cache.getTokens()?.refresh_token).toBe(next.refresh_token);
    expect(a.of('refresh:recovered')).toEqual([{ since: 0, origin: 'other-tab' }]);
  });
});

describe('cross-tab: sign-out and session-ended scope', () => {
  it('ends every tab of the user on signed-out, after the storage is emptied', async () => {
    const w = createWorld({ tabs: 2 });
    const [a, b] = w.tabs;
    const done = track(
      a.controller.signOut(async () => {
        a.storage.deleteTokens();
        a.cache.setTokensCache(undefined);
      }),
    );
    await w.run();
    expect(done.status).toBe('resolved');
    expect(posted(w, 'signed-out')).toHaveLength(1);
    expect(b.of('signout')).toEqual([{ origin: 'other-tab', userId: 'user-1' }]);
    expect(b.cache.getTokens()).toBeUndefined();
    expect(a.names()).toEqual([]);
  });
});
