// Architecture §5.4: the credential fence's verdicts (port of the portal's
// refresh-credential-fence.ts, rounds 11-25): the pre-send storage read, the compare-and-set save,
// failure judgement, forward-only adoption, the blocked successor, held sends, emptied storage,
// and the session-end delete.
import { describe, expect, it, vi } from 'vitest';
import { PassflowError } from '../../lib/api/model';
import { EMPTIED_STORAGE_MESSAGE_WAIT_MS } from '../../lib/refresh/constants';
import { createCredentialFence, IdentityChanged, type SentCredentials, SessionEnded } from '../../lib/refresh/fence';
import { fingerprint, orderOf } from '../../lib/refresh/lineage';
import { StorageManager } from '../../lib/storage';
import type { Tokens } from '../../lib/types';
import { FakeStorage } from '../storage/fake-storage';
import { pair } from './jwt';

function fakeTimers() {
  let now = 0;
  let timers: { at: number; fn: () => void; id: number }[] = [];
  let nextId = 0;
  return {
    schedule(fn: () => void, ms: number): () => void {
      const id = nextId++;
      timers.push({ at: now + ms, fn, id });
      return () => {
        timers = timers.filter((t) => t.id !== id);
      };
    },
    advance(ms: number): void {
      const until = now + ms;
      for (;;) {
        const due = timers.filter((t) => t.at <= until).sort((a, b) => a.at - b.at)[0];
        if (!due) break;
        timers = timers.filter((t) => t.id !== due.id);
        now = due.at;
        due.fn();
      }
      now = until;
    },
    pending: () => timers.length,
  };
}

interface SetupOptions {
  stored?: Tokens;
  cached?: Tokens;
  identity?: string;
  /** false: no onSessionLost / onStoredSessionSeen (no watch, no emptied wait). */
  watch?: boolean;
}

function setup(options: SetupOptions = {}) {
  const raw = new FakeStorage();
  const storage = new StorageManager({ storage: raw });
  if (options.stored) storage.saveTokens(options.stored);
  let cached: Tokens | undefined = options.cached;
  const cache = {
    getTokens: () => cached,
    setTokensCache: vi.fn((tokens: Tokens | undefined) => {
      cached = tokens;
    }),
    stopTokenCheck: vi.fn(),
  };
  const timers = fakeTimers();
  const storageListeners = new Set<() => void>();
  const wakeListeners = new Set<() => void>();
  const onSessionLost = vi.fn();
  const onStoredSessionSeen = vi.fn();
  const warn = vi.fn();
  const watch = options.watch !== false;
  const fence = createCredentialFence({
    storage,
    cache,
    identity: () => options.identity,
    schedule: timers.schedule,
    onStorageChange: (listener) => {
      storageListeners.add(listener);
      return () => storageListeners.delete(listener);
    },
    onWake: (listener) => {
      wakeListeners.add(listener);
      return () => wakeListeners.delete(listener);
    },
    onSessionLost: watch ? onSessionLost : undefined,
    onStoredSessionSeen: watch ? onStoredSessionSeen : undefined,
    warn,
  });
  return {
    fence,
    storage,
    cache,
    timers,
    onSessionLost,
    onStoredSessionSeen,
    warn,
    cached: () => cached,
    stored: () => storage.getTokens(),
    /** Another tab wrote storage: write, then fire the storage event. */
    write(tokens: Tokens | undefined) {
      if (tokens) storage.saveTokens(tokens);
      else storage.deleteTokens();
      for (const listener of Array.from(storageListeners)) listener();
    },
    wake() {
      for (const listener of Array.from(wakeListeners)) listener();
    },
    storageListeners,
    wakeListeners,
  };
}

function send(fence: ReturnType<typeof setup>['fence'], token: string | undefined): SentCredentials {
  const verdict = fence.beginSend(token ?? '');
  if (verdict.kind !== 'send') throw new Error(`expected send, got ${verdict.kind}`);
  return verdict.sent;
}

function blocked(): PassflowError {
  return new PassflowError({ id: 'error.token.blocked', message: 'blocked', status: 400, location: '/auth/refresh', time: '' });
}

function invalid(): PassflowError {
  return new PassflowError({
    id: 'error.token.invalid.error',
    message: 'invalid',
    status: 400,
    location: '/auth/refresh',
    time: '',
  });
}

function unavailable(): PassflowError {
  return new PassflowError({ id: 'error.http.503', message: 'down', status: 503, location: '/auth/refresh', time: '' });
}

function order(tokens: Tokens) {
  const result = orderOf(tokens.refresh_token);
  if (!result) throw new Error('no order');
  return result;
}

function tokensRefreshed(from: Tokens, to: Tokens) {
  const fromOrder = order(from);
  return {
    from: fromOrder.fp,
    fromIat: fromOrder.iat,
    fromSid: fromOrder.sid ?? '',
    to: fingerprint(to.refresh_token),
    tokens: to,
  };
}

describe('StorageManager.tokenKeys', () => {
  it('should list every key of the token session, prefixed', () => {
    const storage = new StorageManager({ storage: new FakeStorage(), prefix: 'app' });
    expect(storage.tokenKeys()).toEqual([
      'app_id_token',
      'app_access',
      'app_refresh',
      'tokens_scopes',
      'passflow_id_token',
      'passflow_csrf_token',
      'passflow_delivery_mode',
    ]);
  });

  it('should name the keys saveTokens and deleteTokens touch', () => {
    const raw = new FakeStorage();
    const storage = new StorageManager({ storage: raw });
    storage.saveTokens({ ...pair(100), id_token: 'id' });
    for (const key of raw.data.keys()) expect(storage.tokenKeys()).toContain(key);
  });
});

describe('checkStoredBeforeSend', () => {
  it('should send when storage holds the cached token', () => {
    const tokens = pair(100);
    const { fence } = setup({ stored: tokens, cached: tokens });
    expect(fence.checkStoredBeforeSend()).toBe('send');
  });

  it('should adopt a newer token of the same session and retire the cached one', () => {
    const held = pair(100);
    const newer = pair(200);
    const { fence, cached } = setup({ stored: newer, cached: held });
    expect(fence.checkStoredBeforeSend()).toBe('adopted');
    expect(cached()?.refresh_token).toBe(newer.refresh_token);
    expect(fence.lineage.isRetired(order(held))).toBe(true);
  });

  it('should adopt what storage holds when the cache is empty', () => {
    const stored = pair(100);
    const { fence, cached } = setup({ stored });
    expect(fence.checkStoredBeforeSend()).toBe('adopted');
    expect(cached()?.refresh_token).toBe(stored.refresh_token);
  });

  it('should hold (send nothing, keep the cache) when storage shows an older token of the session', () => {
    const held = pair(200);
    const { fence, cached } = setup({ stored: pair(100), cached: held });
    expect(fence.checkStoredBeforeSend()).toBe('held');
    expect(cached()).toBe(held);
  });

  it("should throw IdentityChanged when storage holds another user's tokens", () => {
    const { fence } = setup({ stored: pair(200, 's9', 'user-2'), cached: pair(100), identity: 'user-1' });
    expect(() => fence.checkStoredBeforeSend()).toThrow(IdentityChanged);
  });

  it('should fall back to the cached tokens subject when the tab has no identity', () => {
    const { fence } = setup({ stored: pair(200, 's9', 'user-2'), cached: pair(100) });
    expect(() => fence.checkStoredBeforeSend()).toThrow(IdentityChanged);
  });

  it('should throw SessionEnded when the stored token belongs to an ended session', () => {
    const stored = pair(200);
    const { fence } = setup({ stored, cached: pair(100) });
    fence.endLineage({ ...order(stored), sub: 'user-1' });
    expect(() => fence.checkStoredBeforeSend()).toThrow(SessionEnded);
  });

  it('should hold when the stored token ended but the cache is ahead of it', () => {
    const stored = pair(100);
    const { fence } = setup({ stored, cached: pair(200), identity: 'user-1' });
    fence.endLineage({ ...order(stored) });
    expect(fence.checkStoredBeforeSend()).toBe('held');
  });

  it("should send another session's token of the same user (a sign-in again), whatever its iat", () => {
    const { fence, cached } = setup({ stored: pair(50, 's2'), cached: pair(100, 's1') });
    const before = cached();
    expect(fence.checkStoredBeforeSend()).toBe('send');
    expect(cached()).toBe(before);
  });

  it('should adopt another session of the same user once the cached token is known retired', () => {
    const held = pair(100, 's1');
    const other = pair(50, 's2');
    const { fence, cached } = setup({ stored: other, cached: held });
    fence.lineage.retire(order(held));
    expect(fence.checkStoredBeforeSend()).toBe('adopted');
    expect(cached()?.refresh_token).toBe(other.refresh_token);
  });

  it('should send on a same-second tie neither side of which is known retired', () => {
    const { fence } = setup({ stored: pair(100), cached: pair(100) });
    expect(fence.checkStoredBeforeSend()).toBe('send');
  });

  it('should throw SessionEnded on an emptied storage when nothing can wait for a message', () => {
    const { fence } = setup({ cached: pair(100), watch: false });
    expect(() => fence.checkStoredBeforeSend()).toThrow(SessionEnded);
  });

  it('should hold on an emptied storage while it waits for the explaining message, then end', () => {
    const { fence, timers, onSessionLost } = setup({ cached: pair(100), identity: 'user-1' });
    expect(fence.checkStoredBeforeSend()).toBe('held');
    expect(onSessionLost).not.toHaveBeenCalled();
    timers.advance(EMPTIED_STORAGE_MESSAGE_WAIT_MS - 1);
    expect(onSessionLost).not.toHaveBeenCalled();
    timers.advance(1);
    expect(onSessionLost).toHaveBeenCalledWith('emptied');
  });
});

describe('beginSend', () => {
  it('should send, recording the tab identity as the request user', () => {
    const tokens = pair(100);
    const { fence } = setup({ stored: tokens, cached: tokens, identity: 'user-1' });
    const verdict = fence.beginSend(tokens.refresh_token);
    expect(verdict).toEqual({
      kind: 'send',
      sent: { refreshToken: tokens.refresh_token, sub: 'user-1', order: order(tokens) },
    });
  });

  it("should never send another user's refresh token", () => {
    const other = pair(100, 's9', 'user-2');
    const { fence } = setup({ stored: other, cached: pair(100), identity: 'user-1' });
    expect(fence.beginSend(other.refresh_token)).toEqual({ kind: 'identity-changed' });
  });

  it('should never send a token of an ended session, superseded when the cache is ahead of it', () => {
    const dead = pair(100);
    const { fence } = setup({ stored: dead, cached: dead, identity: 'user-1' });
    fence.endLineage(order(dead));
    expect(fence.beginSend(dead.refresh_token)).toEqual({ kind: 'ended' });

    const ahead = setup({ stored: dead, cached: pair(200), identity: 'user-1' });
    ahead.fence.endLineage(order(dead));
    expect(ahead.fence.beginSend(dead.refresh_token)).toEqual({ kind: 'superseded' });
  });

  it('should not send a retired token while the cache holds its successor', () => {
    const old = pair(100);
    const { fence } = setup({ stored: old, cached: pair(200) });
    fence.lineage.retire(order(old));
    expect(fence.beginSend(old.refresh_token)).toEqual({ kind: 'superseded' });
  });
});

describe('commitSave (compare-and-set)', () => {
  it('should save, cache and retire the sent token when storage still holds it', () => {
    const before = pair(100);
    const after = pair(200);
    const { fence, stored, cached } = setup({ stored: before, cached: before, identity: 'user-1' });
    const sent = send(fence, before.refresh_token);
    expect(fence.commitSave(sent, after)).toEqual({ kind: 'saved' });
    expect(stored()?.refresh_token).toBe(after.refresh_token);
    expect(cached()).toBe(after);
    expect(fence.lineage.isRetired(sent.order)).toBe(true);
  });

  it('should drop the answer and adopt newer stored tokens of the same user (superseded)', () => {
    const before = pair(100);
    const theirs = pair(200);
    const mine = pair(201);
    const { fence, stored, cached, write } = setup({ stored: before, cached: before, identity: 'user-1' });
    const sent = send(fence, before.refresh_token);
    write(theirs);
    expect(fence.commitSave(sent, mine)).toEqual({ kind: 'superseded', adopted: true });
    expect(stored()?.refresh_token).toBe(theirs.refresh_token);
    expect(cached()?.refresh_token).toBe(theirs.refresh_token);
  });

  it('should drop the answer and adopt nothing when storage shows an older token than the cache', () => {
    const old = pair(100);
    const sentTokens = pair(150);
    const held = pair(300);
    const { fence, storage, cached } = setup({ stored: sentTokens, cached: held, identity: 'user-1' });
    const sent: SentCredentials = { refreshToken: sentTokens.refresh_token, sub: 'user-1', order: order(sentTokens) };
    storage.saveTokens(old);
    expect(fence.commitSave(sent, pair(400))).toEqual({ kind: 'superseded', adopted: false });
    expect(cached()).toBe(held);
  });

  it('should refuse a late answer for a session that ended meanwhile, even while storage holds the sent token', () => {
    const before = pair(100);
    const { fence, stored } = setup({ stored: before, cached: before, identity: 'user-1' });
    const sent = send(fence, before.refresh_token);
    fence.endLineage(order(before));
    expect(fence.commitSave(sent, pair(200))).toEqual({ kind: 'ended', cause: 'ended' });
    expect(stored()?.refresh_token).toBe(before.refresh_token);
  });

  it('should refuse to write after a sign-out emptied storage', () => {
    const before = pair(100);
    const { fence, stored, write } = setup({ stored: before, cached: before, identity: 'user-1', watch: false });
    const sent = send(fence, before.refresh_token);
    write(undefined);
    expect(fence.commitSave(sent, pair(200))).toEqual({ kind: 'ended', cause: 'emptied' });
    expect(stored()).toBeUndefined();
  });

  it("should not save into another user's storage", () => {
    const before = pair(100);
    const other = pair(300, 's9', 'user-2');
    const { fence, stored, cached, write } = setup({ stored: before, cached: before, identity: 'user-1' });
    const sent = send(fence, before.refresh_token);
    write(other);
    expect(fence.commitSave(sent, pair(200))).toEqual({ kind: 'identity-changed', saved: false });
    expect(stored()?.refresh_token).toBe(other.refresh_token);
    expect(cached()).toBe(before);
  });

  it("should store another user's answer for them but adopt nothing", () => {
    const before = pair(100);
    const theirs = pair(200, 's9', 'user-2');
    const { fence, stored, cached } = setup({ stored: before, cached: before, identity: 'user-1' });
    const sent = send(fence, before.refresh_token);
    expect(fence.commitSave(sent, theirs)).toEqual({ kind: 'identity-changed', saved: true });
    expect(stored()?.refresh_token).toBe(theirs.refresh_token);
    expect(cached()).toBe(before);
  });

  it("should refuse a stolen holder's late 200 when the cache already holds a later token of the session (logged)", () => {
    const sentTokens = pair(100);
    const adopted = pair(200);
    const late = pair(201);
    const { fence, stored, cached, warn } = setup({ stored: sentTokens, cached: sentTokens, identity: 'user-1' });
    const sent = send(fence, sentTokens.refresh_token);
    // The new holder's broadcast arrives while this tab's view of storage still shows the sent token.
    expect(fence.adoptTokens(tokensRefreshed(sentTokens, adopted))).toBe(true);
    expect(fence.commitSave(sent, late)).toEqual({ kind: 'superseded', adopted: false });
    expect(stored()?.refresh_token).toBe(sentTokens.refresh_token);
    expect(cached()?.refresh_token).toBe(adopted.refresh_token);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('should refuse a late 200 when the cache holds a later token of the session even if the sent one is not known retired', () => {
    const sentTokens = pair(100);
    const later = pair(200);
    const { fence, stored, cached } = setup({ stored: sentTokens, cached: later, identity: 'user-1' });
    const sent: SentCredentials = { refreshToken: sentTokens.refresh_token, sub: 'user-1', order: order(sentTokens) };
    expect(fence.commitSave(sent, pair(201))).toEqual({ kind: 'superseded', adopted: false });
    expect(stored()?.refresh_token).toBe(sentTokens.refresh_token);
    expect(cached()).toBe(later);
    expect(fence.lineage.isRetired(sent.order)).toBe(true);
  });

  it('should save a held send although the cache holds a later token of its session', () => {
    const storedOld = pair(100);
    const cachedLater = pair(200);
    const answer = pair(300);
    const { fence, stored, cached } = setup({ stored: storedOld, cached: cachedLater, identity: 'user-1' });
    expect(fence.checkStoredBeforeSend()).toBe('held');
    expect(fence.beginHeldSend()).toBe(true);
    const sent = send(fence, storedOld.refresh_token);
    expect(sent.held).toEqual({ cachedFp: order(cachedLater).fp });
    expect(fence.commitSave(sent, answer)).toEqual({ kind: 'saved' });
    expect(stored()?.refresh_token).toBe(answer.refresh_token);
    expect(cached()).toBe(answer);
    // The cached token is not retired by the save.
    expect(fence.lineage.isRetired(order(cachedLater))).toBe(false);
  });
});

describe('judgeFailure', () => {
  it("should pass the request's own failure through, classified", () => {
    const tokens = pair(100);
    const { fence } = setup({ stored: tokens, cached: tokens, identity: 'user-1' });
    const sent = send(fence, tokens.refresh_token);
    expect(fence.judgeFailure(sent, unavailable())).toEqual({
      kind: 'own',
      failure: { kind: 'transient', status: 503, id: 'error.http.503' },
      heldRefused: false,
    });
    expect(fence.judgeFailure(sent, invalid())).toMatchObject({ kind: 'own', failure: { kind: 'auth' }, heldRefused: false });
    expect(fence.lineage.isRetired(sent.order)).toBe(false);
  });

  it('should retire a blocked token and later adopt its successor from storage, forward only', () => {
    const tokens = pair(100);
    const { fence, cached, write } = setup({ stored: tokens, cached: tokens, identity: 'user-1' });
    const sent = send(fence, tokens.refresh_token);
    expect(fence.judgeFailure(sent, blocked())).toMatchObject({
      kind: 'own',
      failure: { kind: 'blocked' },
      heldRefused: false,
    });
    expect(fence.lineage.isRetired(sent.order)).toBe(true);
    expect(fence.adoptSuccessor()).toBe(false);
    // A predecessor appears: still waiting.
    write(pair(90));
    expect(fence.adoptSuccessor()).toBe(false);
    const successor = pair(200);
    write(successor);
    expect(fence.adoptSuccessor()).toBe(true);
    expect(cached()?.refresh_token).toBe(successor.refresh_token);
  });

  it('should count a same-second successor after a blocked send (the refused token is retired)', () => {
    const tokens = pair(100);
    const { fence, write } = setup({ stored: tokens, cached: tokens, identity: 'user-1' });
    fence.judgeFailure(send(fence, tokens.refresh_token), blocked());
    write(pair(100));
    expect(fence.adoptSuccessor()).toBe(true);
  });

  it("should take another session of the user as the blocked token's successor", () => {
    const tokens = pair(100, 's1');
    const { fence, write } = setup({ stored: tokens, cached: tokens, identity: 'user-1' });
    fence.judgeFailure(send(fence, tokens.refresh_token), blocked());
    write(pair(50, 's2'));
    expect(fence.adoptSuccessor()).toBe(true);
  });

  it("should never take another user's tokens as a successor", () => {
    const tokens = pair(100);
    const { fence, write, onSessionLost, cached } = setup({ stored: tokens, cached: tokens, identity: 'user-1' });
    fence.judgeFailure(send(fence, tokens.refresh_token), blocked());
    onSessionLost.mockClear();
    write(pair(200, 's9', 'user-2'));
    onSessionLost.mockClear();
    expect(fence.adoptSuccessor()).toBe(false);
    expect(cached()).toBe(tokens);
  });

  it('should read a refused held send as no strike: the cached token is the successor at once', () => {
    const storedOld = pair(100);
    const cachedLater = pair(200);
    const { fence } = setup({ stored: storedOld, cached: cachedLater, identity: 'user-1' });
    expect(fence.beginHeldSend()).toBe(true);
    const sent = send(fence, storedOld.refresh_token);
    expect(fence.judgeFailure(sent, invalid())).toMatchObject({ kind: 'own', failure: { kind: 'auth' }, heldRefused: true });
    expect(fence.lineage.isRetired(sent.order)).toBe(true);
    expect(fence.adoptSuccessor()).toBe(true);
  });

  it('should pass a transient failure of a held send through to the normal backoff', () => {
    const storedOld = pair(100);
    const { fence } = setup({ stored: storedOld, cached: pair(200), identity: 'user-1' });
    expect(fence.beginHeldSend()).toBe(true);
    const sent = send(fence, storedOld.refresh_token);
    expect(fence.judgeFailure(sent, unavailable())).toMatchObject({
      kind: 'own',
      failure: { kind: 'transient' },
      heldRefused: false,
    });
    expect(fence.lineage.isRetired(sent.order)).toBe(false);
  });

  it('should read any failure as superseded when storage moved forward meanwhile, a blocked one included', () => {
    const tokens = pair(100);
    const theirs = pair(200);
    const { fence, cached, write } = setup({ stored: tokens, cached: tokens, identity: 'user-1' });
    const sent = send(fence, tokens.refresh_token);
    write(theirs);
    expect(fence.judgeFailure(sent, blocked())).toEqual({ kind: 'superseded', adopted: true });
    expect(cached()?.refresh_token).toBe(theirs.refresh_token);
  });

  it('should read a failure as superseded when the cache adopted a successor while it was in flight', () => {
    const tokens = pair(100);
    const successor = pair(200);
    const { fence, storage, cached } = setup({ stored: tokens, cached: tokens, identity: 'user-1' });
    const sent = send(fence, tokens.refresh_token);
    // Broadcast with `from` = the held token: adopted although this tab's view of storage still
    // shows the sent token.
    expect(fence.adoptTokens(tokensRefreshed(tokens, successor))).toBe(true);
    expect(cached()?.refresh_token).toBe(successor.refresh_token);
    expect(storage.getTokens()?.refresh_token).toBe(tokens.refresh_token);
    expect(fence.judgeFailure(sent, blocked())).toEqual({ kind: 'superseded', adopted: false });
  });

  it("should end when the sent token's session ended while in flight", () => {
    const tokens = pair(100);
    const { fence } = setup({ stored: tokens, cached: tokens, identity: 'user-1' });
    const sent = send(fence, tokens.refresh_token);
    fence.endLineage(order(tokens));
    expect(fence.judgeFailure(sent, unavailable())).toEqual({ kind: 'ended', cause: 'ended' });
  });

  it("should report another user's stored tokens", () => {
    const tokens = pair(100);
    const { fence, write } = setup({ stored: tokens, cached: tokens, identity: 'user-1' });
    const sent = send(fence, tokens.refresh_token);
    write(pair(200, 's9', 'user-2'));
    expect(fence.judgeFailure(sent, unavailable())).toEqual({ kind: 'identity-changed' });
  });
});

describe('adoptTokens (forward only)', () => {
  it('should adopt the successor of the held token', () => {
    const held = pair(100);
    const next = pair(200);
    const { fence, storage, cached } = setup({ stored: held, cached: held, identity: 'user-1' });
    storage.saveTokens(next);
    expect(fence.adoptTokens(tokensRefreshed(held, next))).toBe(true);
    expect(cached()).toEqual(next);
    expect(fence.lineage.isRetired(order(held))).toBe(true);
  });

  it('should adopt a same-second successor of the held token (the sender retired it)', () => {
    const held = pair(100);
    const next = pair(100);
    const { fence, cached } = setup({ stored: held, cached: held, identity: 'user-1' });
    expect(fence.adoptTokens(tokensRefreshed(held, next))).toBe(true);
    expect(cached()?.refresh_token).toBe(next.refresh_token);
  });

  it('should never roll back to an older token (a delayed or rebroadcast message)', () => {
    const old = pair(100);
    const older = pair(50);
    const held = pair(300);
    const { fence, cached } = setup({ stored: held, cached: held, identity: 'user-1' });
    expect(fence.adoptTokens(tokensRefreshed(older, old))).toBe(false);
    expect(cached()).toBe(held);
  });

  it('should adopt a missed link only when storage already holds `to`', () => {
    const held = pair(100);
    const skipped = pair(200);
    const next = pair(300);
    const { fence, storage, cached } = setup({ stored: held, cached: held, identity: 'user-1' });
    expect(fence.adoptTokens(tokensRefreshed(skipped, next))).toBe(false);
    storage.saveTokens(next);
    expect(fence.adoptTokens(tokensRefreshed(skipped, next))).toBe(true);
    expect(cached()?.refresh_token).toBe(next.refresh_token);
    // `from` is retired under its own session once accepted.
    expect(fence.lineage.isRetired(order(skipped))).toBe(true);
  });

  it('should accept (true, nothing new) a message whose `to` the cache already holds', () => {
    const held = pair(100);
    const { fence, cache } = setup({ stored: held, cached: held, identity: 'user-1' });
    expect(fence.adoptTokens(tokensRefreshed(pair(50), held))).toBe(true);
    expect(cache.setTokensCache).not.toHaveBeenCalled();
  });

  it("should refuse another user's tokens and report the identity change", () => {
    const held = pair(100);
    const theirs = pair(200, 's9', 'user-2');
    const { fence, onSessionLost, cached } = setup({ stored: held, cached: held, identity: 'user-1' });
    expect(fence.adoptTokens(tokensRefreshed(held, theirs))).toBe(false);
    expect(onSessionLost).toHaveBeenCalledWith('identity-changed');
    expect(cached()).toBe(held);
  });

  it('should refuse when storage is empty, the pair is incomplete, or `to` is not its fingerprint', () => {
    const held = pair(100);
    const next = pair(200);
    const empty = setup({ cached: held, identity: 'user-1' });
    expect(empty.fence.adoptTokens(tokensRefreshed(held, next))).toBe(false);

    const { fence } = setup({ stored: held, cached: held, identity: 'user-1' });
    expect(fence.adoptTokens({ ...tokensRefreshed(held, next), to: 'nope' })).toBe(false);
    expect(fence.adoptTokens({ ...tokensRefreshed(held, next), tokens: { refresh_token: next.refresh_token } })).toBe(false);
    expect(fence.adoptTokens(null)).toBe(false);
    expect(fence.adoptTokens({ from: 1 })).toBe(false);
  });

  it('should never adopt a token of an ended session', () => {
    const held = pair(100);
    const next = pair(200);
    const { fence } = setup({ stored: held, cached: held, identity: 'user-1' });
    fence.endLineage(order(next));
    expect(fence.adoptTokens(tokensRefreshed(held, next))).toBe(false);
  });
});

describe('beginHeldSend', () => {
  it('should arm nothing for a stored token known rotated or ended', () => {
    const storedOld = pair(100);
    const { fence } = setup({ stored: storedOld, cached: pair(200), identity: 'user-1' });
    fence.lineage.retire(order(storedOld));
    expect(fence.beginHeldSend()).toBe(false);

    const ended = setup({ stored: storedOld, cached: pair(200), identity: 'user-1' });
    ended.fence.endLineage(order(storedOld));
    expect(ended.fence.beginHeldSend()).toBe(false);

    const empty = setup({ cached: pair(200), identity: 'user-1' });
    expect(empty.fence.beginHeldSend()).toBe(false);
  });

  it('should stop marking sends as held after endHeldSend', () => {
    const storedOld = pair(100);
    const { fence } = setup({ stored: storedOld, cached: pair(200), identity: 'user-1' });
    expect(fence.beginHeldSend()).toBe(true);
    fence.endHeldSend();
    expect(send(fence, storedOld.refresh_token).held).toBeUndefined();
  });
});

describe('deleteIfStillDead (session-end delete)', () => {
  it('should delete storage that still holds the dead token', () => {
    const dead = pair(100);
    const { fence, stored } = setup({ stored: dead, cached: dead });
    expect(fence.deleteIfStillDead(order(dead))).toBe(true);
    expect(stored()).toBeUndefined();
  });

  it('should delete storage that holds an older token of its lineage', () => {
    const dead = pair(200);
    const { fence, stored } = setup({ stored: pair(100), cached: dead });
    expect(fence.deleteIfStillDead(order(dead))).toBe(true);
    expect(stored()).toBeUndefined();
  });

  it('should delete nothing when storage holds a later live token, another session, another user or nothing', () => {
    const dead = pair(200);
    for (const stored of [pair(300), pair(200), pair(100, 's2'), pair(100, 's1', 'user-2')]) {
      const s = setup({ stored, cached: dead });
      expect(s.fence.deleteIfStillDead(order(dead))).toBe(false);
      expect(s.stored()?.refresh_token).toBe(stored.refresh_token);
    }
    expect(setup({ cached: dead }).fence.deleteIfStillDead(order(dead))).toBe(false);
  });
});

describe('storage and wake watch', () => {
  it("should report the session's user seen in storage, and another user's as an identity change", () => {
    const held = pair(100);
    const { write, wake, onStoredSessionSeen, onSessionLost } = setup({ stored: held, cached: held, identity: 'user-1' });
    write(pair(200));
    expect(onStoredSessionSeen).toHaveBeenCalledTimes(1);
    wake();
    expect(onStoredSessionSeen).toHaveBeenCalledTimes(2);
    write(pair(300, 's9', 'user-2'));
    expect(onSessionLost).toHaveBeenCalledWith('identity-changed');
  });

  it('should wait 2 s on an emptied storage with no explaining message, then end', () => {
    const held = pair(100);
    const { write, timers, onSessionLost } = setup({ stored: held, cached: held, identity: 'user-1' });
    write(undefined);
    expect(onSessionLost).not.toHaveBeenCalled();
    timers.advance(EMPTIED_STORAGE_MESSAGE_WAIT_MS);
    expect(onSessionLost).toHaveBeenCalledWith('emptied');
    expect(onSessionLost).toHaveBeenCalledTimes(1);
  });

  it('should stop waiting when storage holds a token again within the wait', () => {
    const held = pair(100);
    const { write, timers, onSessionLost, onStoredSessionSeen } = setup({ stored: held, cached: held, identity: 'user-1' });
    write(undefined);
    write(pair(200));
    expect(onStoredSessionSeen).toHaveBeenCalled();
    timers.advance(EMPTIED_STORAGE_MESSAGE_WAIT_MS * 2);
    expect(onSessionLost).not.toHaveBeenCalled();
    expect(timers.pending()).toBe(0);
  });

  it('should keep a cache that is ahead of the token a session-ended names (message before the storage event)', () => {
    const dead = pair(100);
    const held = pair(200);
    const { fence, write, timers, onSessionLost, warn } = setup({ stored: dead, cached: held, identity: 'user-1' });
    fence.endLineage(order(dead));
    fence.endedElsewhere('session-ended', order(dead));
    write(undefined);
    timers.advance(EMPTIED_STORAGE_MESSAGE_WAIT_MS * 2);
    expect(onSessionLost).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
    // Nothing to send while the storage is empty: held, not ended.
    expect(fence.checkStoredBeforeSend()).toBe('held');
  });

  it('should keep the cache when the explaining session-ended arrives after the storage event', () => {
    const dead = pair(100);
    const held = pair(200);
    const { fence, write, timers, onSessionLost } = setup({ stored: dead, cached: held, identity: 'user-1' });
    write(undefined);
    fence.endLineage(order(dead));
    fence.endedElsewhere('session-ended', order(dead));
    timers.advance(EMPTIED_STORAGE_MESSAGE_WAIT_MS * 2);
    expect(onSessionLost).not.toHaveBeenCalled();
  });

  it('should end at once on a signed-out of its user when the view is empty', () => {
    const held = pair(100);
    const { fence, write, onSessionLost } = setup({ stored: held, cached: held, identity: 'user-1' });
    write(undefined);
    fence.endedElsewhere('signed-out', { ...order(held) });
    expect(onSessionLost).toHaveBeenCalledWith('emptied');
  });

  it('should end when the session-ended names its own token (not ahead)', () => {
    const held = pair(100);
    const { fence, write, onSessionLost } = setup({ stored: held, cached: held, identity: 'user-1' });
    fence.endLineage(order(held));
    fence.endedElsewhere('session-ended', order(held));
    write(undefined);
    expect(onSessionLost).toHaveBeenCalledWith('emptied');
  });

  it('should spend an end on the emptying it explained: a later emptying waits again', () => {
    const dead = pair(100);
    const held = pair(200);
    const { fence, write, timers, onSessionLost } = setup({ stored: dead, cached: held, identity: 'user-1' });
    fence.endedElsewhere('session-ended', order(dead));
    write(undefined);
    expect(onSessionLost).not.toHaveBeenCalled();
    write(held);
    write(undefined);
    timers.advance(EMPTIED_STORAGE_MESSAGE_WAIT_MS);
    expect(onSessionLost).toHaveBeenCalledWith('emptied');
  });

  it('should remove its listeners and cancel the wait on stop()', () => {
    const held = pair(100);
    const { fence, write, timers, storageListeners, wakeListeners, onSessionLost } = setup({
      stored: held,
      cached: held,
      identity: 'user-1',
    });
    write(undefined);
    fence.stop();
    expect(storageListeners.size).toBe(0);
    expect(wakeListeners.size).toBe(0);
    timers.advance(EMPTIED_STORAGE_MESSAGE_WAIT_MS);
    expect(onSessionLost).not.toHaveBeenCalled();
  });

  it('should not subscribe without onSessionLost and onStoredSessionSeen', () => {
    const { storageListeners, wakeListeners } = setup({ watch: false });
    expect(storageListeners.size).toBe(0);
    expect(wakeListeners.size).toBe(0);
  });
});

describe('session lineage and dropSession', () => {
  it('should name the cached and stored tokens by fingerprint, claims and the tab identity', () => {
    const held = pair(200);
    const stored = pair(100);
    const { fence } = setup({ stored, cached: held, identity: 'user-1' });
    expect(fence.session()).toEqual({ fp: order(held).fp, sub: 'user-1', sid: 's1', iat: 200 });
    expect(fence.storedSession()).toEqual({ fp: order(stored).fp, sub: 'user-1', sid: 's1', iat: 100 });
    expect(setup().fence.session()).toEqual({});
  });

  it('should drop the cache and stop the token check without touching storage', () => {
    const held = pair(100);
    const { fence, cache, stored, cached } = setup({ stored: held, cached: held });
    fence.dropSession();
    expect(cached()).toBeUndefined();
    expect(cache.stopTokenCheck).toHaveBeenCalledTimes(1);
    expect(stored()?.refresh_token).toBe(held.refresh_token);
  });
});
