/**
 * The credential fence: every storage read and write of the refresh path (architecture §5.4).
 * Port of the portal's `refresh-credential-fence.ts` (PFL-764 rounds 11-25) without the wrapping:
 * the portal monkey-patched `authApi.refreshToken` and `storageManager.saveTokens` and threw
 * replacement errors; here the controller calls the fence directly and gets verdicts back.
 *
 * It keeps a refresh sent in one session from overwriting the next one's tokens, or failing into
 * it: a compare-and-set on the refresh token the request sent, ordered by the refresh JWT's own
 * claims (lineage.ts). Under cross-tab coordination only the lock holder sends, so these checks
 * are what drop a late answer: a stolen holder's, or one that arrives after a sign-out.
 *
 * Rules (each is a portal round, kept so reviewers can diff the behaviour):
 *   - Forward only on every path that writes the cache (adoptTokens, checkStoredBeforeSend, the
 *     save and failure checks, adoptSuccessor): never a token issued before the one held, retired
 *     or ended, and never a same-second token while the one held is not known retired. Once the
 *     held token is known retired, a live token of another session of this user (a sign-in again)
 *     is taken too, whatever its iat.
 *   - A request whose refresh token is retired while the cache holds a later one is not sent
 *     (superseded); nor is its late 200 saved.
 *   - The save is forward only too: a 200 is not saved while the cache holds a later token of the
 *     sent token's session (the sent token was rotated elsewhere; saving this second successor
 *     would roll shared storage back). Except for a held send (below).
 *   - A blocked send's successor is any live token issued after the one it sent, cached before or
 *     after the refusal arrived, or a live token of another session of this user.
 *   - A held send (beginHeldSend) sends the stored token only when this tab does not know it was
 *     rotated, and its refusal on authentication, blocked or not, is never a strike: the sent
 *     token is retired and the cached token, after it, is the successor.
 *   - A request whose refresh token's session ended is not sent, and its late result is not
 *     saved. When the cache holds a live token ahead of the ended one, the outcome is superseded
 *     (the cache kept), not this tab's end.
 *
 * Identity. "The request's user" is this tab's identity when the request was sent (deps.identity:
 * the `sub` the tab's state was built for), else the `sub` of the token sent. A request whose
 * stored token is another user's is never sent. A result whose tokens are another user's is still
 * saved (the server already consumed the token it rotates, and dropping the successor would end
 * that user's session) but not adopted.
 *
 * Emptied storage (rounds 23-24). A tab whose own refresh finds its token dead ends the session in
 * every tab on it (session-ended naming that token) and empties the shared storage. When that
 * token is older than the one another tab caches, the emptying must not end that other tab. Every
 * place that would end a tab on an empty storage asks judgeEmptied:
 *   - keep: the newest session-ended of this user from another tab (not spent on an earlier
 *     emptying) names a token the cache is provably ahead of, and no signed-out of this user
 *     arrived since. The tab keeps its cache and sends nothing.
 *   - wait: no such message yet, but the cache could outlive one: wait for it, at most
 *     EMPTIED_STORAGE_MESSAGE_WAIT_MS (a storage event may arrive before the message).
 *   - end: anything else (a signed-out of this user, an end naming this tab's token or a later
 *     one, a retired/ended/unordered cache, no message within the wait).
 *   - An end explains one emptying: once the view shows a token again, the ends heard before it
 *     last showed none, and the one a "keep" used, are spent.
 *
 * The fence emits no events and never touches the expiry flag or the token check: that is the
 * controller's job, which turns every verdict into the event sequence of architecture §2.4.
 * JSON delivery mode only: cookie and BFF modes have no readable refresh token to fence.
 *
 * @module refresh/fence
 */

import { getDefaultLogger } from '../services/logger';
import type { StorageManager } from '../storage';
import { parseToken } from '../token/service';
import type { Tokens } from '../types';
import { classifyRefreshFailure, type RefreshFailureClass } from './classify';
import { EMPTIED_STORAGE_MESSAGE_WAIT_MS, ENDED_MEMORY } from './constants';
import {
  createRefreshLineage,
  type EndedSession,
  fingerprint,
  orderOf,
  type RefreshLineage,
  type RefreshTokenOrder,
} from './lineage';
import type { WireLineage } from './protocol';

/** The verdict of the storage read under the lock, before a send. */
export type StoredVerdict = 'send' | 'adopted' | 'held';

/** Why the standing watch found the session lost outside a refresh. */
export type SessionLostCause = 'emptied' | 'identity-changed';

/** Internal signal from {@link CredentialFence.checkStoredBeforeSend}: the session ended. */
export class SessionEnded extends Error {
  /** `emptied`: storage holds no refresh token. `ended`: the stored token's session ended. */
  readonly cause: 'emptied' | 'ended';

  constructor(cause: 'emptied' | 'ended') {
    super(
      cause === 'emptied' ? 'The shared token storage was emptied' : 'The stored refresh token belongs to an ended session',
    );
    this.name = 'SessionEnded';
    this.cause = cause;
  }
}

/** Internal signal from {@link CredentialFence.checkStoredBeforeSend}: storage holds another user's tokens. */
export class IdentityChanged extends Error {
  constructor() {
    super("The shared token storage holds another user's tokens");
    this.name = 'IdentityChanged';
  }
}

/** What a refresh request was sent with. */
export interface SentCredentials {
  refreshToken: string;
  /** The user the request belongs to: this tab's identity, else the sent token's `sub`. */
  sub?: string;
  order: RefreshTokenOrder;
  /** A held send's request: the fingerprint of the token the cache held when it was sent. */
  held?: { cachedFp?: string };
}

export type SendVerdict =
  | { kind: 'send'; sent: SentCredentials }
  /** The cache holds a successor of the stored token (already rotated, or its older session ended): nothing to send. */
  | { kind: 'superseded' }
  /** The stored token's session ended and the cache is not ahead of it. */
  | { kind: 'ended' }
  /** Storage holds another user's refresh token. */
  | { kind: 'identity-changed' };

export type SaveVerdict =
  /** Saved: storage and cache hold the new tokens; the sent token is retired. */
  | { kind: 'saved' }
  /** Dropped. `adopted`: the cache now holds the newer stored tokens. */
  | { kind: 'superseded'; adopted: boolean }
  /** Dropped. The session ended: storage emptied with no keeping end, or the sent token's session ended. */
  | { kind: 'ended'; cause: 'emptied' | 'ended' }
  /** Storage (or the answer) holds another user's tokens. `saved`: the answer was stored for them. */
  | { kind: 'identity-changed'; saved: boolean };

export type FailureVerdict =
  /**
   * The request's own failure. When `failure.kind` is `blocked`, or `heldRefused`, the sent token
   * is retired and adoptSuccessor searches for its successor. `heldRefused`: a held send refused
   * on authentication (blocked or auth): never a strike, the cache is the successor.
   */
  | { kind: 'own'; failure: RefreshFailureClass; heldRefused: boolean }
  | { kind: 'superseded'; adopted: boolean }
  | { kind: 'ended'; cause: 'emptied' | 'ended' }
  | { kind: 'identity-changed' };

export interface CredentialFenceDeps {
  storage: Pick<StorageManager, 'getTokens' | 'saveTokens' | 'deleteTokens'>;
  /** The tab's token cache (TokenCacheService). `stopTokenCheck` is optional: test fakes lack it. */
  cache: {
    getTokens(): Tokens | undefined;
    setTokensCache(tokens: Tokens | undefined): void;
    stopTokenCheck?(): void;
  };
  /** This tab's identity (per session generation). Without it the cached tokens' `sub` stands in. */
  identity?: () => string | undefined;
  /** A cancellable timer (the clock's setTimeout), for the emptied-storage wait. */
  schedule: (fn: () => void, ms: number) => () => void;
  /** Shared lineage memory. Default: a new one. */
  lineage?: RefreshLineage;
  /** Another tab wrote the shared storage. Returns unsubscribe. */
  onStorageChange?: (listener: () => void) => () => void;
  /** This tab woke up (platform.onForeground): it may have missed storage events. Returns unsubscribe. */
  onWake?: (listener: () => void) => () => void;
  /**
   * The standing watch found the session lost outside a refresh. Without it there is no wait on
   * an emptied storage: it ends at once.
   */
  onSessionLost?: (cause: SessionLostCause) => void;
  /** The watch read storage and found this tab's user's session: an awaited successor may be there. */
  onStoredSessionSeen?: () => void;
  warn?: (message: string) => void;
}

export interface CredentialFence {
  /** The lineage memory (retired floors, ended sessions) this fence orders by. */
  readonly lineage: RefreshLineage;
  /**
   * The storage read under the lock, before sending:
   *   - no refresh token stored: kept or waiting (judgeEmptied) → "held"; else throws SessionEnded;
   *   - the stored one is the cached one: "send";
   *   - another user's stored: throws IdentityChanged;
   *   - an ended one stored: "held" when the cache is ahead of it, else throws SessionEnded;
   *   - a newer one of the same user (forward, or a live one of another session once the cached
   *     one is known retired): adopts it, "adopted";
   *   - one of another session of this user: "send" (storage only moves forward);
   *   - an older or replaced one of the same session while the cache holds a live later one: "held";
   *   - otherwise (a same-second tie neither side of which is known retired, or no order): "send".
   */
  checkStoredBeforeSend(): StoredVerdict;
  /** At the send, with the stored refresh token about to be sent: whether to send it, and what it was sent with. */
  beginSend(refreshToken: string): SendVerdict;
  /** A 200 for `sent`. Synchronous: no await between the storage read and the write. */
  commitSave(sent: SentCredentials, tokens: Tokens): SaveVerdict;
  /** A failure for `sent`: stale checks first, then blocked / held-send handling. */
  judgeFailure(sent: SentCredentials, error: unknown): FailureVerdict;
  /**
   * Another tab's tokens-refreshed `{ from, fromIat, fromSid, to, tokens }`, forward only. True
   * when the cache now holds `to`. Another user's tokens report the identity change.
   */
  adoptTokens(message: unknown): boolean;
  /** After a blocked send (or a refused held send): true when this tab holds, or just adopted from storage, a successor. */
  adoptSuccessor(): boolean;
  /** A held send starts under the lock. False (nothing armed) when the stored token is known rotated or ended. */
  beginHeldSend(): boolean;
  endHeldSend(): void;
  /** The session of this refresh token ended: never send it, nor an older token of its session. */
  endLineage(session: EndedSession): void;
  /** Another tab's session-ended or signed-out, after endLineage: may explain an emptied storage. */
  endedElsewhere(type: 'session-ended' | 'signed-out', session: WireLineage): void;
  /** The session this tab caches, for the lineage of the messages it sends and applies. */
  session(): WireLineage;
  /** The same for the refresh token storage holds now (the token the next send would send). */
  storedSession(): WireLineage;
  /** Drops this tab's cache without touching the shared storage (another tab ended the session there). */
  dropSession(): void;
  /**
   * Session end after the last strike: deletes the stored tokens only if storage still holds the
   * dead token or an older one of its lineage. True when it deleted.
   */
  deleteIfStillDead(dead: RefreshTokenOrder): boolean;
  /** Removes the storage and wake listeners and cancels the emptied-storage wait. */
  stop(): void;
}

function subOf(token: string | undefined): string | undefined {
  if (!token) return undefined;
  try {
    const sub = (parseToken(token) as { sub?: unknown }).sub;
    return typeof sub === 'string' && sub !== '' ? sub : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The user stored tokens belong to: the access token's `sub`, else the refresh token's, else (cookie
 * and BFF modes, where only the id token is readable) the id token's.
 */
export function tokensSubject(tokens: Tokens | undefined): string | undefined {
  return subOf(tokens?.access_token) ?? subOf(tokens?.refresh_token) ?? subOf(tokens?.id_token);
}

/** `token` was issued before `ref`, in the same session (sid): the claims order them. */
function isOlderInSession(token: RefreshTokenOrder, ref: RefreshTokenOrder | undefined): boolean {
  if (!ref || token.iat === undefined || ref.iat === undefined) return false;
  return token.sid === ref.sid && token.iat < ref.iat;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

export function createCredentialFence(deps: CredentialFenceDeps): CredentialFence {
  const { storage, cache, schedule } = deps;
  const identityOf = deps.identity ?? (() => undefined);
  const warn = deps.warn ?? ((message: string) => getDefaultLogger().warn(message));
  const lineage = deps.lineage ?? createRefreshLineage(warn);
  const onSessionLost = deps.onSessionLost;

  // Emptied storage bookkeeping (rounds 23-24). endSeq counts other tabs' end messages;
  // lastStored.seq is the endSeq when this tab's view first showed the token it last showed.
  let lastStored: { fp: string; seq: number } | undefined;
  let endSeq = 0;
  const deadEnds: (EndedSession & { seq: number })[] = [];
  const signedOuts: { sub?: string; seq: number }[] = [];
  // Ends up to endsFloor are spent (they explained an earlier emptying).
  let endsFloor = 0;
  let emptySeenSeq: number | undefined;
  let keptSeq = 0;
  let cancelEmptiedWait: (() => void) | undefined;
  // The end this tab last logged keeping its cache over.
  let keptOver: string | undefined;

  // The latest send refused as already used (or a held send refused on authentication): a
  // successor comes after it.
  let blockedSend: RefreshTokenOrder | undefined;
  // While a held send holds the lock: the stored token it sends, and the token the cache held.
  let heldSend: { fp: string; cachedFp?: string } | undefined;

  const storedTokens = (): Tokens | undefined => {
    const stored = storage.getTokens();
    const refresh = stored?.refresh_token;
    if (!refresh) {
      emptySeenSeq = endSeq;
      return stored;
    }
    if (emptySeenSeq !== undefined) {
      endsFloor = Math.max(endsFloor, emptySeenSeq, keptSeq);
      emptySeenSeq = undefined;
    }
    const fp = fingerprint(refresh) ?? '';
    if (fp !== lastStored?.fp) lastStored = { fp, seq: endSeq };
    return stored;
  };

  const cachedOrder = (): RefreshTokenOrder | undefined => orderOf(cache.getTokens()?.refresh_token);
  const tabSubject = (): string | undefined => identityOf() ?? tokensSubject(cache.getTokens());

  // The cache holds a live, ordered refresh token of this tab's user. Only such a cache can be
  // provably ahead of another tab's end.
  const cacheMayOutlive = (): boolean => {
    const current = cachedOrder();
    if (!current || current.iat === undefined || !tabSubject()) return false;
    return !lineage.isRetired(current) && !lineage.isEnded(current);
  };

  // The cache holds a live token of this tab's user ahead of `ref` (a token whose session another
  // tab ended): later by the lineage order, or of another session of this user. Anything this tab
  // cannot order is not ahead (fail safe: it ends).
  const cacheAheadOf = (ref: RefreshTokenOrder): boolean => {
    const current = cachedOrder();
    if (!current || current.fp === ref.fp) return false;
    if (!cacheMayOutlive()) return false;
    const sub = tabSubject();
    if (!ref.sub || sub !== ref.sub) return false;
    if (current.iat === undefined || ref.iat === undefined) return false;
    return current.sid !== ref.sid || lineage.isAfter(current, ref);
  };

  const signedOutSince = (seq: number): boolean => {
    const sub = tabSubject();
    return signedOuts.some((each) => each.seq > seq && (!each.sub || !sub || each.sub === sub));
  };

  // The newest unspent session-ended of this tab's user (an end with no `sub` counts as this user's).
  const latestEnd = (): (EndedSession & { seq: number }) | undefined => {
    const sub = tabSubject();
    for (let i = deadEnds.length - 1; i >= 0; i--) {
      const each = deadEnds[i];
      if (!each || each.seq <= endsFloor) break;
      if (!each.sub || !sub || each.sub === sub) return each;
    }
    return undefined;
  };

  const emptiedVerdict = (): 'keep' | 'wait' | 'end' => {
    if (!cacheMayOutlive()) return 'end';
    const seenSeq = lastStored?.seq ?? 0;
    const end = latestEnd();
    if (signedOutSince(end ? Math.min(seenSeq, end.seq) : seenSeq)) return 'end';
    if (end) return cacheAheadOf(end) ? 'keep' : 'end';
    return onSessionLost ? 'wait' : 'end';
  };

  const stopEmptiedWait = (): void => {
    cancelEmptiedWait?.();
    cancelEmptiedWait = undefined;
  };

  // Judges an emptied storage and acts on all but "end", which the caller acts on. `final`: the
  // wait is over, so "wait" counts as "end".
  const judgeEmptied = (final = false): 'keep' | 'wait' | 'end' => {
    let verdict = emptiedVerdict();
    if (verdict === 'wait' && final) verdict = 'end';
    if (verdict !== 'wait') stopEmptiedWait();
    if (verdict === 'wait' && !cancelEmptiedWait) {
      cancelEmptiedWait = schedule(() => {
        cancelEmptiedWait = undefined;
        if (storedTokens()?.refresh_token) {
          checkStoredSession();
          return;
        }
        if (judgeEmptied(true) === 'end') onSessionLost?.('emptied');
      }, EMPTIED_STORAGE_MESSAGE_WAIT_MS);
    }
    const kept = verdict === 'keep' ? latestEnd() : undefined;
    if (kept) keptSeq = Math.max(keptSeq, kept.seq);
    if (kept && keptOver !== kept.fp) {
      keptOver = kept.fp;
      warn(
        `[passflow] The shared token storage was emptied by the end of the session of ${kept.fp}, a refresh token the ${cachedOrder()?.fp ?? '(none)'} this tab holds is ahead of: keeping it. Nothing is refreshed until the storage holds a token again.`,
      );
    }
    return verdict;
  };

  const isHeldSend = (sent: SentCredentials): boolean => sent.held !== undefined && cachedOrder()?.fp === sent.held.cachedFp;

  // The cache holds a live token after `ref`.
  const holdsSuccessorOf = (ref: RefreshTokenOrder): boolean => {
    const current = cachedOrder();
    return !!current && !lineage.isRetired(current) && !lineage.isEnded(current) && lineage.isAfter(current, ref);
  };

  // The cache holds a live token after `ref` that shows `ref` was rotated elsewhere: `ref` is
  // known retired, or the cache holds a later token of `ref`'s own session by iat.
  const holdsRotationOf = (ref: RefreshTokenOrder): boolean => {
    if (!holdsSuccessorOf(ref)) return false;
    if (lineage.isRetired(ref)) return true;
    const current = cachedOrder();
    return ref.iat !== undefined && current?.iat !== undefined && current.sid === ref.sid;
  };

  // `candidate` may replace `held`: forward, or, once `held` is known retired, a live token of
  // another session (the same user signed in again). The callers check the user.
  const takesOver = (candidate: RefreshTokenOrder | undefined, held: RefreshTokenOrder | undefined): boolean => {
    if (lineage.isForward(candidate, held)) return true;
    return (
      !!candidate &&
      !!held &&
      candidate.iat !== undefined &&
      candidate.sid !== held.sid &&
      lineage.isRetired(held) &&
      !lineage.isRetired(candidate) &&
      !lineage.isEnded(candidate)
    );
  };

  // Caches tokens this tab did not request. The refresh token it replaces is retired.
  const adopt = (tokens: Tokens): void => {
    const replaced = cachedOrder();
    if (replaced && replaced.fp !== fingerprint(tokens.refresh_token)) lineage.retire(replaced);
    cache.setTokensCache(tokens);
  };

  // Null while the sent refresh token is still the stored one (the outcome is this request's
  // own); otherwise the verdict that replaces the outcome. Reads storage once, so the judgement and
  // the adopted tokens agree.
  const staleOutcome = (sent: SentCredentials): Exclude<SaveVerdict, { kind: 'saved' }> | null => {
    const stored = storedTokens();
    const current = stored?.refresh_token;
    if (current === sent.refreshToken) return null;
    if (!stored || !current) {
      return judgeEmptied() === 'end' ? { kind: 'ended', cause: 'emptied' } : { kind: 'superseded', adopted: false };
    }
    const storedSub = subOf(stored.access_token) ?? subOf(current);
    if (sent.sub && storedSub && sent.sub !== storedSub) return { kind: 'identity-changed', saved: false };
    const storedOrder = orderOf(current);
    if (lineage.isEnded(storedOrder)) {
      return storedOrder && cacheAheadOf(storedOrder)
        ? { kind: 'superseded', adopted: false }
        : { kind: 'ended', cause: 'ended' };
    }
    lineage.retire(sent.order);
    // Forward, or the very tokens the cache already holds (setTokens in this tab): taken again as
    // a refresh would, which is no rollback.
    const held = cachedOrder();
    if (takesOver(storedOrder, held) || (storedOrder?.fp === held?.fp && !lineage.isRetired(storedOrder))) {
      adopt(stored);
      return { kind: 'superseded', adopted: true };
    }
    return { kind: 'superseded', adopted: false };
  };

  const endedOutcome = (
    order: RefreshTokenOrder,
  ): { kind: 'superseded'; adopted: false } | { kind: 'ended'; cause: 'ended' } =>
    cacheAheadOf(order) ? { kind: 'superseded', adopted: false } : { kind: 'ended', cause: 'ended' };

  // The standing watch: another tab's write, or this tab waking.
  const checkStoredSession = (): void => {
    const stored = storedTokens();
    if (!stored?.refresh_token) {
      if (judgeEmptied() === 'end') onSessionLost?.('emptied');
      return;
    }
    stopEmptiedWait();
    const tabSub = identityOf();
    const storedSub = tokensSubject(stored);
    if (tabSub && storedSub && tabSub !== storedSub) {
      onSessionLost?.('identity-changed');
      return;
    }
    deps.onStoredSessionSeen?.();
  };
  const watching = !!onSessionLost || !!deps.onStoredSessionSeen;
  const stopWatchStorage = watching && deps.onStorageChange ? deps.onStorageChange(checkStoredSession) : undefined;
  const stopWatchWake = watching && deps.onWake ? deps.onWake(checkStoredSession) : undefined;

  const checkStoredBeforeSend = (): StoredVerdict => {
    const stored = storedTokens();
    if (!stored?.refresh_token) {
      // Kept (or waiting for the end message) over an emptied storage: nothing to send, keep the cache.
      if (judgeEmptied() === 'end') throw new SessionEnded('emptied');
      return 'held';
    }
    const cached = cache.getTokens();
    if (stored.refresh_token === cached?.refresh_token) return 'send';
    const tabSub = identityOf() ?? tokensSubject(cached);
    const storedSub = tokensSubject(stored);
    if (tabSub && storedSub && tabSub !== storedSub) throw new IdentityChanged();
    const storedOrder = orderOf(stored.refresh_token);
    if (lineage.isEnded(storedOrder)) {
      // Another tab ended an older token's session than the one the cache holds, and storage
      // still shows it: nothing to send, the cache is kept.
      if (storedOrder && cacheAheadOf(storedOrder)) return 'held';
      throw new SessionEnded('ended');
    }
    const held = orderOf(cached?.refresh_token);
    if (takesOver(storedOrder, held)) {
      adopt(stored);
      return 'adopted';
    }
    // Another session of this user (a sign-in again): storage only moves forward, so it was
    // written after the token this tab holds. Neither adopted over a live cached token nor waited
    // on: it is sent.
    if (storedOrder && held && storedOrder.sid !== held.sid) return 'send';
    // This tab's view of storage still shows an older or replaced token of its session.
    if (storedOrder && holdsSuccessorOf(storedOrder)) return 'held';
    // A same-second tie neither side of which is known retired: the cache keeps its token and the
    // stored one is sent. A live one rotates; a spent one is refused as already used and the kept
    // token is its successor.
    return 'send';
  };

  const beginSend = (refreshToken: string): SendVerdict => {
    const tabSub = identityOf();
    const sentSub = subOf(refreshToken);
    // Storage already holds another user's tokens: never send their refresh token from this tab.
    if (tabSub && sentSub && tabSub !== sentSub) return { kind: 'identity-changed' };
    const order: RefreshTokenOrder = orderOf(refreshToken) ?? { fp: refreshToken };
    if (lineage.isEnded(order)) return cacheAheadOf(order) ? { kind: 'superseded' } : { kind: 'ended' };
    // Already rotated, and the cache holds the successor: sending it would only be refused as
    // already used. A held send too: beginHeldSend arms none for a known retired token.
    if (lineage.isRetired(order) && holdsSuccessorOf(order)) return { kind: 'superseded' };
    const sent: SentCredentials = { refreshToken, order };
    const sub = tabSub ?? sentSub ?? subOf(cache.getTokens()?.access_token);
    if (sub !== undefined) sent.sub = sub;
    if (heldSend && heldSend.fp === order.fp) sent.held = { cachedFp: heldSend.cachedFp };
    return { kind: 'send', sent };
  };

  const commitSave = (sent: SentCredentials, tokens: Tokens): SaveVerdict => {
    // A late answer for a session that ended meanwhile (a thawed holder after session-ended):
    // neither saved nor adopted, even while storage still holds the sent token.
    if (lineage.isEnded(sent.order)) return endedOutcome(sent.order);
    const stale = staleOutcome(sent);
    if (stale) return stale;
    // Forward only: the cache already holds a live successor of the sent token (adopted from a
    // broadcast while this tab's view of storage still shows the sent token). This answer is a
    // second successor of it (a stolen or thawed holder's late 200, or the losing side of a double
    // rotation at the engine). Saving it would roll shared storage back. Not for a held send whose
    // cache still holds the token it held: storage, which every tab follows, holds the sent token.
    if (!isHeldSend(sent) && holdsRotationOf(sent.order)) {
      lineage.retire(sent.order);
      warn(
        `[passflow] Refused to save a late refresh result: it rotated ${sent.order.fp} into ${fingerprint(tokens.refresh_token) ?? '(no refresh token)'}, but this tab already holds ${cachedOrder()?.fp ?? '(none)'}, a later successor of ${sent.order.fp}. Neither saved nor adopted.`,
      );
      return { kind: 'superseded', adopted: false };
    }
    const savedSub = tokensSubject(tokens);
    if (sent.sub && savedSub && savedSub !== sent.sub) {
      // Another user's rotation: keep it stored for them, adopt nothing.
      storage.saveTokens(tokens);
      return { kind: 'identity-changed', saved: true };
    }
    // Forward only (§2.9.5): an answer whose refresh token is older, by iat within the same sid,
    // than the token sent or the one this tab holds never becomes the cached or stored token.
    const answered = orderOf(tokens.refresh_token);
    if (answered && (isOlderInSession(answered, sent.order) || isOlderInSession(answered, cachedOrder()))) {
      warn(
        `[passflow] Refused to save a refresh result older than the token this tab holds: ${sent.order.fp} was answered with ${answered.fp}. Neither saved nor adopted.`,
      );
      return { kind: 'superseded', adopted: false };
    }
    // This tab's own rotation. The cached token is not retired: in a held send it may be a later
    // token than the answer (an engine clock step), and retiring it would raise the floor.
    lineage.retire(sent.order);
    storage.saveTokens(tokens);
    cache.setTokensCache(tokens);
    return { kind: 'saved' };
  };

  const judgeFailure = (sent: SentCredentials, error: unknown): FailureVerdict => {
    if (lineage.isEnded(sent.order)) return endedOutcome(sent.order);
    const stale = staleOutcome(sent);
    if (stale) return stale.kind === 'identity-changed' ? { kind: 'identity-changed' } : stale;
    // Rotated by another tab while in flight (its broadcast arrived before this answer): the
    // successor is cached, so this is superseded, not a strike.
    if (lineage.isRetired(sent.order) && holdsSuccessorOf(sent.order)) return { kind: 'superseded', adopted: false };
    const failure = classifyRefreshFailure(error);
    const refused = failure.kind === 'blocked' || failure.kind === 'auth';
    // A held send refused on authentication: it only tested whether the stored token is live. It
    // is not, so it is retired, and the token the cache holds, after it, is the successor.
    if (isHeldSend(sent) && refused) {
      lineage.retire(sent.order);
      blockedSend = sent.order;
      return { kind: 'own', failure, heldRefused: true };
    }
    // The engine says it was already used: a successor exists somewhere (blocked never kills).
    if (failure.kind === 'blocked') {
      lineage.retire(sent.order);
      blockedSend = sent.order;
    }
    return { kind: 'own', failure, heldRefused: false };
  };

  const adoptTokens = (message: unknown): boolean => {
    if (!isObject(message)) return false;
    const { from, fromIat, fromSid, to, tokens } = message;
    if (typeof from !== 'string' || typeof to !== 'string' || !isObject(tokens)) return false;
    const pair = tokens as Tokens;
    if (
      typeof pair.access_token !== 'string' ||
      pair.access_token === '' ||
      typeof pair.refresh_token !== 'string' ||
      pair.refresh_token === '' ||
      fingerprint(pair.refresh_token) !== to
    ) {
      return false;
    }
    // Emptied storage: the session ended (a sign-out whose broadcast has not arrived yet).
    const stored = storedTokens();
    if (!stored?.refresh_token) return false;
    const cached = cache.getTokens();
    const tabSub = identityOf() ?? tokensSubject(cached);
    const sub = tokensSubject(pair);
    if (tabSub && sub && tabSub !== sub) {
      onSessionLost?.('identity-changed');
      return false;
    }
    const toOrder = orderOf(pair.refresh_token);
    const held = orderOf(cached?.refresh_token);
    // The sender rotated the very token this tab holds: it is known retired, which is what lets a
    // same-second `to` count as forward. Never retired by a tie alone.
    if (held && held.fp === from) lineage.retire(held);
    // `from` is retired only on an accepted move, under its own session and iat (a refused link
    // from another sender may still be the next link for this tab once an earlier one arrives).
    const accept = (): true => {
      if (from !== to && typeof fromIat === 'number' && Number.isFinite(fromIat) && typeof fromSid === 'string') {
        const retired: RefreshTokenOrder = { fp: from, iat: fromIat };
        if (toOrder?.sub !== undefined) retired.sub = toOrder.sub;
        if (fromSid !== '') retired.sid = fromSid;
        lineage.retire(retired);
      }
      return true;
    };
    if (held?.fp === to) return accept();
    // A delayed message, or a rebroadcast: `to` was issued before what this tab holds, or was
    // replaced or ended here. Never roll back.
    if (!lineage.isForward(toOrder, held)) return false;
    // Forward: the successor of what this tab holds, or, when it missed a link, what storage holds.
    if (held?.fp !== from && fingerprint(stored.refresh_token) !== to) return false;
    adopt({ ...pair });
    return accept();
  };

  // Forward only. A successor of the blocked send is a live refresh token issued after it, or a
  // live token of another session of this user.
  const isSuccessor = (token: RefreshTokenOrder | undefined): boolean => {
    if (!token || !blockedSend) return false;
    const sent = blockedSend;
    if (token.fp === sent.fp) return false;
    if (lineage.isEnded(token) || lineage.isRetired(token)) return false;
    if (token.iat !== undefined && sent.iat !== undefined && token.sid !== sent.sid) return true;
    return lineage.isAfter(token, sent);
  };

  const adoptSuccessor = (): boolean => {
    const held = cachedOrder();
    if (!held) return false;
    // The cache already moved on to a live token after the refused one.
    if (isSuccessor(held)) return true;
    const stored = storedTokens();
    const storedOrder = orderOf(stored?.refresh_token);
    if (!stored || !storedOrder || storedOrder.fp === held.fp || !isSuccessor(storedOrder) || !takesOver(storedOrder, held)) {
      return false;
    }
    const tabSub = identityOf() ?? tokensSubject(cache.getTokens());
    const storedSub = tokensSubject(stored);
    if (tabSub && storedSub && tabSub !== storedSub) {
      onSessionLost?.('identity-changed');
      return false;
    }
    adopt(stored);
    return true;
  };

  const lineageOf = (tokens: Tokens | undefined): WireLineage => {
    const order = orderOf(tokens?.refresh_token);
    const result: WireLineage = {};
    const sub = identityOf() ?? tokensSubject(tokens);
    if (order?.fp !== undefined) result.fp = order.fp;
    if (sub !== undefined) result.sub = sub;
    if (order?.sid !== undefined) result.sid = order.sid;
    if (order?.iat !== undefined) result.iat = order.iat;
    return result;
  };

  return {
    lineage,
    checkStoredBeforeSend,
    beginSend,
    commitSave,
    judgeFailure,
    adoptTokens,
    adoptSuccessor,
    beginHeldSend: () => {
      // Never a token this tab knows was rotated (it adopted the successor) or whose session ended.
      const storedOrder = orderOf(storedTokens()?.refresh_token);
      if (!storedOrder || lineage.isRetired(storedOrder) || lineage.isEnded(storedOrder)) {
        heldSend = undefined;
        return false;
      }
      const cachedFp = cachedOrder()?.fp;
      heldSend = cachedFp === undefined ? { fp: storedOrder.fp } : { fp: storedOrder.fp, cachedFp };
      return true;
    },
    endHeldSend: () => {
      heldSend = undefined;
    },
    endLineage: (session) => lineage.end(session),
    endedElsewhere: (type, session) => {
      // Read before the message is stamped, so that this read (a view that shows a token again)
      // spends only earlier ends, never this one.
      const viewEmpty = !storedTokens()?.refresh_token;
      endSeq += 1;
      if (type === 'signed-out') {
        signedOuts.push(session.sub === undefined ? { seq: endSeq } : { sub: session.sub, seq: endSeq });
        if (signedOuts.length > ENDED_MEMORY) signedOuts.shift();
      } else if (session.fp) {
        deadEnds.push({ ...session, fp: session.fp, seq: endSeq });
        if (deadEnds.length > ENDED_MEMORY) deadEnds.shift();
      }
      // This tab's view of storage is already empty: the message decides now. A session-ended
      // that explains the emptying keeps the cache and stops the wait; a user's signed-out ends.
      if (!cachedOrder() || !viewEmpty) return;
      if (judgeEmptied() === 'end') onSessionLost?.('emptied');
    },
    session: () => lineageOf(cache.getTokens()),
    storedSession: () => lineageOf(storedTokens()),
    dropSession: () => {
      cache.setTokensCache(undefined);
      cache.stopTokenCheck?.();
    },
    deleteIfStillDead: (dead) => {
      const storedOrder = orderOf(storedTokens()?.refresh_token);
      if (!storedOrder) return false;
      const sameLineage = storedOrder.sid === dead.sid && (!storedOrder.sub || !dead.sub || storedOrder.sub === dead.sub);
      const stillDead =
        storedOrder.fp === dead.fp ||
        (sameLineage && storedOrder.iat !== undefined && dead.iat !== undefined && storedOrder.iat < dead.iat);
      if (!stillDead) return false;
      storage.deleteTokens();
      return true;
    },
    stop: () => {
      stopWatchStorage?.();
      stopWatchWake?.();
      stopEmptiedWait();
    },
  };
}
