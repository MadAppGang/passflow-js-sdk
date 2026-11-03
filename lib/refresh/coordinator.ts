/**
 * The coordinator: the cross-tab protocol's transport half (architecture §6), port of the portal's
 * `cross-tab-refresh.ts`, and a local stand-in with the same port for fallback (§7).
 *
 * The refresh controller (controller.ts) owns every policy decision: what to send, when to retry,
 * which tab ends. The coordinator owns the mechanics the portal reviewed in rounds 14-25:
 *   - one lock claim per wait for REFRESH_LOCK, with an AbortSignal; a claim that was stolen or
 *     aborted is `dead`, and its grant callback, should it still run, does nothing;
 *   - the one-task hop after a grant (a steal or a message queued before the grant's callback is
 *     seen first), then the controller decides under the lock (`onGranted`, keep or release);
 *   - the holder's heartbeat (`still-refreshing` every 5 s, carrying the retry schedule while in
 *     backoff), a chained timer;
 *   - the waiter's silence timer: 20 s with no holder message, re-armed by every one and extended
 *     past a shared `nextAt` (retry info) or a legacy `rate-limited` `until`; then one waiter takes
 *     over (REFRESH_TAKEOVER_LOCK with ifAvailable, then `steal: true`);
 *   - message parsing, version and self filtering, posting with `v` and `tabId`;
 *   - "a foreign holder message since my last heartbeat", the thawed-timer guard (§6.11).
 *
 * Grant before message (accepted, portal round 14): browsers order neither lock grants against
 * channel messages nor either against storage, so a tab can be granted the lock after the previous
 * holder finished but before its broadcast arrives. That tab may send one extra request, refused
 * as already used, which never kills.
 *
 * @module refresh/coordinator
 */

import { HEARTBEAT_MS, TAKEOVER_SILENCE_MS } from './constants';
import {
  buildMessage,
  type OutgoingMessageBody,
  parseMessage,
  type RefreshMessage,
  type RefreshNames,
  type RetryInfo,
} from './protocol';
import type { RefreshChannel, RefreshClock, RefreshLockManager } from './types';

/** What the coordinator tells the controller. */
export interface CoordinatorHandlers {
  /**
   * This tab's live claim was granted the lock (after the one-task hop). Returns true to keep
   * holding it (until `release()`), false to release it at once.
   */
  onGranted(): boolean;
  /** The lock this tab held was stolen (another tab's takeover). A request in flight goes on. */
  onLockLost(): void;
  /** A valid message from another tab, after the coordinator's own handling (silence, takeover). */
  onMessage(message: RefreshMessage): void;
}

/** The port the controller sees (architecture §3.2 CoordinatorPort, as implemented). */
export interface CoordinatorPort {
  /** False for the local coordinator (fallback, 'none', non-web platforms). */
  readonly coordinated: boolean;
  readonly tabId: string;
  /** This tab's lock request is queued and not granted yet. */
  readonly waiting: boolean;
  /** This tab holds the lock. */
  readonly holding: boolean;
  attach(handlers: CoordinatorHandlers): void;
  /**
   * Queues for the lock, unless this tab already has a request queued or holds the lock (A4: a
   * second need joins the existing request). `silenceUntil`: the silence timer fires no earlier
   * (a shared retry's `nextAt + 20 s`).
   */
  request(silenceUntil?: number): void;
  /** Leaves the queue, or releases a held lock. */
  release(): void;
  /** Posts a message to every other tab (no-op locally). */
  post(body: OutgoingMessageBody): void;
  /** The schedule the holder's heartbeats carry (undefined: none). */
  setRetryInfo(info: RetryInfo | undefined): void;
  /** Another tab's holder message (still-refreshing, takeover, retry-scheduled) arrived since this tab's own last heartbeat. */
  foreignHolderHeard(): boolean;
  /** Leaves the queue, releases the lock, stops every timer, removes the listener and closes the channel. */
  dispose(): void;
}

export interface CrossTabCoordinatorDeps {
  locks: RefreshLockManager;
  channel: RefreshChannel;
  tabId: string;
  names: RefreshNames;
  clock: RefreshClock;
}

// One request for the refresh lock. Its identity tells a steal (the holder's request rejects)
// from this tab's own abort (a queued request rejects).
interface LockClaim {
  takeover: boolean;
  // Stolen (by another tab's takeover, or this tab's own) or aborted: the lock is not this
  // claim's, so its grant callback, if it runs at all, must do nothing.
  dead: boolean;
  abort: AbortController;
}

const noHandlers: CoordinatorHandlers = {
  onGranted: () => false,
  onLockLost: () => undefined,
  onMessage: () => undefined,
};

export function createCrossTabCoordinator(deps: CrossTabCoordinatorDeps): CoordinatorPort {
  const { locks, channel, tabId, names, clock } = deps;
  let handlers = noHandlers;
  // The current claim: queued or held. Null when this tab neither waits nor holds.
  let claim: LockClaim | null = null;
  let holding: LockClaim | null = null;
  let releaseHeld: (() => void) | null = null;
  // Set while a takeover holds the takeover lock until its steal is granted.
  let stealGranted: (() => void) | null = null;
  let cancelHeartbeat: (() => void) | null = null;
  let cancelSilence: (() => void) | null = null;
  // When the silence timer fires; only moves later within one wait.
  let deadline = 0;
  let retryInfo: RetryInfo | undefined;
  let foreignHeard = false;
  let disposed = false;

  const post = (body: OutgoingMessageBody): void => {
    if (disposed) return;
    channel.postMessage(buildMessage(tabId, body));
  };

  const isWaiting = (): boolean => claim !== null && holding === null;

  const stopSilence = (): void => {
    cancelSilence?.();
    cancelSilence = null;
  };

  const armSilence = (at: number): void => {
    deadline = Math.max(deadline, at);
    stopSilence();
    cancelSilence = clock.setTimeout(
      () => {
        cancelSilence = null;
        trySilentTakeover();
      },
      Math.max(0, deadline - clock.now()),
    );
  };

  const stopHeartbeat = (): void => {
    cancelHeartbeat?.();
    cancelHeartbeat = null;
  };

  // Known limit (portal round 16, L2): a long-hidden holder's chained heartbeat is throttled to
  // one wake-up a minute, so a visible waiter may take over. That costs at most one request
  // refused as already used, which never kills.
  const heartbeat = (): void => {
    cancelHeartbeat = clock.setTimeout(() => {
      cancelHeartbeat = null;
      if (!holding) return;
      foreignHeard = false;
      post(retryInfo ? { type: 'still-refreshing', retry: retryInfo } : { type: 'still-refreshing' });
      heartbeat();
    }, HEARTBEAT_MS);
  };

  const release = (): void => {
    stopSilence();
    stopHeartbeat();
    stealGranted?.();
    stealGranted = null;
    const current = claim;
    claim = null;
    holding = null;
    if (current) {
      current.dead = true;
      current.abort.abort();
    }
    const done = releaseHeld;
    releaseHeld = null;
    done?.();
  };

  // This tab's held lock was stolen (a takeover): its request in flight goes on, and the save
  // checks judge its answer.
  const lostLock = (): void => {
    stopHeartbeat();
    holding = null;
    claim = null;
    releaseHeld = null;
    handlers.onLockLost();
  };

  // The grant, one task later: the claim may have been stolen, or the wait ended, meanwhile.
  const proceed = (granted: LockClaim, resolveHeld: () => void): void => {
    if (granted.dead || claim !== granted || disposed) {
      resolveHeld();
      return;
    }
    stopSilence();
    holding = granted;
    releaseHeld = resolveHeld;
    foreignHeard = false;
    heartbeat();
    let keep = false;
    try {
      keep = handlers.onGranted();
    } finally {
      if (!keep && holding === granted) release();
    }
  };

  const onGranted = (granted: LockClaim): Promise<void> | undefined => {
    if (granted.takeover) {
      stealGranted?.();
      stealGranted = null;
    }
    // Stolen or aborted before its callback ran, or the wait ended while queued: release at once.
    if (granted.dead || claim !== granted) return undefined;
    // Let one task pass while holding the lock, then check again before the controller reads
    // storage or sends: a message or steal queued before this callback lands first. In the other
    // order the stolen claim may send the token the stealer is rotating: one wasted request,
    // refused as already used, which never kills.
    return new Promise<void>((resolveHeld) => {
      clock.setTimeout(() => proceed(granted, resolveHeld), 0);
    });
  };

  const claimLock = (steal: boolean): void => {
    const next: LockClaim = { takeover: steal, dead: false, abort: new AbortController() };
    claim = next;
    const options = steal ? { steal: true } : { signal: next.abort.signal };
    locks
      .request(names.lock, options, () => onGranted(next))
      .catch(() => {
        // Stolen while held, or this tab's own abort of a queued request. Either way the lock is
        // not this claim's: its grant callback, should it still run, does nothing.
        next.dead = true;
        if (holding === next) lostLock();
      });
  };

  const trySilentTakeover = (): void => {
    if (!isWaiting()) return;
    const waitingClaim = claim;
    locks
      .request(names.takeoverLock, { ifAvailable: true }, (lock) => {
        if (claim !== waitingClaim || !isWaiting()) return undefined;
        // Another waiter is taking over: wait for its messages.
        if (lock === null) {
          armSilence(clock.now() + TAKEOVER_SILENCE_MS);
          return undefined;
        }
        post({ type: 'takeover' });
        // Hold the takeover lock until the steal is granted, so no other waiter takes over meanwhile.
        return new Promise<void>((resolve) => {
          stealGranted = resolve;
          // This tab's own earlier claim may already be granted, its callback still queued: the
          // steal takes the lock from it too.
          if (waitingClaim) {
            waitingClaim.dead = true;
            waitingClaim.abort.abort();
          }
          claimLock(true);
        });
      })
      .catch(() => {
        if (isWaiting()) armSilence(clock.now() + TAKEOVER_SILENCE_MS);
      });
  };

  const onMessage = (event: { data: unknown }): void => {
    if (disposed) return;
    const message = parseMessage(event.data);
    if (!message || message.tabId === tabId) return;
    switch (message.type) {
      case 'still-refreshing':
        foreignHeard = true;
        if (isWaiting()) {
          armSilence(clock.now() + TAKEOVER_SILENCE_MS);
          if (message.retry) armSilence(message.retry.nextAt + TAKEOVER_SILENCE_MS);
        }
        break;
      case 'takeover':
        foreignHeard = true;
        if (isWaiting()) armSilence(clock.now() + TAKEOVER_SILENCE_MS);
        break;
      case 'retry-scheduled':
        foreignHeard = true;
        if (isWaiting()) armSilence(Math.max(clock.now(), message.retry.nextAt) + TAKEOVER_SILENCE_MS);
        break;
      case 'rate-limited':
        if (isWaiting()) armSilence(message.until + TAKEOVER_SILENCE_MS);
        break;
      default:
        break;
    }
    handlers.onMessage(message);
  };
  channel.addEventListener('message', onMessage);

  return {
    coordinated: true,
    tabId,
    get waiting() {
      return isWaiting();
    },
    get holding() {
      return holding !== null;
    },
    attach: (next) => {
      handlers = next;
    },
    request: (silenceUntil) => {
      if (disposed || claim) return;
      deadline = 0;
      armSilence(Math.max(clock.now() + TAKEOVER_SILENCE_MS, silenceUntil ?? 0));
      claimLock(false);
    },
    release,
    post,
    setRetryInfo: (info) => {
      retryInfo = info;
    },
    foreignHolderHeard: () => foreignHeard,
    dispose: () => {
      if (disposed) return;
      release();
      disposed = true;
      channel.removeEventListener('message', onMessage);
      channel.close();
    },
  };
}

/**
 * The local coordinator (fallback, `'none'`, non-web platforms): this instance is the only one
 * that refreshes, so "the lock" is granted at once (a microtask, keeping the controller's
 * asynchronous shape) and nothing is posted.
 */
export function createLocalCoordinator(tabId = 'local'): CoordinatorPort {
  let handlers = noHandlers;
  let claimed = false;
  let held = false;
  let seq = 0;
  let disposed = false;

  const release = (): void => {
    claimed = false;
    held = false;
    seq += 1;
  };

  return {
    coordinated: false,
    tabId,
    get waiting() {
      return claimed && !held;
    },
    get holding() {
      return held;
    },
    attach: (next) => {
      handlers = next;
    },
    request: () => {
      if (disposed || claimed) return;
      claimed = true;
      const mine = ++seq;
      Promise.resolve().then(() => {
        if (disposed || seq !== mine || !claimed) return;
        held = true;
        let keep = false;
        try {
          keep = handlers.onGranted();
        } finally {
          if (!keep && seq === mine) release();
        }
      });
    },
    release,
    post: () => undefined,
    setRetryInfo: () => undefined,
    foreignHolderHeard: () => false,
    dispose: () => {
      release();
      disposed = true;
    },
  };
}
