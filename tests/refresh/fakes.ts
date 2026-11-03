/**
 * Test doubles for cross-tab refresh (port of the portal's `cross-tab-refresh.fakes.ts`,
 * PFL-764): one Web Locks manager, one BroadcastChannel hub and one storage that N simulated tabs
 * share, on one virtual clock.
 *
 * Realistic orderings. Browsers order neither lock grants against channel messages nor either
 * against another process's storage writes, so the fakes do not either:
 *   - every lock callback, steal rejection, ifAvailable miss, message delivery and storage event is
 *     a separate macrotask in the receiving tab's event loop (VirtualClock.task), not a microtask
 *     in the caller's program order;
 *   - a frozen tab runs none of them, nor its timers: they wait, in the order they were queued,
 *     until it thaws;
 *   - FakeChannelHub.hold delays or reorders one tab's incoming messages;
 *   - SharedStorage.lag gives one tab a stale view of the shared storage, with its own writes
 *     visible to itself, until sync;
 *   - FakeLockManager.holdRejections delays one tab's lock rejections (a steal, an abort) behind
 *     its own later tasks and timers.
 * By default the queue is FIFO, which keeps the order the holder acted in: it posts before it
 * releases, so its broadcast is queued before the next grant.
 *
 * SDK additions: `scheduler(tab)` returns a RefreshClock (`now`, `setTimeout`, `random`), and
 * SharedStorage fires storage events in the other tabs on every write (`storageEvents(tab)`, the
 * coordinator's `onStorageChange`).
 */
import type { RefreshChannel, RefreshClock, RefreshLockManager, RefreshLockOptions } from '../../lib/refresh/types';
import type { Storage } from '../../lib/storage';

function abortError(message: string): Error {
  return Object.assign(new Error(message), { name: 'AbortError' });
}

interface VirtualTimer {
  tab: string;
  due: number;
  seq: number;
  fn: () => void;
}

export interface VirtualClock {
  now: () => number;
  /** A tab's RefreshClock: its timers are virtual and belong to that tab (frozen with it). */
  scheduler: (tab: string, random?: () => number) => Required<RefreshClock>;
  /** Timers still waiting, for one tab or all. */
  pending: (tab?: string) => number;
  /** A macrotask in a tab's event loop: it runs after the current task, in queue order. A frozen tab's tasks wait until thaw. */
  task: (tab: string, fn: () => void) => void;
  /** A frozen tab (Page Lifecycle) runs nothing: neither timers nor tasks, until thaw. */
  freeze: (tab: string) => void;
  thaw: (tab: string) => void;
  /** Moves the clock on by `ms`, firing each timer that falls due in due order, and awaits `settle` after each one. */
  advance: (ms: number, settle: () => Promise<void>) => Promise<void>;
}

export function createVirtualClock(): VirtualClock {
  let now = 0;
  let seq = 0;
  const timers: VirtualTimer[] = [];
  const frozen = new Set<string>();
  const deferred = new Map<string, (() => void)[]>();

  const nextDue = (end: number): VirtualTimer | undefined => {
    let next: VirtualTimer | undefined;
    for (const timer of timers) {
      if (frozen.has(timer.tab) || timer.due > end) continue;
      if (!next || timer.due < next.due || (timer.due === next.due && timer.seq < next.seq)) next = timer;
    }
    return next;
  };

  const task = (tab: string, fn: () => void): void => {
    setImmediate(() => {
      if (frozen.has(tab)) {
        const list = deferred.get(tab) ?? [];
        list.push(fn);
        deferred.set(tab, list);
        return;
      }
      fn();
    });
  };

  return {
    now: () => now,
    scheduler: (tab, random = () => 0) => ({
      now: () => now,
      random,
      setTimeout: (fn, ms) => {
        const timer: VirtualTimer = { tab, due: now + Math.max(0, ms), seq: seq++, fn };
        timers.push(timer);
        return () => {
          const index = timers.indexOf(timer);
          if (index !== -1) timers.splice(index, 1);
        };
      },
    }),
    pending: (tab) => timers.filter((timer) => tab === undefined || timer.tab === tab).length,
    task,
    freeze: (tab) => {
      frozen.add(tab);
    },
    thaw: (tab) => {
      frozen.delete(tab);
      const list = deferred.get(tab) ?? [];
      deferred.delete(tab);
      for (const fn of list) task(tab, fn);
    },
    advance: async (ms, settle) => {
      const end = now + ms;
      for (let fired = 0; fired < 10_000; fired++) {
        const timer = nextDue(end);
        if (!timer) {
          now = end;
          return;
        }
        timers.splice(timers.indexOf(timer), 1);
        now = Math.max(now, timer.due);
        timer.fn();
        await settle();
      }
      throw new Error('advance() fired 10000 timers: a timer storm');
    },
  };
}

interface LockRequest {
  tab: string;
  name: string;
  callback: (lock: unknown) => unknown;
  resolve: (value: unknown) => void;
  reject: (error: unknown) => void;
  stolen: boolean;
  signal?: AbortSignal;
  onAbort?: () => void;
}

export interface FakeLockManager {
  /** One tab's navigator.locks: its callbacks and rejections run as that tab's tasks. */
  forTab: (tab: string) => RefreshLockManager;
  /** A request is granted the lock and not released yet. */
  isHeld: (name: string) => boolean;
  /** The tab whose request holds the lock. */
  holder: (name: string) => string | undefined;
  /** Requests queued for the lock. */
  queued: (name: string) => number;
  /** A discarded or killed tab: the browser releases every lock it holds and drops its queued requests. */
  kill: (tab: string) => void;
  /** Delays one tab's lock rejections (a steal, an abort) until releaseRejections. */
  holdRejections: (tab: string) => void;
  /** Queues the held rejections as tasks of the tab, in the order they happened, and stops holding. */
  releaseRejections: (tab: string) => void;
}

/**
 * The Web Locks API, exclusive mode only: queued requests in order, `ifAvailable` (callback(null)
 * when the lock is held or queued), `steal` (the holder's request rejects with AbortError and the
 * stealer is granted at once, ahead of the queue) and `signal` (a queued request rejects with
 * AbortError and leaves the queue; aborting a granted one does nothing). A grant marks the lock
 * held at once and runs the callback as a task of the requesting tab, so a steal can land between
 * a grant and its callback, and the callback still runs (the spec does not cancel it).
 */
export function createFakeLockManager(clock: Pick<VirtualClock, 'task'>): FakeLockManager {
  const held = new Map<string, LockRequest>();
  const queues = new Map<string, LockRequest[]>();
  const heldRejections = new Map<string, (() => void)[]>();
  const killed = new Set<string>();

  const rejectAsTask = (tab: string, reject: () => void): void => {
    const pending = heldRejections.get(tab);
    if (pending) {
      pending.push(reject);
      return;
    }
    clock.task(tab, reject);
  };
  const queueOf = (name: string): LockRequest[] => {
    let queue = queues.get(name);
    if (!queue) {
      queue = [];
      queues.set(name, queue);
    }
    return queue;
  };

  const grantNext = (name: string): void => {
    if (held.has(name)) return;
    const next = queueOf(name).shift();
    if (!next) return;
    if (next.onAbort) next.signal?.removeEventListener('abort', next.onAbort);
    grant(next);
  };

  const finish = (request: LockRequest): void => {
    if (held.get(request.name) !== request) return;
    held.delete(request.name);
    grantNext(request.name);
  };

  const grant = (request: LockRequest): void => {
    held.set(request.name, request);
    clock.task(request.tab, () => {
      let result: Promise<unknown>;
      try {
        result = Promise.resolve(request.callback({ name: request.name }));
      } catch (error) {
        result = Promise.reject(error);
      }
      result.then(
        (value) => {
          finish(request);
          if (!request.stolen) request.resolve(value);
        },
        (error: unknown) => {
          finish(request);
          if (!request.stolen) request.reject(error);
        },
      );
    });
  };

  const request = (
    tab: string,
    name: string,
    options: RefreshLockOptions,
    callback: (lock: unknown) => unknown,
  ): Promise<unknown> =>
    new Promise<unknown>((resolve, reject) => {
      if (killed.has(tab)) return;
      const req: LockRequest = { tab, name, callback, resolve, reject, stolen: false, signal: options.signal };
      if (options.signal?.aborted) {
        clock.task(tab, () => reject(abortError('aborted before the request')));
        return;
      }
      if (options.steal) {
        const holder = held.get(name);
        if (holder) {
          held.delete(name);
          holder.stolen = true;
          rejectAsTask(holder.tab, () => holder.reject(abortError('lock stolen')));
        }
        grant(req);
        return;
      }
      if (options.ifAvailable) {
        if (held.has(name) || queueOf(name).length > 0) {
          clock.task(tab, () => {
            Promise.resolve()
              .then(() => callback(null))
              .then(resolve, reject);
          });
          return;
        }
        grant(req);
        return;
      }
      queueOf(name).push(req);
      if (options.signal) {
        const signal = options.signal;
        req.onAbort = () => {
          const queue = queueOf(name);
          const index = queue.indexOf(req);
          if (index === -1) return;
          queue.splice(index, 1);
          rejectAsTask(tab, () => reject(abortError('aborted while queued')));
        };
        signal.addEventListener('abort', req.onAbort, { once: true });
      }
      grantNext(name);
    });

  return {
    forTab: (tab) => ({ request: (name, options, callback) => request(tab, name, options, callback) }),
    isHeld: (name) => held.has(name),
    holder: (name) => held.get(name)?.tab,
    queued: (name) => queueOf(name).length,
    kill: (tab) => {
      killed.add(tab);
      queues.forEach((queue, name) => {
        queues.set(
          name,
          queue.filter((req) => req.tab !== tab),
        );
      });
      for (const req of Array.from(held.values())) {
        if (req.tab === tab) finish(req);
      }
    },
    holdRejections: (tab) => {
      if (!heldRejections.has(tab)) heldRejections.set(tab, []);
    },
    releaseRejections: (tab) => {
      const pending = heldRejections.get(tab) ?? [];
      heldRejections.delete(tab);
      for (const reject of pending) clock.task(tab, reject);
    },
  };
}

export interface PostedMessage {
  from: string;
  data: unknown;
}

/** Picks messages for FakeChannelHub.hold and release. */
export type MessageFilter = (data: unknown, from: string) => boolean;

export interface FakeChannelHub {
  /** One tab's BroadcastChannel. It never delivers a tab's message to itself; every other open channel gets a structured clone, as a task of the receiving tab. */
  channel: (tabId: string) => RefreshChannel;
  /** Every message posted, in order. */
  posted: PostedMessage[];
  /** A frozen tab gets no message until thaw. */
  freeze: (tabId: string) => void;
  thaw: (tabId: string) => void;
  /** Delays one tab's incoming messages that match `filter` (all by default) until release. */
  hold: (tabId: string, filter?: MessageFilter) => void;
  /** Delivers the held messages that match `filter`, in posting order, and stops holding when none is left. */
  release: (tabId: string, filter?: MessageFilter) => void;
  /** Messages held for one tab. */
  held: (tabId: string) => PostedMessage[];
  /** A tab posts nothing more and gets nothing more (killed). */
  close: (tabId: string) => void;
}

export function createFakeChannelHub(clock: Pick<VirtualClock, 'task'>): FakeChannelHub {
  type Listener = (event: { data: unknown }) => void;
  interface Member {
    tabId: string;
    listeners: Set<Listener>;
    open: boolean;
    frozen: boolean;
    backlog: unknown[];
    holdFilter: MessageFilter | null;
    held: PostedMessage[];
  }
  const members: Member[] = [];
  const posted: PostedMessage[] = [];

  const dispatch = (member: Member, data: unknown): void => {
    if (!member.open) return;
    if (member.frozen) {
      member.backlog.push(data);
      return;
    }
    clock.task(member.tabId, () => {
      if (!member.open) return;
      for (const listener of Array.from(member.listeners)) listener({ data: structuredClone(data) });
    });
  };

  const deliver = (member: Member, message: PostedMessage): void => {
    if (member.holdFilter?.(message.data, message.from)) {
      member.held.push(message);
      return;
    }
    dispatch(member, message.data);
  };

  const memberOf = (tabId: string): Member | undefined => members.find((m) => m.tabId === tabId);

  return {
    posted,
    channel: (tabId) => {
      const member: Member = {
        tabId,
        listeners: new Set(),
        open: true,
        frozen: false,
        backlog: [],
        holdFilter: null,
        held: [],
      };
      members.push(member);
      return {
        postMessage: (data) => {
          if (!member.open) return;
          const message = { from: tabId, data: structuredClone(data) };
          posted.push(message);
          for (const other of members) {
            if (other !== member) deliver(other, message);
          }
        },
        addEventListener: (_type, listener) => {
          member.listeners.add(listener);
        },
        removeEventListener: (_type, listener) => {
          member.listeners.delete(listener);
        },
        close: () => {
          member.open = false;
        },
      };
    },
    freeze: (tabId) => {
      const member = memberOf(tabId);
      if (member) member.frozen = true;
    },
    thaw: (tabId) => {
      const member = memberOf(tabId);
      if (!member) return;
      member.frozen = false;
      for (const data of member.backlog.splice(0)) dispatch(member, data);
    },
    hold: (tabId, filter = () => true) => {
      const member = memberOf(tabId);
      if (member) member.holdFilter = filter;
    },
    release: (tabId, filter = () => true) => {
      const member = memberOf(tabId);
      if (!member) return;
      const keep: PostedMessage[] = [];
      for (const message of member.held) {
        if (filter(message.data, message.from)) dispatch(member, message.data);
        else keep.push(message);
      }
      member.held = keep;
      if (keep.length === 0) member.holdFilter = null;
    },
    held: (tabId) => [...(memberOf(tabId)?.held ?? [])],
    close: (tabId) => {
      const member = memberOf(tabId);
      if (member) member.open = false;
    },
  };
}

export interface SharedStorage {
  /** One tab's storage: the shared one, or a stale copy while lagging. Writes go to the shared one. */
  view: (tab: string) => Storage;
  /** The tab's storage event source (another tab wrote): `RefreshCoordinator.onStorageChange`. */
  storageEvents: (tab: string) => (listener: () => void) => () => void;
  /** From now on the tab sees the shared storage as it is now, plus its own writes, until sync. */
  lag: (tab: string) => void;
  /** The tab sees the shared storage again. */
  sync: (tab: string) => void;
  /** The shared items, for assertions. */
  items: Map<string, string>;
}

/**
 * One storage shared by every tab, with per-tab views. A write by one tab fires a storage event
 * (a task) in every other tab, as `window`'s `storage` event does. A lagging view never goes back
 * in time: it is a snapshot of an earlier shared state, and sync moves it forward.
 */
export function createSharedStorage(clock: Pick<VirtualClock, 'task'>): SharedStorage {
  const items = new Map<string, string>();
  const snapshots = new Map<string, Map<string, string>>();
  const listeners = new Map<string, Set<() => void>>();

  const notifyOthers = (writer: string): void => {
    listeners.forEach((set, tab) => {
      if (tab === writer) return;
      for (const listener of Array.from(set)) clock.task(tab, listener);
    });
  };

  return {
    items,
    view: (tab) => ({
      getItem: (key) => {
        const snapshot = snapshots.get(tab);
        return snapshot ? (snapshot.get(key) ?? null) : (items.get(key) ?? null);
      },
      setItem: (key, value) => {
        items.set(key, String(value));
        snapshots.get(tab)?.set(key, String(value));
        notifyOthers(tab);
      },
      removeItem: (key) => {
        if (!items.has(key)) return;
        items.delete(key);
        snapshots.get(tab)?.delete(key);
        notifyOthers(tab);
      },
    }),
    storageEvents: (tab) => (listener) => {
      let set = listeners.get(tab);
      if (!set) {
        set = new Set();
        listeners.set(tab, set);
      }
      set.add(listener);
      return () => {
        listeners.get(tab)?.delete(listener);
      };
    },
    lag: (tab) => {
      snapshots.set(tab, new Map(items));
    },
    sync: (tab) => {
      snapshots.delete(tab);
    },
  };
}

/** Lets every queued task and promise chain run (several macrotask rounds). */
export async function settle(rounds = 12): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}
