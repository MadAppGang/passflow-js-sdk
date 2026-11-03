/**
 * A browser of N tabs for refresh tests: each tab is a RefreshController over one shared storage,
 * with its own token cache, event log and fake transport, on one virtual clock. Coordinated tabs
 * share the fake Web Locks manager and channel hub; local tabs coordinate with nothing.
 *
 * The fake server answers every /auth/refresh from `world.answer` (default: rotate the sent token
 * into a new pair of the same session, one second later). An answer can be held until the test
 * settles it.
 */

import type { PassflowAuthorizationResponse } from '../../lib/api/model';
import { PassflowError } from '../../lib/api/model';
import {
  createRefreshController,
  type RefreshController,
  type RefreshEventMap,
  type RefreshTransport,
} from '../../lib/refresh/controller';
import { orderOf } from '../../lib/refresh/lineage';
import { refreshNames } from '../../lib/refresh/protocol';
import type { ResolvedCoordination } from '../../lib/refresh/resolve';
import { StorageManager } from '../../lib/storage';
import type { Tokens } from '../../lib/types';
import {
  createFakeChannelHub,
  createFakeLockManager,
  createSharedStorage,
  createVirtualClock,
  type FakeChannelHub,
  type FakeLockManager,
  type SharedStorage,
  settle,
  type VirtualClock,
} from './fakes';
import { pair } from './jwt';

export type EventName = keyof RefreshEventMap;

export interface Recorded {
  event: EventName;
  payload: RefreshEventMap[EventName];
  at: number;
}

export interface ServerRequest {
  tab: string;
  at: number;
  refreshToken?: string;
  upgrade?: unknown;
}

/** What the fake server does with one request. */
export type Answer = { ok: Tokens } | { error: unknown } | 'rotate' | 'hold';

export interface HeldRequest {
  request: ServerRequest;
  resolve(tokens: Tokens): void;
  reject(error: unknown): void;
}

export interface FakeCache {
  getTokens(): Tokens | undefined;
  setTokensCache(tokens: Tokens | undefined): void;
  stopTokenCheck: () => void;
  startTokenCheck: () => void;
  tokenExpiredFlag: boolean;
  stops: number;
  starts: number;
}

export interface Tab {
  id: string;
  controller: RefreshController;
  cache: FakeCache;
  storage: StorageManager;
  events: Recorded[];
  of<E extends EventName>(event: E): RefreshEventMap[E][];
  names(): EventName[];
  wake(): void;
  warnings: string[];
}

export interface World {
  clock: VirtualClock;
  locks: FakeLockManager;
  hub: FakeChannelHub;
  shared: SharedStorage;
  tabs: Tab[];
  requests: ServerRequest[];
  held: HeldRequest[];
  answer: (request: ServerRequest) => Answer;
  /** Another writer (a sign-in elsewhere, a portal tab) writes storage: every tab gets a storage event. */
  storage: StorageManager;
  /** Moves the virtual clock on by `ms`, letting every task run. */
  run(ms?: number): Promise<void>;
  /** Kills a tab: its locks are released, its queue entries dropped, it runs nothing more. */
  kill(tab: Tab): void;
  addTab(id?: string): Tab;
  stored(): Tokens | undefined;
}

export interface WorldOptions {
  tabs?: number;
  coordinated?: boolean;
  initial?: Tokens | null;
  strikes?: number;
  random?: () => number;
  answer?: (request: ServerRequest) => Answer;
}

export function unavailable(): PassflowError {
  return new PassflowError({ id: 'error.http.503', message: 'unavailable', status: 503, location: '/auth/refresh', time: '' });
}

export function blockedError(): PassflowError {
  return new PassflowError({ id: 'error.token.blocked', message: 'blocked', status: 400, location: '/auth/refresh', time: '' });
}

export function invalidError(): PassflowError {
  return new PassflowError({
    id: 'error.token.invalid.error',
    message: 'invalid',
    status: 400,
    location: '/auth/refresh',
    time: '',
  });
}

/** The raw axios error `handleRateLimitError` passes through for a POST 429. */
export function rateLimited(seconds: number): unknown {
  return Object.assign(new Error('Request failed with status code 429'), {
    isAxiosError: true,
    response: { status: 429, headers: { 'retry-after': String(seconds) }, data: {} },
  });
}

/** The next pair of the sent token's session: same sub and sid, one second later. */
export function rotate(refreshToken: string | undefined): Tokens {
  const order = orderOf(refreshToken);
  return pair((order?.iat ?? 100) + 1, order?.sid ?? 's1', order?.sub ?? 'user-1');
}

export function createWorld(options: WorldOptions = {}): World {
  const clock = createVirtualClock();
  const locks = createFakeLockManager(clock);
  const hub = createFakeChannelHub(clock);
  const shared = createSharedStorage(clock);
  const coordinated = options.coordinated ?? true;
  const requests: ServerRequest[] = [];
  const held: HeldRequest[] = [];
  const outside = new StorageManager({ storage: shared.view('outside') });
  const initial = options.initial === undefined ? pair(100) : options.initial;
  if (initial) outside.saveTokens(initial);

  const world: World = {
    clock,
    locks,
    hub,
    shared,
    tabs: [],
    requests,
    held,
    answer: options.answer ?? (() => 'rotate'),
    storage: outside,
    run: async (ms = 0) => {
      await settle();
      await clock.advance(ms, () => settle());
      for (let i = 0; i < 3; i++) {
        await settle();
        await clock.advance(0, () => settle());
      }
    },
    kill: (tab) => {
      clock.freeze(tab.id);
      hub.close(tab.id);
      locks.kill(tab.id);
    },
    addTab: (id) => {
      const tab = createTab(id ?? `tab-${world.tabs.length}`);
      world.tabs.push(tab);
      return tab;
    },
    stored: () => outside.getTokens(),
  };

  const createTab = (id: string): Tab => {
    const storage = new StorageManager({ storage: shared.view(id) });
    let tokens: Tokens | undefined = storage.getTokens();
    const cache: FakeCache = {
      getTokens: () => tokens,
      setTokensCache: (next) => {
        tokens = next;
      },
      stopTokenCheck: () => {
        cache.stops += 1;
      },
      startTokenCheck: () => {
        cache.starts += 1;
      },
      tokenExpiredFlag: false,
      stops: 0,
      starts: 0,
    };
    const events: Recorded[] = [];
    const wakeListeners = new Set<() => void>();
    const warnings: string[] = [];
    const transport: RefreshTransport = {
      mode: () => 'json',
      send: (job) =>
        new Promise<PassflowAuthorizationResponse>((resolve, reject) => {
          const request: ServerRequest = { tab: id, at: clock.now(), refreshToken: job.tokens?.refresh_token };
          if (job.upgrade !== undefined) request.upgrade = job.upgrade;
          requests.push(request);
          const answer = world.answer(request);
          if (answer === 'hold') {
            held.push({ request, resolve, reject });
            return;
          }
          // The answer arrives as a later task of the sending tab.
          clock.task(id, () => {
            if (answer === 'rotate') resolve(rotate(job.tokens?.refresh_token));
            else if ('ok' in answer) resolve({ ...answer.ok });
            else reject(answer.error);
          });
        }),
      applyOpaque: () => Promise.resolve(),
      invalidate: () => undefined,
      assertPin: () => undefined,
    };
    const scheduler = clock.scheduler(id, options.random);
    const coordination: ResolvedCoordination = coordinated
      ? {
          transports: { locks: locks.forTab(id), channel: hub.channel(id), tabId: id },
          names: refreshNames(''),
          clock: scheduler,
          onStorageChange: shared.storageEvents(id),
          warnOnFirstCycle: false,
        }
      : {
          transports: null,
          names: refreshNames(''),
          clock: scheduler,
          onStorageChange: shared.storageEvents(id),
          warnOnFirstCycle: false,
        };
    const controller = createRefreshController({
      emit: (event, payload) => {
        events.push({ event, payload, at: clock.now() } as Recorded);
      },
      storage,
      cache,
      transport,
      coordination,
      platform: {
        onForeground: (listener) => {
          wakeListeners.add(listener);
          return () => wakeListeners.delete(listener);
        },
      },
      strikes: options.strikes,
      logger: {
        error: (message) => warnings.push(message),
        warn: (message) => warnings.push(message),
        info: () => undefined,
        debug: () => undefined,
      },
    });
    return {
      id,
      controller,
      cache,
      storage,
      events,
      warnings,
      of: <E extends EventName>(event: E) =>
        events.filter((each) => each.event === event).map((each) => each.payload as RefreshEventMap[E]),
      names: () => events.map((each) => each.event),
      wake: () => {
        for (const listener of Array.from(wakeListeners)) clock.task(id, listener);
      },
    };
  };

  for (let i = 0; i < (options.tabs ?? 1); i++) world.addTab(`tab-${i}`);
  return world;
}

/** Records how a promise settled, without an unhandled rejection. */
export function track<T>(promise: Promise<T>) {
  const state: { status: 'pending' | 'resolved' | 'rejected'; value?: T; error?: unknown; at?: number } = {
    status: 'pending',
  };
  promise.then(
    (value) => {
      state.status = 'resolved';
      state.value = value;
    },
    (error: unknown) => {
      state.status = 'rejected';
      state.error = error;
    },
  );
  return state;
}
