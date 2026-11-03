/**
 * Real `Passflow` instances as browser tabs (PFL-792 architecture §2.12), for the black-box
 * multi-tab and event suites.
 *
 * Every tab is a `Passflow` over one shared storage, coordinated through the fake Web Locks and
 * BroadcastChannel on one virtual clock (tests/refresh/fakes.ts), with `clock.random = () => 0` so
 * the retry schedule is exact. Only HTTP is stubbed: `AuthAPI.prototype.refreshToken` (§2.8a),
 * which records who sent what and when, and answers through the test's `answer` function.
 */
import { vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { type PassflowConfig, PassflowError } from '../../lib/api/model';
import { Passflow } from '../../lib/passflow';
import { StorageManager } from '../../lib/storage';
import { PassflowEvent } from '../../lib/store';
import type { Tokens } from '../../lib/types';
import { TEST_CONFIG } from '../helpers/fixtures';
import { createMockPlatform, type MockPlatform } from '../helpers/mock-platform';
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
import { jwt } from './jwt';

export const FUTURE = 4_102_444_800;
export const EXPIRED = 1_600_000_000;
/** The outage schedule of §2.13 #2 with random = 0: 0, then +1, +3, +10, +30, +60, +60 s. */
export const OUTAGE_SCHEDULE = [0, 1_000, 4_000, 14_000, 44_000, 104_000, 164_000];

let issued = 0;
let lastIat = 1_700_000_000;

/** A token pair of `sub`/`sid`. The access token is expired unless `fresh`. Each pair has a later `iat`. */
export function pairOf(sub = 'user-1', options: { fresh?: boolean; sid?: string } = {}): Tokens {
  issued += 1;
  lastIat += 60;
  const sid = options.sid ?? 's1';
  return {
    access_token: jwt({
      sub,
      sid,
      exp: options.fresh ? FUTURE : EXPIRED,
      iat: lastIat,
      jti: `access-${issued}`,
      type: 'access',
    }),
    refresh_token: jwt({ sub, sid, exp: FUTURE, iat: lastIat, jti: `refresh-${issued}`, type: 'refresh' }),
    scopes: TEST_CONFIG.scopes,
  };
}

function claimsOf(token: string): { sub?: string; sid?: string } {
  try {
    const payload = token.split('.')[1] ?? '';
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8')) as { sub?: string; sid?: string };
  } catch {
    return {};
  }
}

/** The server's rotation of `refreshToken`: a new pair of the same user and session, access token fresh. */
export function rotationOf(refreshToken: string): Tokens {
  const { sub, sid } = claimsOf(refreshToken);
  return pairOf(sub ?? 'user-1', { fresh: true, sid: sid ?? 's1' });
}

export const httpError = (id: string, status: number): PassflowError =>
  new PassflowError({ id, message: id, status, location: '/auth/refresh', time: new Date(0).toISOString() });
export const outage = (): PassflowError => httpError('error.http.503', 503);
export const blocked = (): PassflowError => httpError('error.token.blocked', 400);
export const invalid = (): PassflowError => httpError('error.token.invalid.error', 400);
/** The shape the SDK produces for a POST 429: the raw axios error (§2.8a). */
export const rateLimited = (seconds: number): unknown =>
  Object.assign(new Error('Request failed with status code 429'), {
    isAxiosError: true,
    response: { status: 429, headers: { 'retry-after': String(seconds) }, data: {} },
  });
export const networkError = (): unknown =>
  Object.assign(new Error('Network Error'), { isAxiosError: true, code: 'ERR_NETWORK' });

export interface SentRequest {
  tab: string;
  at: number;
  refreshToken: string;
  upgrade?: unknown;
  resolve: (tokens: Tokens) => void;
  reject: (error: unknown) => void;
}

/** How the stub server answers one request: rotate the sent token, hold it for the test, reject, or answer these tokens. */
export type Answer = 'rotate' | 'hold' | { error: unknown } | { tokens: Tokens };

export interface RecordedEvent {
  event: PassflowEvent;
  payload: unknown;
  /** `getCachedTokens()` at the moment the event was delivered. */
  cached: Tokens | undefined;
}

export interface Tab {
  id: string;
  passflow: Passflow;
  events: RecordedEvent[];
  /** Event names in order. */
  names: () => PassflowEvent[];
  /** Payloads of one event, in order. */
  of: <T = Record<string, unknown>>(event: PassflowEvent) => T[];
}

export interface Tracked<T> {
  status: 'pending' | 'resolved' | 'rejected';
  value?: T;
  error?: unknown;
  at?: number;
}

export interface SdkWorld {
  clock: VirtualClock;
  locks: FakeLockManager;
  hub: FakeChannelHub;
  shared: SharedStorage;
  tabs: Tab[];
  requests: SentRequest[];
  /** Opens a tab: a new `Passflow` over the shared storage with its own fake coordinator (plus `config`). */
  open: (id: string, config?: Partial<PassflowConfig>, platform?: Partial<MockPlatform>) => Tab;
  /** Writes a pair into the shared storage as if an earlier page had signed in. */
  seed: (tokens: Tokens) => void;
  /** The shared tokens (StorageManager view). */
  stored: () => Tokens | undefined;
  /** A copy of every shared key but the device id. */
  snapshot: () => Record<string, string>;
  /** Lets tasks run and moves the virtual clock on by `ms` (0 still fires due timers: the grant hop). */
  run: (ms?: number) => Promise<void>;
  /** Lets the opened tabs finish loading, then forgets their load-time events (`TokenCacheExpired{true}` for an expired access token). */
  ready: () => Promise<void>;
  /** The page is gone: no timers, no messages, its locks released. */
  kill: (tab: Tab) => void;
  /** Settles a promise into a record the test reads synchronously. */
  track: <T>(promise: Promise<T>) => Tracked<T>;
  sentBy: (tab: Tab) => SentRequest[];
  postedTypes: () => string[];
  dispose: () => void;
}

export function createSdkWorld(answer: (request: SentRequest) => Answer = () => 'rotate'): SdkWorld {
  const clock = createVirtualClock();
  const locks = createFakeLockManager(clock);
  const hub = createFakeChannelHub(clock);
  const shared = createSharedStorage(clock);
  const tabs: Tab[] = [];
  const requests: SentRequest[] = [];
  const tabOfApi = new WeakMap<object, string>();
  const reader = new StorageManager({ storage: shared.view('reader') });

  vi.spyOn(AuthAPI.prototype, 'refreshToken').mockImplementation(function (
    this: AuthAPI,
    refreshToken: string,
    _scopes: string[],
    _accessToken?: string,
    upgrade?: unknown,
  ) {
    return new Promise((resolve, reject) => {
      const request: SentRequest = {
        tab: tabOfApi.get(this) ?? 'unknown',
        at: clock.now(),
        refreshToken,
        ...(upgrade !== undefined ? { upgrade } : {}),
        resolve: (tokens) => resolve({ ...tokens } as never),
        reject,
      };
      requests.push(request);
      const decision = answer(request);
      if (decision === 'hold') return;
      if (decision === 'rotate') request.resolve(rotationOf(refreshToken));
      else if ('error' in decision) request.reject(decision.error);
      else request.resolve(decision.tokens);
    }) as never;
  });

  const run = async (ms = 0): Promise<void> => {
    await settle();
    await clock.advance(ms, () => settle());
    await settle();
  };

  const world: SdkWorld = {
    clock,
    locks,
    hub,
    shared,
    tabs,
    requests,
    open: (id, config = {}, platformOverrides = {}) => {
      const platform = createMockPlatform({ ...platformOverrides, storage: shared.view(id) });
      const passflow = new Passflow({
        ...TEST_CONFIG,
        ...config,
        platform,
        refreshCoordination: {
          locks: locks.forTab(id),
          channel: hub.channel(id),
          tabId: id,
          clock: clock.scheduler(id, () => 0),
          onStorageChange: shared.storageEvents(id),
        },
      });
      tabOfApi.set((passflow as unknown as { authApi: AuthAPI }).authApi, id);
      const events: RecordedEvent[] = [];
      passflow.subscribe({
        onAuthChange: (event, payload) => events.push({ event, payload, cached: passflow.getCachedTokens() }),
      });
      const tab: Tab = {
        id,
        passflow,
        events,
        names: () => events.map((e) => e.event),
        of: <T>(event: PassflowEvent) => events.filter((e) => e.event === event).map((e) => e.payload as T),
      };
      tabs.push(tab);
      return tab;
    },
    seed: (tokens) => new StorageManager({ storage: shared.view('seed') }).saveTokens(tokens),
    stored: () => reader.getTokens(),
    snapshot: () => Object.fromEntries([...shared.items.entries()].filter(([key]) => key !== 'passflowDeviceId').sort()),
    run,
    ready: async () => {
      await run();
      for (const tab of tabs) tab.events.length = 0;
    },
    kill: (tab) => {
      clock.freeze(tab.id);
      hub.close(tab.id);
      locks.kill(tab.id);
    },
    track: <T>(promise: Promise<T>): Tracked<T> => {
      const tracked: Tracked<T> = { status: 'pending' };
      promise.then(
        (value) => {
          tracked.status = 'resolved';
          tracked.value = value;
          tracked.at = clock.now();
        },
        (error: unknown) => {
          tracked.status = 'rejected';
          tracked.error = error;
          tracked.at = clock.now();
        },
      );
      return tracked;
    },
    sentBy: (tab) => requests.filter((r) => r.tab === tab.id),
    postedTypes: () => hub.posted.map((m) => String((m.data as { type?: unknown }).type)),
    dispose: () => {
      for (const tab of tabs) tab.passflow.dispose();
      vi.restoreAllMocks();
    },
  };
  return world;
}

/** Ends of a session as seen by the app: SignOut and SessionExpired. */
export const endsOf = (tab: Tab): RecordedEvent[] =>
  tab.events.filter((e) => e.event === PassflowEvent.SignOut || e.event === PassflowEvent.SessionExpired);
