/**
 * Cross-tab sign-out on real `Passflow` instances (PFL-792 §2.8, §2.9.9, §2.13 #8 and #16).
 *
 * Every tab is a `Passflow` over one shared storage, coordinated through the fake Web Locks and
 * BroadcastChannel on a virtual clock (tests/refresh/fakes.ts). Only HTTP is stubbed:
 * `AuthAPI.prototype.refreshToken` and `AuthAPI.prototype.logOut`.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { Passflow } from '../../lib/passflow';
import { StorageManager } from '../../lib/storage';
import { PassflowEvent } from '../../lib/store';
import type { Tokens } from '../../lib/types';
import { TEST_CONFIG } from '../helpers/fixtures';
import { createMockPlatform } from '../helpers/mock-platform';
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

const FUTURE = 4_102_444_800;
const EXPIRED = 1_600_000_000;

let issued = 0;
const pairOf = (sub: string, iat: number, fresh = false): Tokens => {
  issued += 1;
  return {
    access_token: jwt({ sub, sid: 's1', exp: fresh ? FUTURE : EXPIRED, iat, jti: `access-${issued}`, type: 'access' }),
    refresh_token: jwt({ sub, sid: 's1', exp: FUTURE, iat, jti: `refresh-${issued}`, type: 'refresh' }),
    scopes: TEST_CONFIG.scopes,
  };
};

interface Tab {
  id: string;
  passflow: Passflow;
  events: { event: PassflowEvent; payload: unknown; cached: Tokens | undefined }[];
}

describe('sign-out across tabs', () => {
  let clock: VirtualClock;
  let locks: FakeLockManager;
  let hub: FakeChannelHub;
  let shared: SharedStorage;
  let tabs: Tab[];
  let logOutApi: ReturnType<typeof vi.spyOn>;

  const openTab = (id: string): Tab => {
    const platform = createMockPlatform({ storage: shared.view(id) });
    const passflow = new Passflow({
      ...TEST_CONFIG,
      platform,
      refreshCoordination: {
        locks: locks.forTab(id),
        channel: hub.channel(id),
        tabId: id,
        clock: clock.scheduler(id, () => 0),
        onStorageChange: shared.storageEvents(id),
      },
    });
    const tab: Tab = { id, passflow, events: [] };
    passflow.subscribe({
      onAuthChange: (event, payload) => tab.events.push({ event, payload, cached: passflow.getCachedTokens() }),
    });
    tabs.push(tab);
    return tab;
  };

  const seed = (tokens: Tokens) => new StorageManager({ storage: shared.view('seed') }).saveTokens(tokens);
  /** Every shared key but the device id, which outlives a sign-out. */
  const storedKeys = () => [...shared.items.keys()].filter((key) => key !== 'passflowDeviceId');
  const signOutsOf = (tab: Tab) => tab.events.filter((e) => e.event === PassflowEvent.SignOut);
  const endsOf = (tab: Tab) =>
    tab.events.filter((e) => e.event === PassflowEvent.SignOut || e.event === PassflowEvent.SessionExpired);
  /** Lets tasks run and moves the virtual clock on (0 ms still fires due timers: the grant hop). */
  const run = async (ms = 0) => {
    await settle();
    await clock.advance(ms, () => settle());
    await settle();
  };

  beforeEach(() => {
    clock = createVirtualClock();
    locks = createFakeLockManager(clock);
    hub = createFakeChannelHub(clock);
    shared = createSharedStorage(clock);
    tabs = [];
    logOutApi = vi.spyOn(AuthAPI.prototype, 'logOut').mockResolvedValue({ status: 'ok' } as never);
  });

  afterEach(() => {
    for (const tab of tabs) tab.passflow.dispose();
    vi.restoreAllMocks();
  });

  test('logOut() in tab A: A gets one SignOut{this-tab}, every other tab of the user one SignOut{other-tab}', async () => {
    seed(pairOf('user-a', 1_700_000_000, true));
    const a = openTab('a');
    const b = openTab('b');
    const c = openTab('c');
    expect(b.passflow.getCachedTokens()?.refresh_token).toBeDefined();

    const loggingOut = a.passflow.logOut();
    await run();
    await loggingOut;
    await run(3_000);

    expect(signOutsOf(a).map((e) => e.payload)).toEqual([{ origin: 'this-tab', userId: 'user-a' }]);
    for (const other of [b, c]) {
      expect(endsOf(other).map((e) => [e.event, e.payload])).toEqual([
        [PassflowEvent.SignOut, { origin: 'other-tab', userId: 'user-a' }],
      ]);
      expect(signOutsOf(other)[0]?.cached).toBeUndefined();
      expect(other.passflow.getCachedTokens()).toBeUndefined();
    }
    expect(signOutsOf(a)[0]?.cached).toBeUndefined();
    expect(storedKeys()).toEqual([]);
    expect(logOutApi).toHaveBeenCalledTimes(1);
    expect(hub.posted.filter((m) => (m.data as { type?: string }).type === 'signed-out')).toHaveLength(1);
  });

  test('reset() in tab A (synchronous) ends tab B with one SignOut{other-tab} and calls no API', async () => {
    seed(pairOf('user-a', 1_700_000_000, true));
    const a = openTab('a');
    const b = openTab('b');

    a.passflow.reset();
    expect(signOutsOf(a).map((e) => e.payload)).toEqual([{ origin: 'this-tab', userId: 'user-a' }]);
    await run(3_000);

    expect(endsOf(b).map((e) => e.payload)).toEqual([{ origin: 'other-tab', userId: 'user-a' }]);
    expect(logOutApi).not.toHaveBeenCalled();
    expect(storedKeys()).toEqual([]);
  });

  test('logout during a coordinated refresh waits for the answer and logs out the new token (§2.13 #16)', async () => {
    const first = pairOf('user-a', 1_700_000_000);
    seed(first);
    const rotated = pairOf('user-a', 1_700_000_060, true);
    let answer: (tokens: Tokens) => void = () => undefined;
    const refreshToken = vi.spyOn(AuthAPI.prototype, 'refreshToken').mockImplementation(
      () =>
        new Promise((resolve) => {
          answer = (tokens) => resolve({ ...tokens } as never);
        }),
    );
    const a = openTab('a');
    const b = openTab('b');

    const refreshing = a.passflow.refreshToken().catch((error: unknown) => error);
    await run();
    expect(refreshToken).toHaveBeenCalledTimes(1);

    const loggingOut = b.passflow.logOut();
    await run(1_000);
    // A holds the lock mid-request: B's logout call waits for A's answer.
    expect(logOutApi).not.toHaveBeenCalled();

    answer(rotated);
    await run();
    await loggingOut;
    await run(3_000);

    expect(await refreshing).toMatchObject({ refresh_token: rotated.refresh_token });
    expect(logOutApi).toHaveBeenCalledTimes(1);
    expect(logOutApi.mock.calls[0]?.[1]).toBe(rotated.refresh_token);
    expect(storedKeys()).toEqual([]);
    expect(signOutsOf(b).map((e) => e.payload)).toEqual([{ origin: 'this-tab', userId: 'user-a' }]);
    expect(signOutsOf(a).map((e) => e.payload)).toEqual([{ origin: 'other-tab', userId: 'user-a' }]);
    expect(a.passflow.getCachedTokens()).toBeUndefined();
    expect(refreshToken).toHaveBeenCalledTimes(1);
  });

  test('a holder in backoff yields the lock to a logout at once', async () => {
    seed(pairOf('user-a', 1_700_000_000));
    const outage = Object.assign(new Error('Network Error'), { isAxiosError: true });
    const refreshToken = vi.spyOn(AuthAPI.prototype, 'refreshToken').mockRejectedValue(outage);
    const a = openTab('a');
    const b = openTab('b');

    const refreshing = a.passflow.refreshToken().catch((error: unknown) => error);
    await run();
    expect(await refreshing).toBe(outage);
    // A holds the lock in backoff; its next attempt is due at t = 1 s.
    const loggingOut = b.passflow.logOut();
    await run();
    await loggingOut;

    expect(clock.now()).toBeLessThan(1_000);
    expect(logOutApi).toHaveBeenCalledTimes(1);
    expect(signOutsOf(b)).toHaveLength(1);

    await run(120_000);
    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(signOutsOf(a).map((e) => e.payload)).toEqual([{ origin: 'other-tab', userId: 'user-a' }]);
  });

  test('a logout whose lock wait passes 5 s still cleans up and emits its SignOut', async () => {
    seed(pairOf('user-a', 1_700_000_000));
    vi.spyOn(AuthAPI.prototype, 'refreshToken').mockImplementation(() => new Promise(() => undefined));
    const a = openTab('a');
    const b = openTab('b');

    a.passflow.refreshToken().catch(() => undefined);
    await run();
    // A is frozen mid-request: no heartbeat, no answer, no release.
    clock.freeze('a');
    hub.freeze('a');

    const loggingOut = b.passflow.logOut();
    await run(5_000);
    await loggingOut;

    expect(logOutApi).toHaveBeenCalledTimes(1);
    expect(signOutsOf(b).map((e) => e.payload)).toEqual([{ origin: 'this-tab', userId: 'user-a' }]);
    expect(b.passflow.getCachedTokens()).toBeUndefined();
    expect(storedKeys()).toEqual([]);
  });
});
