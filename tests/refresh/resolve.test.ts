// Architecture §2.2, §7 and amendment A5: how `refreshCoordination` resolves for one instance.
// jsdom has window, document and BroadcastChannel but no navigator.locks.
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { PlatformAdapter } from '../../lib/platform';
import { WebAdapter } from '../../lib/platform';
import { refreshNames } from '../../lib/refresh/protocol';
import { defaultRefreshClock, FALLBACK_WARNING, resolveCoordination } from '../../lib/refresh/resolve';
import type { RefreshCoordinator } from '../../lib/refresh/types';
import { createVirtualClock } from './fakes';
import { createWorld, track } from './harness';

const keys = { tokenKeys: () => ['access_token', 'refresh_token'] };

/** The adapter members resolution reads: the device type and the shared-storage hint. */
function platform(overrides: Partial<PlatformAdapter> & { shared?: boolean } = {}): PlatformAdapter {
  const { shared, ...rest } = overrides;
  return {
    storage: window.localStorage,
    storageSharedAcrossTabs: shared ?? true,
    getDeviceType: () => 'web' as const,
    ...rest,
  } as unknown as PlatformAdapter;
}

function fakeLocks() {
  return { request: vi.fn(() => new Promise<unknown>(() => undefined)) };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('resolveCoordination', () => {
  it('uses a custom coordinator as given: coordinated, its transports and clock, never falls back', () => {
    const clock = createVirtualClock().scheduler('t', () => 0.25);
    const coordinator: RefreshCoordinator = {
      locks: fakeLocks(),
      channel: { postMessage: vi.fn(), addEventListener: vi.fn(), removeEventListener: vi.fn(), close: vi.fn() },
      tabId: 'tab-x',
      clock,
      onStorageChange: () => () => undefined,
    };
    const resolved = resolveCoordination(coordinator, platform({ getDeviceType: () => 'ios' }), 'app', keys);
    expect(resolved.transports).toEqual({ locks: coordinator.locks, channel: coordinator.channel, tabId: 'tab-x' });
    expect(resolved.names).toEqual(refreshNames('app'));
    expect(resolved.clock.random()).toBe(0.25);
    expect(resolved.onStorageChange).toBe(coordinator.onStorageChange);
    expect(resolved.warnOnFirstCycle).toBe(false);
  });

  it('gives a custom coordinator without tabId a random one, and the default clock without one', () => {
    const resolved = resolveCoordination(
      {
        locks: fakeLocks(),
        channel: { postMessage: vi.fn(), addEventListener: vi.fn(), removeEventListener: vi.fn(), close: vi.fn() },
      },
      platform(),
      undefined,
      keys,
    );
    expect(resolved.transports?.tabId).toMatch(/.{8,}/);
    expect(resolved.clock).toBe(defaultRefreshClock);
  });

  it("resolves 'none' to local, silently, still watching storage events on a browser page", () => {
    const resolved = resolveCoordination('none', platform(), undefined, keys);
    expect(resolved.transports).toBeNull();
    expect(resolved.warnOnFirstCycle).toBe(false);
    expect(resolved.onStorageChange).toBeTypeOf('function');
  });

  it("falls back from 'web-locks' to local without navigator.locks (jsdom), with the warning flag, and opens no channel", () => {
    const channel = vi.fn();
    vi.stubGlobal('BroadcastChannel', channel);
    const resolved = resolveCoordination(undefined, platform(), undefined, keys);
    expect(resolved.transports).toBeNull();
    expect(resolved.warnOnFirstCycle).toBe(true);
    expect(channel).not.toHaveBeenCalled();
  });

  it("coordinates 'web-locks' with navigator.locks and BroadcastChannel, on the prefix-scoped channel", () => {
    const locks = fakeLocks();
    vi.stubGlobal('navigator', { ...navigator, locks });
    const opened: string[] = [];
    vi.stubGlobal(
      'BroadcastChannel',
      class {
        constructor(name: string) {
          opened.push(name);
        }
        postMessage() {}
        addEventListener() {}
        removeEventListener() {}
        close() {}
      },
    );
    const resolved = resolveCoordination('web-locks', platform(), 'p', keys);
    expect(resolved.transports?.locks).toBe(locks);
    expect(opened).toEqual(['passflow-auth:p']);
    expect(resolved.names.lock).toBe('passflow-refresh:p');
    expect(resolved.warnOnFirstCycle).toBe(false);
  });

  it('resolves a per-tab storage to local without a warning (A5: the adapter decides)', () => {
    vi.stubGlobal('navigator', { ...navigator, locks: fakeLocks() });
    const resolved = resolveCoordination('web-locks', platform({ shared: false }), undefined, keys);
    expect(resolved.transports).toBeNull();
    expect(resolved.warnOnFirstCycle).toBe(false);
  });

  it('treats an adapter whose storage hint throws as per-tab', () => {
    vi.stubGlobal('navigator', { ...navigator, locks: fakeLocks() });
    const throwing = platform();
    Object.defineProperty(throwing, 'storageSharedAcrossTabs', {
      get() {
        throw new Error('SecurityError');
      },
    });
    const resolved = resolveCoordination('web-locks', throwing, undefined, keys);
    expect(resolved.transports).toBeNull();
    expect(resolved.warnOnFirstCycle).toBe(false);
  });

  it('resolves a non-web platform to local, silently, with no storage watch', () => {
    vi.stubGlobal('navigator', { ...navigator, locks: fakeLocks() });
    const resolved = resolveCoordination('web-locks', platform({ getDeviceType: () => 'android' }), undefined, keys);
    expect(resolved.transports).toBeNull();
    expect(resolved.warnOnFirstCycle).toBe(false);
    expect(resolved.onStorageChange).toBeUndefined();
  });

  it('marks the default web adapter storage as shared across tabs', () => {
    expect(new WebAdapter().storageSharedAcrossTabs).toBe(true);
  });

  it('filters the window storage event to the token keys', () => {
    const resolved = resolveCoordination('none', platform(), undefined, keys);
    const listener = vi.fn();
    const stop = resolved.onStorageChange?.(listener);
    window.dispatchEvent(new StorageEvent('storage', { key: 'unrelated' }));
    window.dispatchEvent(new StorageEvent('storage', { key: 'refresh_token' }));
    window.dispatchEvent(new StorageEvent('storage', { key: null }));
    stop?.();
    window.dispatchEvent(new StorageEvent('storage', { key: 'refresh_token' }));
    expect(listener).toHaveBeenCalledTimes(2);
  });
});

describe('fallback warning', () => {
  it('is written once, on the first refresh, never at construction', async () => {
    const w = createWorld({ coordinated: false });
    const [tab] = w.tabs;
    // The harness resolves with warnOnFirstCycle false; build one that warns.
    const warnings: string[] = [];
    const { createRefreshController } = await import('../../lib/refresh/controller');
    const controller = createRefreshController({
      emit: () => undefined,
      storage: tab.storage,
      cache: tab.cache,
      transport: {
        mode: () => 'json',
        send: () => new Promise(() => undefined),
        applyOpaque: () => Promise.resolve(),
        invalidate: () => undefined,
        assertPin: () => undefined,
      },
      coordination: {
        transports: null,
        names: refreshNames(''),
        clock: w.clock.scheduler('warn'),
        warnOnFirstCycle: true,
      },
      logger: { warn: (m: string) => warnings.push(m), error: () => undefined, info: () => undefined, debug: () => undefined },
    });
    expect(warnings).toEqual([]);
    track(controller.refresh({ trigger: 'token-check' }));
    track(controller.refresh({ trigger: 'refresh-token', fresh: true }));
    await w.run();
    expect(warnings).toEqual([FALLBACK_WARNING]);
    controller.dispose();
  });
});
