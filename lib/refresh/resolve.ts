/**
 * Resolution of `PassflowConfig.refreshCoordination` (architecture §2.2, §7, amendment A5).
 *
 *   - a RefreshCoordinator object → coordinated over its transports; never falls back;
 *   - 'none' → local (single instance), silent;
 *   - 'web-locks' (default) → coordinated only on a browser page (window and document exist,
 *     platform.getDeviceType() === 'web') whose platform storage is shared by every tab (the
 *     adapter says so: `storageSharedAcrossTabs`, true for the default web adapter; never decided
 *     by identity comparison), with `navigator.locks.request` and `BroadcastChannel`. The channel
 *     is created only after the locks check passes, so Node/jsdom (BroadcastChannel without
 *     navigator.locks) opens no channel that would hold the event loop. Otherwise → local, with
 *     the one fallback warning only for a shared-storage browser page that lacks the APIs.
 *
 * Local coordination on a browser page still watches the window `storage` event (filtered to the
 * token keys), so fallback tabs follow each other's writes forward.
 *
 * @module refresh/resolve
 */

import type { PlatformAdapter } from '../platform';
import { type RefreshNames, refreshNames } from './protocol';
import type { RefreshChannel, RefreshClock, RefreshCoordination, RefreshLockManager } from './types';

/** The transports of the cross-tab protocol for one instance. */
export interface CrossTabTransports {
  locks: RefreshLockManager;
  channel: RefreshChannel;
  tabId: string;
}

/** What `refreshCoordination` resolved to for one instance. */
export interface ResolvedCoordination {
  /** Cross-tab transports, or null: local (single-instance) coordination. */
  transports: CrossTabTransports | null;
  /** Lock and channel names for the storage prefix. */
  names: RefreshNames;
  /** The time source of every refresh timer of the instance. */
  clock: Required<RefreshClock>;
  /** Another tab wrote the shared token storage. Returns unsubscribe. */
  onStorageChange?: (listener: () => void) => () => void;
  /** Write the fallback warning once, when the instance first starts a refresh. */
  warnOnFirstCycle: boolean;
}

export const FALLBACK_WARNING =
  '[passflow] navigator.locks or BroadcastChannel is unavailable (they need a secure context); each tab refreshes on its own, with the save checks only';

/** Date.now / setTimeout / Math.random; Node timers are unref'd so they never hold the process. */
export const defaultRefreshClock: Required<RefreshClock> = {
  now: () => Date.now(),
  random: () => Math.random(),
  setTimeout: (fn, ms) => {
    const timer = setTimeout(fn, ms) as unknown as { unref?: () => void };
    timer.unref?.();
    return () => clearTimeout(timer as unknown as ReturnType<typeof setTimeout>);
  },
};

/** A random tab id: crypto.randomUUID() where available. */
export function newTabId(): string {
  const cryptoApi = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (typeof cryptoApi?.randomUUID === 'function') return cryptoApi.randomUUID();
  return `tab-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

function completeClock(clock: RefreshClock | undefined): Required<RefreshClock> {
  if (!clock) return defaultRefreshClock;
  const random = clock.random ? () => clock.random?.() ?? Math.random() : defaultRefreshClock.random;
  return { now: () => clock.now(), setTimeout: (fn, ms) => clock.setTimeout(fn, ms), random };
}

function isBrowserPage(platform: PlatformAdapter): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined' && platform.getDeviceType() === 'web';
}

function sharesStorage(platform: PlatformAdapter): boolean {
  try {
    return platform.storageSharedAcrossTabs === true;
  } catch {
    return false;
  }
}

function browserLocks(): RefreshLockManager | undefined {
  try {
    const locks = (globalThis as { navigator?: { locks?: { request?: unknown } } }).navigator?.locks;
    return locks && typeof locks.request === 'function' ? (locks as unknown as RefreshLockManager) : undefined;
  } catch {
    return undefined;
  }
}

/** The window `storage` event, filtered to `keys` (null key: storage cleared). */
function windowStorageEvents(keys: () => string[]): (listener: () => void) => () => void {
  return (listener) => {
    const handler = (event: Event): void => {
      const key = (event as StorageEvent).key;
      if (key === null || key === undefined || keys().includes(key)) listener();
    };
    window.addEventListener('storage', handler);
    return () => window.removeEventListener('storage', handler);
  };
}

/** Local (single-instance) coordination with no storage watch: the default of a standalone AuthService. */
export function localCoordination(keyStoragePrefix?: string): ResolvedCoordination {
  return { transports: null, names: refreshNames(keyStoragePrefix), clock: defaultRefreshClock, warnOnFirstCycle: false };
}

export interface ResolveOptions {
  /** The storage keys a token write touches (StorageManager.tokenKeys), for the storage-event filter. */
  tokenKeys: () => string[];
}

/**
 * Resolves `refreshCoordination` for one instance. Creates the BroadcastChannel (web-locks) only
 * when it will be used.
 */
export function resolveCoordination(
  config: RefreshCoordination | undefined,
  platform: PlatformAdapter,
  keyStoragePrefix: string | undefined,
  options: ResolveOptions,
): ResolvedCoordination {
  const names = refreshNames(keyStoragePrefix);
  const browser = isBrowserPage(platform);
  const storageEvents = browser ? windowStorageEvents(options.tokenKeys) : undefined;
  const local = (warnOnFirstCycle: boolean): ResolvedCoordination => {
    const resolved: ResolvedCoordination = { transports: null, names, clock: defaultRefreshClock, warnOnFirstCycle };
    if (storageEvents) resolved.onStorageChange = storageEvents;
    return resolved;
  };

  if (typeof config === 'object' && config !== null) {
    const resolved: ResolvedCoordination = {
      transports: { locks: config.locks, channel: config.channel, tabId: config.tabId ?? newTabId() },
      names,
      clock: completeClock(config.clock),
      warnOnFirstCycle: false,
    };
    if (config.onStorageChange) resolved.onStorageChange = config.onStorageChange;
    return resolved;
  }
  if (config === 'none') return local(false);

  // 'web-locks' (explicit or default).
  if (!browser || !sharesStorage(platform)) return local(false);
  const locks = browserLocks();
  if (!locks || typeof BroadcastChannel !== 'function') return local(true);
  let channel: RefreshChannel;
  try {
    channel = new BroadcastChannel(names.channel) as unknown as RefreshChannel;
  } catch {
    return local(true);
  }
  const resolved: ResolvedCoordination = {
    transports: { locks, channel, tabId: newTabId() },
    names,
    clock: defaultRefreshClock,
    warnOnFirstCycle: false,
  };
  if (storageEvents) resolved.onStorageChange = storageEvents;
  return resolved;
}
