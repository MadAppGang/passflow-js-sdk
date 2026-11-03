import { afterEach, beforeEach, expect, vi } from 'vitest';
import {
  AuthAPI,
  type ErrorPayload,
  type ParsedTokens,
  Passflow,
  type PassflowAuthorizationResponse,
  type PassflowConfig,
  PassflowError,
  PassflowEvent,
  type PassflowEventPayload,
  type PlatformAdapter,
  type Tokens,
  type UpgradeRefreshField,
} from '../../lib/index';
import { createFakeChannelHub, createFakeLockManager, createSharedStorage, createVirtualClock, settle } from '../refresh/fakes';

// Only transport/clock fakes are reused. No SDK harness or runtime SDK helpers are imported.
export const BASE = 1_900_000_000_000;
export const SECOND = BASE / 1_000;
export const SCHEDULE = [0, 1_000, 4_000, 14_000, 44_000, 104_000, 164_000];
export type Pair = Required<Tokens>;

export function jwt(claims: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(claims)}.c2ln`;
}

export function claims(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8'));
}

export function pair(
  iat = SECOND - 100,
  options: { sub?: string; sid?: string; tag?: string; expired?: boolean; exp?: number } = {},
): Pair {
  const sub = options.sub ?? 'qa-user';
  const sid = options.sid ?? 'qa-session';
  const common = { sub, sid, iat, iss: 'https://passflow.invalid', aud: ['qa-app'] };
  const tag = options.tag ?? String(iat);
  return {
    access_token: jwt({
      ...common,
      jti: `access-${tag}`,
      type: 'access',
      exp: options.exp ?? (options.expired === false ? SECOND + 86_400 : SECOND - 60),
      acr: 'urn:passflow:aal:2',
    }),
    refresh_token: jwt({ ...common, jti: `refresh-${tag}`, type: 'refresh', exp: SECOND + 86_400 }),
    id_token: jwt({ ...common, jti: `id-${tag}`, type: 'id_token', exp: SECOND + 86_400 }),
    scopes: ['id', 'offline', 'openid'],
  };
}

export function successor(token: string, extra = 1): Pair {
  const c = claims(token);
  return pair(Number(c.iat) + extra, { sub: String(c.sub), sid: String(c.sid), expired: false });
}

export function http(id = 'error.http.503', status = 503): PassflowError {
  return new PassflowError({
    id,
    status,
    message: id,
    location: '/auth/refresh',
    time: new Date(BASE).toISOString(),
  });
}

export const network = () =>
  Object.assign(new Error('Network Error'), {
    isAxiosError: true,
    code: 'ERR_NETWORK',
  });

export function axiosError(status: number, id?: string, retryAfter?: string): unknown {
  return Object.assign(new Error(`HTTP ${status}`), {
    isAxiosError: true,
    response: {
      status,
      headers: retryAfter === undefined ? {} : { 'retry-after': retryAfter },
      data: id ? { error: { id } } : {},
    },
  });
}

// Independent, documented wire fingerprint, not an import of SDK lineage logic.
export function fingerprint(value: string): string {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
}

export function tokenMessage(from: Pair, to: Pair, overrides: Record<string, unknown> = {}) {
  const c = claims(from.refresh_token);
  return {
    v: 1,
    type: 'tokens-refreshed',
    tabId: 'protocol-peer',
    tokens: to,
    from: fingerprint(from.refresh_token),
    fromIat: c.iat,
    fromSid: c.sid ?? '',
    to: fingerprint(to.refresh_token),
    ...overrides,
  };
}

export function endMessage(tokens: Pair, type = 'session-ended') {
  const c = claims(tokens.refresh_token);
  return {
    v: 1,
    type,
    tabId: 'protocol-peer',
    fp: fingerprint(tokens.refresh_token),
    sub: c.sub,
    sid: c.sid,
    iat: c.iat,
  };
}

export interface Observed<T> {
  status: 'pending' | 'resolved' | 'rejected';
  value?: T;
  error?: unknown;
}

export function observe<T>(promise: Promise<T>): Observed<T> {
  const out: Observed<T> = { status: 'pending' };
  promise.then(
    (value) => {
      out.status = 'resolved';
      out.value = value;
    },
    (error: unknown) => {
      out.status = 'rejected';
      out.error = error;
    },
  );
  return out;
}

export interface EventRecord {
  event: PassflowEvent;
  payload: unknown;
  cached?: Tokens;
  parsed?: ParsedTokens;
}

export interface PublicTab {
  id: string;
  sdk: Passflow;
  events: EventRecord[];
  wake(): void;
  unload(): void;
  of<E extends PassflowEvent>(event: E): PassflowEventPayload[E][];
  names(): PassflowEvent[];
}

export interface RequestRecord {
  at: number;
  sender?: string;
  token: string;
  scopes: string[];
  access?: string;
  upgrade?: UpgradeRefreshField;
  resolve(response: PassflowAuthorizationResponse): void;
  reject(error: unknown): void;
}

export type Reply = 'hold' | 'success' | { error: unknown } | { tokens: PassflowAuthorizationResponse };
type WorldOptions = {
  mode?: 'custom' | 'none' | 'browser';
  random?: () => number;
  config?: Partial<PassflowConfig>;
  sharedHint?: boolean;
  device?: 'web' | 'ios' | 'android';
  watchStorage?: boolean;
};

const active: { dispose(): void }[] = [];

beforeEach(() => {
  // setImmediate stays real: fake browser grants and messages are asynchronous tasks.
  vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] });
  vi.setSystemTime(BASE);
});

afterEach(async () => {
  for (const fixture of active.splice(0)) fixture.dispose();
  await settle();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

export function world(answer: (request: RequestRecord, index: number) => Reply = () => 'success', options: WorldOptions = {}) {
  const clock = createVirtualClock();
  const locks = createFakeLockManager(clock);
  const hub = createFakeChannelHub(clock);
  const shared = createSharedStorage(clock);
  const tabs: PublicTab[] = [];
  const requests: RequestRecord[] = [];
  const disposed = new WeakSet<Passflow>();
  const mode = options.mode ?? 'custom';
  const config: PassflowConfig = {
    url: 'https://passflow.invalid',
    appId: 'qa-app',
    parseQueryParams: false,
    scopes: ['id', 'offline', 'openid'],
    ...options.config,
  };
  const now = () => (mode === 'custom' ? clock.now() : Date.now() - BASE);
  let sender: string | undefined;

  vi.spyOn(AuthAPI.prototype, 'refreshToken').mockImplementation(function (token, scopes, access, upgrade) {
    return new Promise<PassflowAuthorizationResponse>((resolve, reject) => {
      const request: RequestRecord = {
        at: now(),
        sender,
        token,
        scopes,
        access,
        upgrade,
        resolve,
        reject,
      };
      sender = undefined;
      requests.push(request);
      const reply = answer(request, requests.length - 1);
      if (reply === 'hold') return;
      if (reply === 'success') resolve(successor(token));
      else if ('error' in reply) reject(reply.error);
      else resolve(reply.tokens);
    });
  });

  function open(id: string, overrides: Partial<PassflowConfig> = {}, viewId = id): PublicTab {
    const foreground = new Set<() => void>();
    const unloading = new Set<() => void>();
    const platform: PlatformAdapter = {
      storage: shared.view(viewId),
      storageSharedAcrossTabs: options.sharedHint ?? true,
      getCurrentUrl: () => ({
        href: 'https://app.invalid/',
        origin: 'https://app.invalid',
        hostname: 'app.invalid',
        pathname: '/',
        search: '',
        hash: '',
      }),
      replaceUrl: () => {},
      navigateTo: () => {},
      onForeground: (listener) => {
        foreground.add(listener);
        return () => foreground.delete(listener);
      },
      onBackground: () => () => {},
      onBeforeUnload: (listener) => {
        unloading.add(listener);
        return () => unloading.delete(listener);
      },
      isInForeground: () => true,
      openAuthUrl: async () => ({ callbackSearch: '', callbackHash: '' }),
      btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
      atob: (value) => Buffer.from(value, 'base64').toString('binary'),
      cookiesSupported: () => true,
      getDeviceType: () => options.device ?? 'web',
    };
    const tabClock = clock.scheduler(id, options.random ?? (() => 0));
    const sdk = new Passflow({
      ...config,
      platform,
      ...(mode === 'custom'
        ? {
            refreshCoordination: {
              locks: locks.forTab(id),
              channel: hub.channel(id),
              tabId: id,
              clock: { ...tabClock, now: () => BASE + clock.now() },
              ...(options.watchStorage === false ? {} : { onStorageChange: shared.storageEvents(viewId) }),
            },
          }
        : mode === 'none'
          ? { refreshCoordination: 'none' as const }
          : {}),
      ...overrides,
    });
    const events: EventRecord[] = [];
    sdk.subscribe({
      onAuthChange: (event, payload) => {
        if (event === PassflowEvent.RefreshStart) sender = id;
        events.push({
          event,
          payload,
          cached: sdk.getCachedTokens() && { ...sdk.getCachedTokens() },
          parsed: sdk.getParsedTokens() && { ...sdk.getParsedTokens() },
        });
      },
    });
    const tab: PublicTab = {
      id,
      sdk,
      events,
      wake: () => {
        for (const listener of [...foreground]) listener();
      },
      unload: () => {
        for (const listener of [...unloading]) listener();
      },
      of: <E extends PassflowEvent>(event: E) =>
        events.filter((item) => item.event === event).map((item) => item.payload as PassflowEventPayload[E]),
      names: () => events.map((item) => item.event),
    };
    tabs.push(tab);
    return tab;
  }

  async function run(ms = 0): Promise<void> {
    await settle();
    if (mode === 'custom') await clock.advance(ms, () => settle());
    else await vi.advanceTimersByTimeAsync(ms);
    await settle();
  }

  function seed(tokens: Tokens, overrides: Partial<PassflowConfig> = {}): void {
    const seeder = open('seeder', { refreshCoordination: 'none', ...overrides });
    seeder.sdk.setTokens(tokens);
    close(seeder);
    tabs.splice(tabs.indexOf(seeder), 1);
  }

  function close(tab: PublicTab): void {
    if (disposed.has(tab.sdk)) return;
    disposed.add(tab.sdk);
    tab.sdk.dispose();
  }

  const fixture = {
    clock,
    locks,
    hub,
    shared,
    tabs,
    requests,
    config,
    open,
    seed,
    run,
    now,
    close,
    async ready() {
      await run();
      for (const tab of tabs) tab.events.length = 0;
    },
    // Reload via the public API, without knowledge of any token key names.
    async stored(overrides: Partial<PassflowConfig> = {}): Promise<Tokens | undefined> {
      const reader = open(`reader-${tabs.length}`, { refreshCoordination: 'none', ...overrides });
      await run();
      const result = reader.sdk.getCachedTokens();
      close(reader);
      tabs.splice(tabs.indexOf(reader), 1);
      return result;
    },
    snapshot: () => new Map(shared.items),
    restore(snapshot: Map<string, string>) {
      shared.items.clear();
      for (const [key, value] of snapshot) shared.items.set(key, value);
    },
    empty() {
      // Deleting every session key simulates another process clearing shared storage.
      for (const key of [...shared.items.keys()]) shared.view('external-storage-writer').removeItem(key);
    },
    post(message: unknown) {
      const peer = hub.channel(`peer-${now()}-${hub.posted.length}`);
      peer.postMessage(message);
      peer.close();
    },
    kill(tab: PublicTab) {
      clock.freeze(tab.id);
      hub.close(tab.id);
      locks.kill(tab.id);
    },
    dispose() {
      for (const tab of tabs) close(tab);
    },
  };
  active.push(fixture);
  return fixture;
}

export type World = ReturnType<typeof world>;
export const errors = (tab: PublicTab): ErrorPayload[] => tab.of(PassflowEvent.Error);
export const ends = (tab: PublicTab) =>
  tab.events.filter((e) => e.event === PassflowEvent.SessionExpired || e.event === PassflowEvent.SignOut);
export function expectNoEnd(...tabs: PublicTab[]): void {
  for (const tab of tabs) expect(ends(tab)).toEqual([]);
}
export function expectClearAtEnd(tab: PublicTab): void {
  for (const e of ends(tab)) {
    expect(e.cached).toBeUndefined();
    expect(e.parsed).toBeUndefined();
  }
}
export function expectRefreshOrder(tab: PublicTab): void {
  for (let i = 0; i < tab.events.length; i += 1) {
    const record = tab.events[i]!;
    if (record.event !== PassflowEvent.Refresh) continue;
    const payload = record.payload as PassflowEventPayload[PassflowEvent.Refresh];
    expect(record.cached).toEqual(payload.tokens);
    expect(record.parsed).toEqual(payload.parsedTokens);
    expect(tab.events[i + 1]).toMatchObject({
      event: PassflowEvent.TokenCacheExpired,
      payload: { isExpired: false },
    });
  }
}
