// @vitest-environment node
// REQ-49 / REQ-94: C33/C35/T-S4a. Handler-entry snapshot is covered here;
// pre-dispatch authority on Passflow's internal axios path needs an HTTP integration fixture.
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { createAxiosUpgradeHandler } from '../../lib/upgrade/axios-adapter';
import { isInterceptionScope } from '../../lib/upgrade/core';
import { planReplay } from '../../lib/upgrade/replay';
import { createRequestSnapshot, normaliseUrl, snapshotHeader } from '../../lib/upgrade/snapshot';
import { base, challengeHeader, deferred, options } from './fetch-fixtures';
import { observed } from './pass2-fixtures';

beforeEach(() => {
  vi.stubGlobal('location', new URL(base));
  vi.stubGlobal('document', { baseURI: base });
  vi.stubGlobal('window', globalThis);
});
afterEach(() => vi.unstubAllGlobals());

test('REQ-49 REQ-94 C35 T-S4a ReplayPlan exposes a frozen snapshot detached from mutable URL/init/headers', async () => {
  const url = new URL('/api/original', base);
  const headers = new Headers({ authorization: 'Bearer old', 'x-caller': 'original' });
  const init: RequestInit = { method: 'POST', body: 'original-body', headers };
  const plan = planReplay(url, init);
  const snapshot = plan.snapshot;

  url.href = 'https://evil.example/changed';
  headers.set('x-caller', 'changed');
  headers.set('authorization', 'Bearer foreign');
  init.method = 'DELETE';
  init.body = 'changed-body';
  init.headers = { 'x-caller': 'replacement' };

  expect(snapshot.href).toBe('https://app.example/api/original');
  expect(snapshot.origin).toBe('https://app.example');
  expect(snapshot.method).toBe('POST');
  expect(snapshot.body).toBe('original-body');
  expect(snapshotHeader(snapshot, 'x-caller')).toBe('original');
  expect(snapshotHeader(snapshot, 'authorization')).toBe('Bearer old');
  expect(Object.isFrozen(snapshot)).toBe(true);
  // C33 requires a frozen snapshot detached from caller input, not recursive Object.freeze.
  // Header detachment is asserted above and through the observable replay below.
  expect(Reflect.set(snapshot, 'href', 'https://evil.example/')).toBe(false);
  const sent: Request[] = [];
  const reply = new Response('ok');
  expect(
    await plan.replay(async (input, requestInit) => {
      sent.push(new Request(input, requestInit));
      return reply;
    }),
  ).toBe(reply);
  expect(sent).toHaveLength(1);
  expect(sent[0].url).toBe(snapshot.href);
  expect(sent[0].method).toBe(snapshot.method);
  expect(sent[0].headers.get('x-caller')).toBe('original');
  expect(await sent[0].text()).toBe('original-body');
  expect(plan.snapshot).toBe(snapshot);
});

test('REQ-94 C33 T-S4a axios config mutations during proof cannot redirect replay, waiter context, scope or diagnostics', async () => {
  const proof = deferred<void>();
  const entered = deferred<void>();
  const config = {
    baseURL: 'https://app.example',
    url: '/api/original',
    method: 'post',
    data: 'original-body',
    headers: { authorization: 'Bearer old', 'x-caller': 'original' },
  };
  const scopeUrls: string[] = [];
  const waiters: unknown[] = [];
  const diagnostics: { url: string; reason: string }[] = [];
  const replays: { url?: string; baseURL?: string; method?: string; data?: unknown; headers?: unknown }[] = [];
  const original = {
    config,
    response: { status: 401, headers: { 'www-authenticate': challengeHeader }, data: { error: 'upgrade_required' } },
  };
  const handler = createAxiosUpgradeHandler(
    options({
      shouldIntercept: (url) => {
        scopeUrls.push(url);
        return true;
      },
      elevate: async (_challenge, waiter) => {
        waiters.push(waiter);
        entered.resolve();
        await proof.promise;
      },
      onUpgradeDiagnostic: (d) => {
        diagnostics.push(d);
      },
    }),
    async (replay) => {
      replays.push(replay);
      // Return a *second* challenge as axios does: reject the response.
      throw {
        config: replay,
        response: { status: 401, headers: { 'www-authenticate': challengeHeader }, data: { error: 'upgrade_required' } },
      };
    },
  );
  const result = observed(handler(original));
  await entered.promise;

  config.url = 'https://evil.example/changed';
  config.baseURL = 'https://evil.example';
  config.method = 'delete';
  config.data = 'changed-body';
  config.headers.authorization = 'Bearer foreign';
  config.headers['x-caller'] = 'changed';
  proof.resolve();

  expect(await result).toMatchObject({ ok: false, error: { code: 'upgrade_insufficient' } });
  expect(waiters).toEqual([{ kind: 'request', url: 'https://app.example/api/original', method: 'POST' }]);
  expect(scopeUrls.length).toBeGreaterThan(0);
  expect(scopeUrls.every((url) => url === 'https://app.example/api/original')).toBe(true);
  expect(replays).toHaveLength(1);
  expect(new URL(replays[0].url!, replays[0].baseURL).href).toBe('https://app.example/api/original');
  expect(replays[0].method?.toUpperCase()).toBe('POST');
  expect(replays[0].data).toBe('original-body');
  expect(new Headers(replays[0].headers as HeadersInit).get('x-caller')).toBe('original');
  expect(diagnostics).toContainEqual(
    expect.objectContaining({
      reason: 'elevated-insufficient',
      url: 'https://app.example/api/original',
    }),
  );
  expect(diagnostics.every((d) => d.url === 'https://app.example/api/original')).toBe(true);
});

// Directly tests the NEW declared pure snapshot/scope API, not pass-1's fetch tests.
const path = '/api/x';
const generated = Array.from({ length: 32 }, (_, code) => code)
  .concat(92)
  .flatMap((code) =>
    Array.from({ length: path.length + 1 }, (_, position) => ({
      code,
      position,
      raw: path.slice(0, position) + String.fromCharCode(code) + path.slice(position),
    })),
  );
test.each(generated)('REQ-95 T-S4b snapshot C0 property code=$code position=$position preserves platform origin', ({ raw }) => {
  const expected = new URL(raw, base);
  const snapshot = createRequestSnapshot({ url: raw, bodyKind: 'none', base });
  const scope = { passflow: { origin: 'https://app.example' }, backend: ['https://app.example'] };
  expect(normaliseUrl(raw, base)).toMatchObject({ href: expected.href, origin: expected.origin });
  expect(snapshot.href).toBe(expected.href);
  expect(snapshot.origin).toBe(expected.origin);
  expect(isInterceptionScope(snapshot, scope)).toBe(expected.origin === 'https://app.example');
  expect(Object.isFrozen(snapshot)).toBe(true);
});
