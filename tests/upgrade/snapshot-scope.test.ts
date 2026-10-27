// @vitest-environment node
// Coverage map: REQ-3 (FR3), REQ-13 (Policy-diagnostic), REQ-45 (C31), REQ-46 (C32), REQ-47 (C33), REQ-48 (C34), REQ-49 (C35), REQ-50 (C36), REQ-51 (C37), REQ-77 (SF-1), REQ-78 (SF-2), REQ-79 (SF-3), REQ-80 (SF-4), REQ-81 (SF-5), REQ-82 (SF-6), REQ-83 (SF-7), REQ-84 (SF-8), REQ-85 (SF-9), REQ-86 (SF-10), REQ-87 (SF-11), REQ-88 (SF-12), REQ-93 (T-S4), REQ-94 (T-S4a), REQ-95 (T-S4b)
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { UpgradeDiagnostic } from '../../lib/upgrade/challenge';
import { upgradeFetch } from '../../lib/upgrade/fetch-adapter';
import { base, challengeResponse, deferred, options, scopeFixtures } from './fetch-fixtures';

beforeEach(() => {
  vi.stubGlobal('location', new URL(base));
  vi.stubGlobal('document', { baseURI: base });
  vi.stubGlobal('window', globalThis);
});
afterEach(() => vi.unstubAllGlobals());

describe('request snapshot scope', () => {
  test.each(scopeFixtures)(
    'REQ-C31 REQ-C32 T-S4 $id is $inside in scope after platform resolution',
    async ({ input, inside }) => {
      const original = challengeResponse();
      // A poisoned clone makes the contract's "never clone/read out of scope" observable:
      // the default parser would produce a body challenge if this boundary were crossed.
      let cloneReads = 0;
      if (!inside)
        Object.defineProperty(original, 'clone', {
          value: () => {
            cloneReads++;
            throw new Error('out-of-scope body cloned');
          },
        });
      const exchanges: string[] = [];
      const diagnostics: UpgradeDiagnostic[] = [];
      let prompts = 0;
      const wrapped = upgradeFetch(
        async (url) => {
          exchanges.push(String(url instanceof Request ? url.url : url));
          return exchanges.length === 1 ? original : new Response('ok');
        },
        options({
          elevate: async () => {
            prompts++;
          },
          onUpgradeDiagnostic: (d) => diagnostics.push(d),
        }),
      );

      const result = await wrapped(input);
      const normalized = new URL(input, base);
      expect(normalized.origin === 'https://app.example').toBe(inside);
      expect(prompts).toBe(inside ? 1 : 0);
      expect(exchanges).toHaveLength(inside ? 2 : 1);
      expect(original.bodyUsed).toBe(false);
      if (inside) {
        expect(result.status).toBe(200);
        expect(new URL(exchanges[1]!, base).href).toBe(normalized.href);
      } else {
        expect(result).toBe(original);
        expect(cloneReads).toBe(0);
        expect(diagnostics).toEqual([
          expect.objectContaining({
            reason: 'challenge-out-of-scope',
            url: normalized.href,
          }),
        ]);
        expect(await result.json()).toEqual({ error: 'upgrade_required', acr_values: '2' });
      }
    },
  );

  // Exhaustive finite property: 33 characters × 7 positions = 231 inputs.
  const path = '/api/x';
  const controls = Array.from({ length: 32 }, (_, i) => i).concat(92);
  const cases = controls.flatMap((code) =>
    Array.from({ length: path.length + 1 }, (_, position) => ({
      code,
      position,
      input: path.slice(0, position) + String.fromCharCode(code) + path.slice(position),
    })),
  );
  test.each(cases)(
    'REQ-C37 T-S4b code=$code position=$position agrees with URL.origin, never a character blacklist',
    async ({ input }) => {
      let prompts = 0;
      let dispatches = 0;
      const wrapped = upgradeFetch(
        async () => (++dispatches === 1 ? challengeResponse() : new Response('ok')),
        options({
          elevate: async () => {
            prompts++;
          },
        }),
      );
      const result = await wrapped(input);
      const inside = new URL(input, base).origin === 'https://app.example';
      expect(prompts).toBe(inside ? 1 : 0);
      expect(dispatches).toBe(inside ? 2 : 1);
      expect(result.status).toBe(inside ? 200 : 401);
    },
  );

  test('REQ-C33 REQ-C34 REQ-C35 REQ-C36 T-S4a URL and init mutations during proof cannot redirect replay', async () => {
    const entered = deferred<void>();
    const proof = deferred<void>();
    const url = new URL('/api/x', base);
    const init: RequestInit = { method: 'POST', body: 'original-body', headers: { Authorization: 'Bearer original' } };
    const sent: { url: string; method: string; body: string; auth: string | null }[] = [];
    const diagnostics: UpgradeDiagnostic[] = [];
    let waiter: unknown;
    const wrapped = upgradeFetch(
      async (input, requestInit) => {
        const request = new Request(input, requestInit);
        sent.push({
          url: request.url,
          method: request.method,
          body: await request.text(),
          auth: request.headers.get('authorization'),
        });
        return challengeResponse();
      },
      options({
        elevate: async (_, context) => {
          waiter = context;
          entered.resolve();
          await proof.promise;
        },
        onUpgradeDiagnostic: (d) => diagnostics.push(d),
      }),
    );
    const pending = wrapped(url, init);
    await entered.promise;
    url.href = 'https://evil.example/stolen';
    init.method = 'DELETE';
    init.body = 'tampered-body';
    (init.headers as Record<string, string>).Authorization = 'Bearer tampered';
    proof.resolve();
    const result = await pending;

    expect(sent).toEqual([
      { url: 'https://app.example/api/x', method: 'POST', body: 'original-body', auth: 'Bearer original' },
      { url: 'https://app.example/api/x', method: 'POST', body: 'original-body', auth: 'Bearer original' },
    ]);
    expect(waiter).toMatchObject({ kind: 'request', url: 'https://app.example/api/x', method: 'POST' });
    expect(result.status).toBe(401);
    expect(diagnostics.filter((d) => d.reason === 'elevated-insufficient')).toEqual([
      expect.objectContaining({ url: 'https://app.example/api/x' }),
    ]);
  });

  test('REQ-C34 T-S4a URL mutation before the challenged response arrives cannot change challenge-time authority', async () => {
    const dispatched = deferred<void>();
    const response = deferred<Response>();
    const url = new URL('/api/x', base);
    const seen: string[] = [];
    let prompts = 0;
    const wrapped = upgradeFetch(
      async (input) => {
        seen.push(String(input instanceof Request ? input.url : input));
        if (seen.length === 1) {
          dispatched.resolve();
          return response.promise;
        }
        return new Response('ok');
      },
      options({
        elevate: async () => {
          prompts++;
        },
      }),
    );
    const pending = wrapped(url);
    await dispatched.promise;
    url.href = 'https://evil.example/x';
    response.resolve(challengeResponse());
    expect((await pending).status).toBe(200);
    expect(prompts).toBe(1);
    expect(new URL(seen[1]!, base).href).toBe('https://app.example/api/x');
  });
});
