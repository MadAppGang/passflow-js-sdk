// @vitest-environment node
// REQ-41 C27: shared suite over the declared adapter constructors and internal-seam factory.
// This does NOT claim Passflow's internal AxiosClient session-invalidating interceptor is tested.
import axios, { AxiosError, AxiosHeaders, type AxiosAdapter, type AxiosRequestConfig } from 'axios';
import { describe, expect, test } from 'vitest';
import { createUpgradeClient } from '../../lib/upgrade/client';
import {
  isUpgradeCancelled,
  isUpgradeExhausted,
  isUpgradeInsufficient,
  isUpgradeSessionChanged,
  isUpgradeTransportFailure,
  isUpgradeUnavailable,
  isUpgradeUnsatisfiable,
} from '../../lib/upgrade/core';
import { UpgradeSessionChangedError } from '../../lib/upgrade/errors';
import { createUpgradeFacade } from '../../lib/upgrade/facade';
import type { UpgradeFacadeDeps } from '../../lib/upgrade/facade';
import { createMockPlatform } from '../helpers/mock-platform';
import { challengeHeader, challengeResponse } from './fetch-fixtures';
import { observed } from './pass2-fixtures';

const adapters = ['withAuth', 'attachAuth', 'createClient', 'internal-seam'] as const;
type Adapter = (typeof adapters)[number];
const cases = [
  { name: 'success', predicate: undefined, code: undefined, replay: true },
  { name: 'cancelled', predicate: isUpgradeCancelled, code: 'upgrade_cancelled', replay: false },
  { name: 'exhausted', predicate: isUpgradeExhausted, code: 'upgrade_transport', replay: false },
  { name: 'unsatisfiable', predicate: isUpgradeUnsatisfiable, code: 'upgrade_unsatisfiable', replay: false },
  { name: 'insufficient', predicate: isUpgradeInsufficient, code: 'upgrade_insufficient', replay: true },
  { name: 'unavailable', predicate: isUpgradeUnavailable, code: 'upgrade_unavailable', replay: false },
  { name: 'transport', predicate: isUpgradeTransportFailure, code: 'upgrade_transport', replay: false },
  { name: 'session-changed', predicate: isUpgradeSessionChanged, code: 'upgrade_session_changed', replay: false },
] as const;

function harness(adapter: Adapter, outcome: string, backend: string[] = ['https://app.example']) {
  let prompts = 0;
  let commits = 0;
  let applicationAuthenticated = true;
  const exchanges: { url: string; method: string; data: unknown }[] = [];
  const diagnostics: { reason: string; url: string }[] = [];
  let seamFactory: Parameters<NonNullable<UpgradeFacadeDeps['attachInternalSeam']>>[0];
  const facade = createUpgradeFacade({
    platform: createMockPlatform(),
    passflowDomain: { origin: 'https://auth.example' },
    attachInternalSeam: (factory) => {
      seamFactory = factory;
    },
    canCommit: () => (outcome === 'unavailable' ? { ok: false, reason: 'BFF' } : { ok: true }),
    startUpgrade: async () => {
      throw new Error('TOTP must not prepare');
    },
    commitRefresh: async () => {
      commits++;
      if (outcome === 'exhausted') throw { status: 401, id: 'error.upgrade.challenge_too_many_attempts' };
      if (outcome === 'transport') throw { status: 400, id: 'error.upgrade.unsupported_factor' };
      if (outcome === 'session-changed') throw new UpgradeSessionChangedError();
    },
    readObtainedBar: () => ({ level: 2, acrValues: '2' }),
    markSessionInvalid: () => {
      applicationAuthenticated = false;
    },
  });
  const disable = facade.enable({
    backend,
    interceptFetch: false,
    maxAttempts: 1,
    ...(outcome === 'unsatisfiable' ? { factors: [] } : {}),
    onUpgradeDiagnostic: (d) => {
      diagnostics.push(d);
    },
    prompt: async (request) => {
      prompts++;
      if (outcome === 'cancelled') return { type: 'cancel' };
      request.onFactorSelected('totp');
      return { type: 'submit', factor: 'totp', code: '123456' };
    },
  });
  const originalFetch = challengeResponse();
  const replayFetch = outcome === 'insufficient' ? challengeResponse() : new Response('protected-result');
  const wire: AxiosAdapter = async (config) => {
    exchanges.push({ url: new URL(config.url!, config.baseURL).href, method: config.method!, data: config.data });
    const replay = exchanges.length > 1;
    const status = replay && outcome !== 'insufficient' ? 200 : 401;
    const response = {
      config,
      status,
      statusText: status === 200 ? 'OK' : 'Unauthorized',
      data: status === 200 ? 'protected-result' : { error: 'upgrade_required', acr_values: '2' },
      headers: status === 200 ? {} : { 'www-authenticate': challengeHeader, 'content-type': 'application/json' },
    };
    if (status >= 400) throw new AxiosError('denied', 'ERR_BAD_REQUEST', config, undefined, response);
    return response;
  };
  let detach = () => {};
  let invoke: (url: string) => Promise<unknown>;
  if (adapter === 'withAuth') {
    const wrapped = facade.withAuth(async (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      exchanges.push({ url, method: init?.method ?? 'GET', data: init?.body });
      return exchanges.length === 1 ? originalFetch : replayFetch;
    });
    invoke = (url) => wrapped(url);
  } else if (adapter === 'internal-seam') {
    // Drive the exact documented registration edge, including re-entry on replay errors.
    const dispatch = async (config: AxiosRequestConfig): Promise<unknown> => {
      try {
        return await wire({
          ...config,
          headers: AxiosHeaders.from(config.headers as never),
        } as Parameters<AxiosAdapter>[0]);
      } catch (error) {
        if (!seamFactory) throw error;
        return seamFactory(dispatch)(error);
      }
    };
    invoke = (url) => dispatch({ url, method: 'GET' });
  } else {
    const client =
      adapter === 'createClient'
        ? createUpgradeClient({ adapter: wire }, (host) => facade.attachAuth(host))
        : axios.create({ adapter: wire });
    if (adapter === 'attachAuth') detach = facade.attachAuth(client);
    invoke = (url) => client.get(url);
  }
  return {
    invoke,
    exchanges,
    diagnostics,
    originalFetch,
    replayFetch,
    prompts: () => prompts,
    commits: () => commits,
    authenticated: () => applicationAuthenticated,
    close: () => {
      detach();
      disable();
    },
  };
}

for (const adapter of adapters)
  describe('REQ-41 C27 shared settlement suite: ' + adapter, () => {
    test.each(cases)('$name settles on ' + adapter + ' without hidden replay or false success', async (row) => {
      const h = harness(adapter, row.name);
      try {
        const result = await observed(h.invoke('https://app.example/private'));
        if (adapter === 'withAuth') {
          expect(result.ok).toBe(true);
          if (!result.ok) throw result.error;
          const response = result.value as Response;
          expect(response).toBe(row.replay ? h.replayFetch : h.originalFetch);
          expect(response.status).toBe(row.name === 'success' ? 200 : 401);
          expect(response.bodyUsed).toBe(false);
          if (row.predicate) {
            expect(row.predicate(response)).toBe(true);
            expect(row.predicate(response.clone())).toBe(false);
          }
        } else if (row.name === 'success') {
          expect(result).toMatchObject({ ok: true, value: { status: 200, data: 'protected-result' } });
        } else {
          expect(result).toMatchObject({ ok: false, error: { code: row.code } });
          if (!result.ok && row.name === 'transport') expect(result.error.retryable).toBe(false);
          if (!result.ok && row.name === 'insufficient')
            expect(result.error).toMatchObject({
              obtained: { level: 2 },
              required: { level: 2 },
            });
        }
        expect(h.exchanges).toHaveLength(row.replay ? 2 : 1);
        expect(h.prompts()).toBe(row.name === 'unsatisfiable' ? 0 : 1);
        expect(h.commits()).toBe(['cancelled', 'unsatisfiable', 'unavailable'].includes(row.name) ? 0 : 1);
        expect(h.authenticated()).toBe(true);
      } finally {
        h.close();
      }
    });
  });

const scopeCases = [
  { url: 'https://auth.example/private', backend: [], inside: true },
  { url: 'https://app.example/private', backend: [], inside: false },
  { url: 'https://app.example/private', backend: ['https://app.example'], inside: true },
  { url: 'https://evil.example/private', backend: ['https://app.example'], inside: false },
];
for (const adapter of adapters)
  test.each(scopeCases)(
    'REQ-76 C27a ' + adapter + ' scope $url backend=$backend admits=$inside',
    async ({ url, backend, inside }) => {
      const h = harness(adapter, 'cancelled', backend);
      try {
        const result = await observed(h.invoke(url));
        expect(h.prompts()).toBe(inside ? 1 : 0);
        expect(h.commits()).toBe(0);
        expect(h.exchanges).toHaveLength(1);
        if (inside && adapter !== 'withAuth') {
          expect(result).toMatchObject({ ok: false, error: { code: 'upgrade_cancelled' } });
        }
        if (!inside) {
          expect(h.diagnostics).toEqual([expect.objectContaining({ reason: 'challenge-out-of-scope', url })]);
        }
      } finally {
        h.close();
      }
    },
  );
