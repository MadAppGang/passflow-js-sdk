// @vitest-environment node
// Coverage map: REQ-2 (FR2), REQ-3 (FR3), REQ-10 (NFR-cancel), REQ-13 (Policy-diagnostic), REQ-14 (Policy-replay), REQ-15 (C1), REQ-16 (C2), REQ-17 (C3), REQ-18 (C4), REQ-19 (C5), REQ-20 (C6), REQ-21 (C7), REQ-22 (C8), REQ-23 (C9), REQ-24 (C10), REQ-25 (C11), REQ-26 (C12), REQ-27 (C13), REQ-29 (C15), REQ-30 (C16), REQ-37 (C23), REQ-38 (C24), REQ-39 (C25), REQ-42 (C28), REQ-58 (C9b), REQ-71 (C25a), REQ-76 (C27a)
import { describe, expect, test } from 'vitest';
import { isUpgradeCancelled, isUpgradeInsufficient } from '../../lib/index';
import type { UpgradeChallenge, UpgradeDiagnostic } from '../../lib/upgrade/challenge';
import { UpgradeCancelledError } from '../../lib/upgrade/controller';
import { upgradeFetch } from '../../lib/upgrade/fetch-adapter';
import { challengeHeader, challengeResponse, deferred, options } from './fetch-fixtures';

const url = 'https://app.example/api/x';

describe('fetch surface observable behaviour', () => {
  test.each([
    ['C1', 200, {}],
    ['C2', 401, {}],
    ['C3', 401, { 'www-authenticate': 'Bearer' }],
  ])('REQ-%s returns the same unread non-challenge Response', async (_, status, headers) => {
    const original = new Response('{"error":"unauthorized"}', {
      status,
      headers: { ...headers, 'content-type': 'application/json' },
    });
    let prompts = 0;
    let dispatches = 0;
    const wrapped = upgradeFetch(
      async () => {
        dispatches++;
        return original;
      },
      options({
        elevate: async () => {
          prompts++;
        },
      }),
    );
    const result = await wrapped(url);
    expect(result).toBe(original);
    expect(result.bodyUsed).toBe(false);
    expect(prompts).toBe(0);
    expect(dispatches).toBe(1);
    expect(await result.json()).toEqual({ error: 'unauthorized' });
  });

  test.each([
    ['C4', 401, false],
    ['C5', 403, true],
  ] as const)('REQ-%s accepts the challenge, replays, and leaves the original body readable', async (_, status, bodyOnly) => {
    const original = bodyOnly
      ? new Response('{"error":"upgrade_required","acr_values":"2"}', {
          status,
          headers: { 'content-type': 'application/json' },
        })
      : challengeResponse(status);
    const success = new Response('result');
    let dispatches = 0;
    const challenges: UpgradeChallenge[] = [];
    const wrapped = upgradeFetch(
      async () => (++dispatches === 1 ? original : success),
      options({
        elevate: async (c) => {
          challenges.push(c);
        },
      }),
    );
    expect(await wrapped(url)).toBe(success);
    expect(challenges).toEqual([expect.objectContaining({ status, acrValues: '2', requiredLevel: 2 })]);
    expect(original.bodyUsed).toBe(false);
  });

  test.each(['init', 'Request'] as const)('REQ-C6 REQ-C11 replays captured POST %s body exactly once', async (kind) => {
    const wire: { url: string; method: string; body: string }[] = [];
    const wrapped = upgradeFetch(async (input, init) => {
      const request = new Request(input, init);
      wire.push({ url: request.url, method: request.method, body: await request.text() });
      return wire.length === 1 ? challengeResponse() : new Response('created', { status: 201 });
    }, options());
    const init = { method: 'POST', body: 'amount=25' };
    const result = kind === 'Request' ? await wrapped(new Request(url, init)) : await wrapped(url, init);
    expect(result.status).toBe(201);
    expect(wire).toEqual(Array.from({ length: 2 }, () => ({ url, method: 'POST', body: 'amount=25' })));
  });

  test('REQ-C7 REQ-C24 second challenge is insufficient, never a third dispatch or second elevation', async () => {
    const first = challengeResponse();
    const second = challengeResponse(403, 'Bearer error="insufficient_user_authentication", acr_values="3"');
    let dispatches = 0;
    let prompts = 0;
    const diagnostics: UpgradeDiagnostic[] = [];
    const wrapped = upgradeFetch(
      async () => (++dispatches === 1 ? first : second),
      options({
        elevate: async () => {
          prompts++;
        },
        onUpgradeDiagnostic: (d) => diagnostics.push(d),
      }),
    );
    const result = await wrapped(url);
    expect(result).toBe(second);
    expect(isUpgradeInsufficient(result)).toBe(true);
    expect(result.bodyUsed).toBe(false);
    expect(prompts).toBe(1);
    expect(dispatches).toBe(2);
    expect(diagnostics.filter((d) => d.reason === 'elevated-insufficient')).toEqual([
      expect.objectContaining({ url, detail: expect.objectContaining({ required: expect.objectContaining({ level: 3 }) }) }),
    ]);
  });

  test('REQ-C8 cancellation resolves the identical original denied Response, tagged only by identity', async () => {
    const original = challengeResponse();
    let dispatches = 0;
    const wrapped = upgradeFetch(
      async () => {
        dispatches++;
        return original;
      },
      options({
        elevate: async () => {
          throw new UpgradeCancelledError();
        },
      }),
    );
    const result = await wrapped(url);
    expect(result).toBe(original);
    expect(result.ok).toBe(false);
    expect(result.bodyUsed).toBe(false);
    expect(isUpgradeCancelled(result)).toBe(true);
    expect(isUpgradeCancelled(result.clone())).toBe(false);
    expect(dispatches).toBe(1);
    expect(await result.json()).toMatchObject({ error: 'upgrade_required' });
  });

  test('REQ-C9 reject opt-out exposes the literal cancellation discriminant', async () => {
    const wrapped = upgradeFetch(
      async () => challengeResponse(),
      options({
        onCancel: 'reject',
        elevate: async () => {
          throw new UpgradeCancelledError();
        },
      }),
    );
    await expect(wrapped(url)).rejects.toMatchObject({ code: 'upgrade_cancelled' });
  });

  test('REQ-C9b calling again after cancel starts a fresh attempt without a cancelled-request replay', async () => {
    let dispatches = 0;
    let prompts = 0;
    const wrapped = upgradeFetch(
      async () => {
        dispatches++;
        return challengeResponse();
      },
      options({
        elevate: async () => {
          prompts++;
          throw new UpgradeCancelledError();
        },
      }),
    );
    expect(isUpgradeCancelled(await wrapped(url))).toBe(true);
    expect(dispatches).toBe(1);
    expect(isUpgradeCancelled(await wrapped(url))).toBe(true);
    expect(prompts).toBe(2);
    expect(dispatches).toBe(2);
  });

  test('REQ-C10 streaming init body is returned denied without any prompt or replay', async () => {
    const original = challengeResponse();
    let prompts = 0;
    let dispatches = 0;
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('x'));
        controller.close();
      },
    });
    const wrapped = upgradeFetch(
      async () => {
        dispatches++;
        return original;
      },
      options({
        elevate: async () => {
          prompts++;
        },
      }),
    );
    const result = await wrapped(url, { method: 'POST', body: stream });
    expect(result).toBe(original);
    expect(prompts).toBe(0);
    expect(dispatches).toBe(1);
    expect(result.bodyUsed).toBe(false);
  });

  test('REQ-C12 abort while proof is pending rejects with the signal reason, never replays', async () => {
    const entered = deferred<void>();
    const proof = deferred<void>();
    const controller = new AbortController();
    const reason = new Error('caller aborted');
    let dispatches = 0;
    const wrapped = upgradeFetch(
      async () => {
        dispatches++;
        return challengeResponse();
      },
      options({
        elevate: async () => {
          entered.resolve();
          await proof.promise;
        },
      }),
    );
    const pending = wrapped(url, { signal: controller.signal });
    const rejection = expect(pending).rejects.toBe(reason);
    await entered.promise;
    controller.abort(reason);
    await rejection;
    proof.resolve();
    await Promise.resolve();
    expect(dispatches).toBe(1);
  });

  test('REQ-C13 narrowing callback excludes an admitted URL', async () => {
    let prompts = 0;
    const original = challengeResponse();
    const wrapped = upgradeFetch(
      async () => original,
      options({
        shouldIntercept: () => false,
        elevate: async () => {
          prompts++;
        },
      }),
    );
    expect(await wrapped(url)).toBe(original);
    expect(prompts).toBe(0);
  });

  test.each([
    ['C15', 'Bearer old', 'Bearer new'],
    ['C16', 'Bearer someone-elses', 'Bearer someone-elses'],
  ])('REQ-%s replaces only the credential owned by this session', async (_, credential, expected) => {
    const auth: (string | null)[] = [];
    const wrapped = upgradeFetch(
      async (input, init) => {
        auth.push(new Request(input, init).headers.get('authorization'));
        return auth.length === 1 ? challengeResponse() : new Response('ok');
      },
      options({ authorizationSwap: () => ({ from: 'Bearer old', to: 'Bearer new' }) }),
    );
    expect((await wrapped(url, { headers: { authorization: credential } })).status).toBe(200);
    expect(auth).toEqual([credential, expected]);
  });

  test('REQ-C23 strict header mode does not read a body-only challenge and explains why it passed through', async () => {
    const original = new Response('{"error":"upgrade_required"}', {
      status: 403,
      headers: { 'content-type': 'application/json' },
    });
    let reads = 0;
    const clone = original.clone.bind(original);
    Object.defineProperty(original, 'clone', {
      value: () => {
        reads++;
        return clone();
      },
    });
    const diagnostics: UpgradeDiagnostic[] = [];
    let prompts = 0;
    const wrapped = upgradeFetch(
      async () => original,
      options({
        requireChallengeChannel: 'header',
        elevate: async () => {
          prompts++;
        },
        onUpgradeDiagnostic: (d) => diagnostics.push(d),
      }),
    );
    expect(await wrapped(url)).toBe(original);
    expect(reads).toBe(0);
    expect(prompts).toBe(0);
    expect(diagnostics).toEqual([expect.objectContaining({ reason: 'header-required-but-absent', url })]);
  });

  test.each([
    ['C25', { passflow: { origin: 'https://auth.example' }, backend: [] }, false],
    ['C25a', { passflow: { origin: 'https://auth.example' }, backend: ['https://app.example'] }, true],
    ['C27a', { passflow: { origin: 'https://app.example' }, backend: [] }, true],
    ['C28', { passflow: null, backend: [] }, false],
  ] as const)(
    'REQ-%s scope uses the two explicit domains, even when shouldIntercept returns true',
    async (_, scope, admitted) => {
      let prompts = 0;
      let dispatches = 0;
      let reads = 0;
      const original = challengeResponse();
      const clone = original.clone.bind(original);
      Object.defineProperty(original, 'clone', {
        value: () => {
          reads++;
          return clone();
        },
      });
      const diagnostics: UpgradeDiagnostic[] = [];
      const wrapped = upgradeFetch(
        async () => (++dispatches === 1 ? original : new Response('ok')),
        options({
          scope: { passflow: scope.passflow, backend: [...scope.backend] },
          shouldIntercept: () => true,
          elevate: async () => {
            prompts++;
          },
          onUpgradeDiagnostic: (d) => diagnostics.push(d),
        }),
      );
      const result = await wrapped(url);
      expect(prompts).toBe(admitted ? 1 : 0);
      expect(dispatches).toBe(admitted ? 2 : 1);
      if (!admitted) {
        expect(result).toBe(original);
        expect(reads).toBe(0);
        expect(diagnostics).toEqual([expect.objectContaining({ reason: 'challenge-out-of-scope', url })]);
      } else expect(result.status).toBe(200);
    },
  );

  test('REQ-C19 JSON header hit still reads the stronger body on a clone', async () => {
    const original = new Response('{"error":"upgrade_required","acr_values":"3"}', {
      status: 401,
      headers: { 'content-type': 'application/json', 'www-authenticate': challengeHeader },
    });
    const seen: UpgradeChallenge[] = [];
    let count = 0;
    const wrapped = upgradeFetch(
      async () => (++count === 1 ? original : new Response('ok')),
      options({
        elevate: async (c) => {
          seen.push(c);
        },
      }),
    );
    expect((await wrapped(url)).status).toBe(200);
    expect(seen).toEqual([expect.objectContaining({ requiredLevel: 3, acrValues: '3' })]);
    expect(original.bodyUsed).toBe(false);
  });
});
