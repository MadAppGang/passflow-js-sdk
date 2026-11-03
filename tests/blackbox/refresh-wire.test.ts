import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { errors, expectNoEnd, expectRefreshOrder, observe, pair, successor, tokenMessage, world } from './public-fixture';

describe('documented refresh wire interoperability', () => {
  test('REQ-29 TEST-74 ignores malformed, unknown and own-tab messages then accepts a versionless successor', async () => {
    const w = world(() => 'hold', { watchStorage: false });
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    await w.ready();
    const next = successor(initial.refresh_token);
    const malformed: unknown[] = [
      null,
      undefined,
      17,
      'tokens-refreshed',
      [],
      {},
      { v: 1, tabId: 'peer', type: 'unknown-message' },
      { v: 1, tabId: 'peer', type: 'tokens-refreshed' },
      { v: 1, tabId: 'peer', type: 'tokens-refreshed', tokens: { refresh_token: 'not-a-JWT' } },
      tokenMessage(initial, next, { v: 2 }),
      tokenMessage(initial, next, { tabId: a.id }),
    ];
    for (const message of malformed) w.post(message);
    await w.run();
    expect(a.sdk.getCachedTokens()).toEqual(initial);
    expect(a.events).toEqual([]);
    expect(w.requests).toEqual([]);

    w.seed(next);
    const legacy: Record<string, unknown> = tokenMessage(initial, next);
    delete legacy.v;
    w.post(legacy);
    await w.run();
    expect(a.sdk.getCachedTokens()).toEqual(next);
    expect(a.of(PassflowEvent.Refresh)).toEqual([expect.objectContaining({ source: 'adopted', tokens: next })]);
    expect(a.of(PassflowEvent.RefreshStart)).toEqual([]);
    expect(errors(a)).toEqual([]);
    expectRefreshOrder(a);
    expectNoEnd(a);
  });

  test('REQ-2 REQ-29 TEST-74 a storage-only legacy adoption does not satisfy a later explicit fresh request', async () => {
    const w = world(() => 'hold', { watchStorage: false });
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    await w.ready();
    const adopted = successor(initial.refresh_token);
    w.seed(adopted);
    const legacy: Record<string, unknown> = tokenMessage(initial, adopted);
    delete legacy.v;
    w.post(legacy);
    await w.run();
    await w.run(10);
    const result = observe(a.sdk.refreshToken());
    await w.run();
    expect(w.requests.map((request) => request.token)).toEqual([adopted.refresh_token]);
    expect(result.status).toBe('pending');
    const issued = successor(adopted.refresh_token);
    w.requests[0]!.resolve(issued);
    await w.run();
    expect(result).toMatchObject({ status: 'resolved', value: issued });
    expectNoEnd(a);
  });
});
