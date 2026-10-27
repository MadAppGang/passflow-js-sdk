// @vitest-environment node
// Revision 5 is authoritative: NEVER assert the complement of recoverable errors.
import { expect, test, vi } from 'vitest';
import { UpgradeController } from '../../lib/upgrade/controller';
import { UpgradeErrorIds, UpgradeTransportError, invalidatesSessionOnCommit } from '../../lib/upgrade/errors';
import { createUpgradeTransport } from '../../lib/upgrade/transport';
import { createMockPlatform } from '../helpers/mock-platform';
import { challenge, observed, promptDriver } from './pass2-fixtures';

test.each([
  { id: UpgradeErrorIds.tokenInvalid, invalid: true },
  { id: UpgradeErrorIds.twoFactorNotEnabled, invalid: false },
  { id: 'error.qa.previously_unseen', invalid: false },
  { id: '', invalid: false },
])('REQ-74 REQ-75 REQ-91 REQ-92 C26b C26c T-S3 T-S3a commit 401 $id invalidates=$invalid', async ({ id, invalid }) => {
  let session: { sub: string; sid: string } | undefined = { sub: 'A', sid: 'session-A' };
  const live = session;
  const transport = createUpgradeTransport({
    canCommit: () => ({ ok: true }),
    startUpgrade: async () => {
      throw new Error('unused');
    },
    commitRefresh: async () => {
      throw { status: 401, id };
    },
    markSessionInvalid: () => {
      session = undefined;
    },
  });

  const result = await observed(transport.commit('totp', { code: '123456' }));

  // C26b/C26c specify the elevation outcome, not the direct transport's error tag.
  // The transport exposes classified UpgradeTransportError failures (errors.d.ts / T8–T9).
  expect(result).toMatchObject({
    ok: false,
    error: { code: 'upgrade_transport', status: 401, errorId: id, retryable: false },
  });
  expect(session).toBe(invalid ? undefined : live);
  expect(
    invalidatesSessionOnCommit(
      new UpgradeTransportError({
        kind: 'session_changed',
        status: 401,
        errorId: id,
      }),
    ),
  ).toBe(invalid);
});

test.each([UpgradeErrorIds.twoFactorCodeInvalid])(
  'REQ-40 REQ-89 C26 T-S1 recoverable commit %s preserves session and re-prompts retryably',
  async (id) => {
    const driver = promptDriver();
    const live = { sub: 'A', sid: 'session-A' };
    let session: typeof live | undefined = live;
    const summaries: unknown[] = [];
    const transport = createUpgradeTransport({
      canCommit: () => ({ ok: true }),
      startUpgrade: async () => {
        throw new Error('TOTP must not prepare');
      },
      commitRefresh: async () => {
        throw { status: 401, id };
      },
      markSessionInvalid: () => {
        session = undefined;
      },
    });
    const controller = new UpgradeController({
      platform: createMockPlatform(),
      transport,
      prompt: driver.prompt,
      onFlightSettled: (summary) => {
        summaries.push(summary);
      },
    });
    const result = observed(controller.elevate(challenge(), { kind: 'request', url: 'https://app.example/a', method: 'GET' }));
    await vi.waitFor(() => expect(driver.requests).toHaveLength(1));
    driver.select();
    driver.submit();
    await vi.waitFor(() => expect(driver.requests).toHaveLength(2));

    expect(driver.requests[1].previousError).toMatchObject({ kind: 'wrong_code', retryable: true });
    expect(session).toBe(live);
    expect(controller.currentState).toBe('collecting');
    expect(summaries).toEqual([]);
    driver.cancel(1);
    expect(await result).toMatchObject({ ok: false, error: { code: 'upgrade_cancelled' } });
    await vi.waitFor(() => expect(controller.active).toBe(false));
    expect(session).toBe(live);
  },
);

test.each([UpgradeErrorIds.twoFactorNotEnabled, 'error.qa.future', UpgradeErrorIds.tokenInvalid])(
  'REQ-74 REQ-75 REQ-91 REQ-92 terminal 401 %s clears the flight without a second prompt',
  async (id) => {
    const driver = promptDriver();
    let authenticated = true;
    const controller = new UpgradeController({
      platform: createMockPlatform(),
      prompt: driver.prompt,
      transport: createUpgradeTransport({
        canCommit: () => ({ ok: true }),
        startUpgrade: async () => {
          throw new Error('unexpected prepare');
        },
        commitRefresh: async () => {
          throw { status: 401, id };
        },
        markSessionInvalid: () => {
          authenticated = false;
        },
      }),
    });
    const result = observed(controller.elevate(challenge()));
    await vi.waitFor(() => expect(driver.requests).toHaveLength(1));
    driver.select();
    driver.submit();
    expect(await result).toMatchObject({ ok: false, error: { code: 'upgrade_session_changed' } });
    await vi.waitFor(() => expect(controller.active).toBe(false));
    expect(driver.requests).toHaveLength(1);
    expect(authenticated).toBe(id !== UpgradeErrorIds.tokenInvalid);
  },
);
