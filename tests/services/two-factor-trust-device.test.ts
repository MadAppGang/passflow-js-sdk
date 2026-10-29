/**
 * TwoFactorService: `trustDevice`, the pending 2FA token on the v2 calls, and
 * trusted-device management.
 */
import { Mock, beforeEach, describe, expect, test, vi } from 'vitest';
import { TwoFactorApiClient } from '../../lib/api/two-factor';
import { TwoFactorService } from '../../lib/services/two-factor-service';
import { PassflowEvent, PassflowStore } from '../../lib/store';
import { VALID_TOKENS } from '../helpers/fixtures';

const TFA_TOKEN = 'tfa.jwt.token';

describe('TwoFactorService — device trust', () => {
  let api: Record<string, Mock>;
  let store: PassflowStore;
  let service: TwoFactorService;

  beforeEach(() => {
    sessionStorage.clear();
    api = {
      verify: vi.fn().mockResolvedValue({ success: true, ...VALID_TOKENS }),
      useRecoveryCode: vi.fn().mockResolvedValue({ success: true, remaining_recovery_codes: 5, ...VALID_TOKENS }),
      verifyV2: vi.fn().mockResolvedValue({ success: true, ...VALID_TOKENS }),
      requestChallenge: vi.fn().mockResolvedValue({ challenge_id: 'c', method: 'totp', alternative_methods: [] }),
      getTrustedDevices: vi.fn(),
      revokeTrustedDevice: vi.fn(),
    };
    store = new PassflowStore();
    service = new TwoFactorService(api as unknown as TwoFactorApiClient, store);
    store.notify(PassflowEvent.TwoFactorRequired, { email: '', challengeId: '', tfaToken: TFA_TOKEN });
  });

  test('verify sends trust_device only with trustDevice: true', async () => {
    await service.verify('123456');
    store.notify(PassflowEvent.TwoFactorRequired, { email: '', challengeId: '', tfaToken: TFA_TOKEN });
    await service.verify('123456', { trustDevice: false });
    store.notify(PassflowEvent.TwoFactorRequired, { email: '', challengeId: '', tfaToken: TFA_TOKEN });
    await service.verify('123456', { trustDevice: true });

    expect(api.verify.mock.calls[0][0]).not.toHaveProperty('trust_device');
    expect(api.verify.mock.calls[1][0]).not.toHaveProperty('trust_device');
    expect(api.verify.mock.calls[2][0]).toEqual({ code: '123456', tfa_token: TFA_TOKEN, trust_device: true });
  });

  test('useRecoveryCode sends trust_device only with trustDevice: true', async () => {
    await service.useRecoveryCode('ABCD-1234');
    store.notify(PassflowEvent.TwoFactorRequired, { email: '', challengeId: '', tfaToken: TFA_TOKEN });
    await service.useRecoveryCode('ABCD-1234', { trustDevice: true });

    expect(api.useRecoveryCode.mock.calls[0][0]).not.toHaveProperty('trust_device');
    expect(api.useRecoveryCode.mock.calls[1][0]).toMatchObject({ tfa_token: TFA_TOKEN, trust_device: true });
  });

  test('the v2 challenge calls carry the pending 2FA token', async () => {
    await service.requestChallenge({});
    await service.verifyV2({ challenge_id: 'c', method: 'totp', response: '123456', trust_device: true });

    expect(api.requestChallenge).toHaveBeenCalledWith({}, TFA_TOKEN);
    expect(api.verifyV2).toHaveBeenCalledWith(expect.objectContaining({ trust_device: true }), TFA_TOKEN);
    // The sign-in is over: nothing is left waiting on a second factor.
    expect(service.isVerificationRequired()).toBe(false);
  });

  test('getTrustedDevices returns the typed list', async () => {
    const devices = [{ id: 'd1', created_at: 'a', expires_at: 'b', current: false }];
    api.getTrustedDevices.mockResolvedValueOnce(devices);

    await expect(service.getTrustedDevices()).resolves.toEqual(devices);
  });

  test('revokeTrustedDevice revokes by id and surfaces a failure as an Error event', async () => {
    const errors: unknown[] = [];
    store.subscribe({ onAuthChange: (_e, payload) => errors.push(payload) }, [PassflowEvent.Error]);

    await service.revokeTrustedDevice('d1');
    expect(api.revokeTrustedDevice).toHaveBeenCalledWith('d1');

    api.revokeTrustedDevice.mockRejectedValueOnce(Object.assign(new Error('not found'), { id: 'error.http.404' }));
    await expect(service.revokeTrustedDevice('nope')).rejects.toThrow('not found');
    expect(errors).toHaveLength(1);
  });
});
