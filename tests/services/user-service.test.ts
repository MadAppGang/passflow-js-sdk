import { describe, test, expect, beforeEach, vi, Mock } from 'vitest';
import { UserService } from '../../lib/services/user-service';
import { UserAPI, OS, PassflowSuccessResponse } from '../../lib/api';
import { DeviceService } from '../../lib/device-service';

// Mock dependencies
vi.mock('../../lib/api/user');
vi.mock('../../lib/device-service');
vi.mock('@simplewebauthn/browser', () => ({
  startRegistration: vi.fn().mockResolvedValue({ id: 'reg-id' }),
}));

describe('UserService', () => {
  // Setup for all tests
  let userService: UserService;
  let mockUserApi: {
    getUserPasskeys: Mock;
    renameUserPasskey: Mock;
    deleteUserPasskey: Mock;
    addUserPasskeyStart: Mock;
    addUserPasskeyComplete: Mock;
  };
  let mockDeviceService: {
    getDeviceId: Mock;
  };

  const mockDeviceId = 'test-device-id';
  const mockPasskeyId = 'test-passkey-id';
  const mockPasskeyName = 'My Passkey';

  const mockPasskeys = [
    { id: 'passkey-1', name: 'Passkey 1', created_at: '2023-01-01' },
    { id: 'passkey-2', name: 'Passkey 2', created_at: '2023-01-02' },
  ];

  const mockSuccessResponse: PassflowSuccessResponse = {
    result: 'ok',
  };

  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();

    // Create mock instances
    mockUserApi = {
      getUserPasskeys: vi.fn().mockResolvedValue(mockPasskeys),
      renameUserPasskey: vi.fn().mockResolvedValue(mockSuccessResponse),
      deleteUserPasskey: vi.fn().mockResolvedValue(mockSuccessResponse),
      addUserPasskeyStart: vi.fn().mockResolvedValue({
        challenge_id: 'challenge-123',
        publicKey: { user: { id: 'user-id' } },
      }),
      addUserPasskeyComplete: vi.fn().mockResolvedValue(mockSuccessResponse),
    };

    mockDeviceService = {
      getDeviceId: vi.fn().mockReturnValue(mockDeviceId),
    };

    // Create UserService instance
    userService = new UserService(mockUserApi as unknown as UserAPI, mockDeviceService as unknown as DeviceService);
  });

  describe('getUserPasskeys', () => {
    test('should call UserAPI getUserPasskeys', async () => {
      const passkeys = await userService.getUserPasskeys();

      expect(mockUserApi.getUserPasskeys).toHaveBeenCalled();
      expect(passkeys).toEqual(mockPasskeys);
    });
  });

  describe('renameUserPasskey', () => {
    test('should call UserAPI renameUserPasskey with correct parameters', async () => {
      await userService.renameUserPasskey(mockPasskeyName, mockPasskeyId);

      expect(mockUserApi.renameUserPasskey).toHaveBeenCalledWith(mockPasskeyName, mockPasskeyId);
    });

    test('should return success response', async () => {
      const response = await userService.renameUserPasskey(mockPasskeyName, mockPasskeyId);

      expect(response).toEqual(mockSuccessResponse);
    });
  });

  describe('deleteUserPasskey', () => {
    test('should call UserAPI deleteUserPasskey with correct parameters', async () => {
      await userService.deleteUserPasskey(mockPasskeyId);

      expect(mockUserApi.deleteUserPasskey).toHaveBeenCalledWith(mockPasskeyId);
    });

    test('should return success response', async () => {
      const response = await userService.deleteUserPasskey(mockPasskeyId);

      expect(response).toEqual(mockSuccessResponse);
    });
  });

  describe('addUserPasskey', () => {
    test('should call UserAPI addUserPasskeyStart with correct parameters', async () => {
      const options = {
        relyingPartyId: 'example.com',
        passkeyUsername: 'testuser',
        passkeyDisplayName: 'Test User',
      };

      await userService.addUserPasskey(options);

      expect(mockUserApi.addUserPasskeyStart).toHaveBeenCalledWith({
        relyingPartyId: options.relyingPartyId,
        deviceId: mockDeviceId,
        os: OS.web,
        passkeyDisplayName: options.passkeyDisplayName,
        passkeyUsername: options.passkeyUsername,
      });
    });

    test('should use hostname as relyingPartyId if not provided', async () => {
      // Mock window.location.hostname
      const originalHostname = window.location.hostname;
      Object.defineProperty(window.location, 'hostname', {
        value: 'test-hostname.com',
        writable: true,
      });

      await userService.addUserPasskey({});

      expect(mockUserApi.addUserPasskeyStart).toHaveBeenCalledWith(
        expect.objectContaining({
          relyingPartyId: 'test-hostname.com',
        }),
      );

      // Restore window.location.hostname
      Object.defineProperty(window.location, 'hostname', {
        value: originalHostname,
        writable: true,
      });
    });

    test('should call addUserPasskeyComplete with registration result', async () => {
      await userService.addUserPasskey({});

      expect(mockUserApi.addUserPasskeyComplete).toHaveBeenCalledWith(
        { id: 'reg-id' }, // Mock result from startRegistration
        mockDeviceId,
        'challenge-123',
      );
    });
  });
});
