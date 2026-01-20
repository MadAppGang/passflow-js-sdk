import { Mock, afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { PassflowError } from '../../lib/api';
import {
  TwoFactorConfirmResponse,
  TwoFactorDisableResponse,
  TwoFactorPolicy,
  TwoFactorRecoveryResponse,
  TwoFactorRegenerateResponse,
  TwoFactorSetupResponse,
  TwoFactorStatusResponse,
  TwoFactorVerifyResponse,
} from '../../lib/api/model';
import { TwoFactorApiClient } from '../../lib/api/two-factor';
import { TwoFactorService } from '../../lib/services/two-factor-service';
import { StorageManager } from '../../lib/storage';
import { PassflowEvent, PassflowStore } from '../../lib/store';

// Mock dependencies
vi.mock('../../lib/api/two-factor');
vi.mock('../../lib/storage');
vi.mock('../../lib/store');

describe('TwoFactorService', () => {
  // Setup for all tests
  let twoFactorService: TwoFactorService;
  let mockTwoFactorApi: {
    getStatus: Mock;
    beginSetup: Mock;
    confirmSetup: Mock;
    verify: Mock;
    useRecoveryCode: Mock;
    disable: Mock;
    regenerateRecoveryCodes: Mock;
  };
  let mockSubscribeStore: {
    notify: Mock;
    subscribe: Mock;
  };
  let mockStorageManager: {
    saveTokens: Mock;
    getTokens: Mock;
    deleteTokens: Mock;
  };

  // Mock sessionStorage
  const mockSessionStorage: Record<string, string> = {};
  const sessionStorageMock = {
    getItem: vi.fn((key: string) => mockSessionStorage[key] || null),
    setItem: vi.fn((key: string, value: string) => {
      mockSessionStorage[key] = value;
    }),
    removeItem: vi.fn((key: string) => {
      delete mockSessionStorage[key];
    }),
    clear: vi.fn(() => {
      Object.keys(mockSessionStorage).forEach((key) => delete mockSessionStorage[key]);
    }),
  };

  beforeEach(() => {
    // Reset all mocks
    vi.clearAllMocks();
    vi.useFakeTimers();

    // Clear sessionStorage mock
    Object.keys(mockSessionStorage).forEach((key) => delete mockSessionStorage[key]);

    // Setup global sessionStorage mock
    Object.defineProperty(global, 'sessionStorage', {
      value: sessionStorageMock,
      writable: true,
    });

    // Create mock API client
    mockTwoFactorApi = {
      getStatus: vi.fn(),
      beginSetup: vi.fn(),
      confirmSetup: vi.fn(),
      verify: vi.fn(),
      useRecoveryCode: vi.fn(),
      disable: vi.fn(),
      regenerateRecoveryCodes: vi.fn(),
    };

    // Create mock subscribe store
    mockSubscribeStore = {
      notify: vi.fn(),
      subscribe: vi.fn(),
    };

    // Create mock storage manager
    mockStorageManager = {
      saveTokens: vi.fn(),
      getTokens: vi.fn(),
      deleteTokens: vi.fn(),
    };

    // Instantiate service with mocks
    twoFactorService = new TwoFactorService(
      mockTwoFactorApi as unknown as TwoFactorApiClient,
      mockSubscribeStore as unknown as PassflowStore,
    );
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ===================================
  // Category 1: Status Operations
  // ===================================

  describe('getStatus()', () => {
    test('TEST-1: Get 2FA status when disabled', async () => {
      // Given: User is authenticated, 2FA is not enabled
      const mockResponse: TwoFactorStatusResponse = {
        enabled: false,
        policy: TwoFactorPolicy.Optional,
        recovery_codes_remaining: 0,
      };
      mockTwoFactorApi.getStatus.mockResolvedValue(mockResponse);

      // When: getStatus() is called
      const result = await twoFactorService.getStatus();

      // Then: Returns correct status
      expect(result).toEqual(mockResponse);
      expect(result.enabled).toBe(false);
      expect(result.policy).toBe(TwoFactorPolicy.Optional);
      expect(result.recovery_codes_remaining).toBe(0);
      expect(mockTwoFactorApi.getStatus).toHaveBeenCalledTimes(1);
    });

    test('TEST-2: Get 2FA status when enabled', async () => {
      // Given: User is authenticated, 2FA is enabled with 8 recovery codes
      const mockResponse: TwoFactorStatusResponse = {
        enabled: true,
        policy: TwoFactorPolicy.Optional,
        recovery_codes_remaining: 8,
      };
      mockTwoFactorApi.getStatus.mockResolvedValue(mockResponse);

      // When: getStatus() is called
      const result = await twoFactorService.getStatus();

      // Then: Returns correct status
      expect(result).toEqual(mockResponse);
      expect(result.enabled).toBe(true);
      expect(result.recovery_codes_remaining).toBe(8);
      expect(mockTwoFactorApi.getStatus).toHaveBeenCalledTimes(1);
    });

    test('TEST-3: Get 2FA status handles API error', async () => {
      // Given: API returns 401 Unauthorized
      const error = new PassflowError({
        id: 'UNAUTHORIZED',
        message: 'Unauthorized',
        status: 401,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.getStatus.mockRejectedValue(error);

      // When/Then: Throws error and emits error event
      await expect(twoFactorService.getStatus()).rejects.toThrow();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          message: 'Unauthorized',
          code: 'UNAUTHORIZED',
        }),
      );
    });
  });

  // ===================================
  // Category 2: Setup Flow
  // ===================================

  describe('beginSetup()', () => {
    test('TEST-4: Begin 2FA setup successfully', async () => {
      // Given: User is authenticated, 2FA is not enabled
      const mockResponse: TwoFactorSetupResponse = {
        secret: 'JBSWY3DPEHPK3PXP',
        qr_code: 'data:image/png;base64,iVBORw0KGgo...',
      };
      mockTwoFactorApi.beginSetup.mockResolvedValue(mockResponse);

      // When: beginSetup() is called
      const result = await twoFactorService.beginSetup();

      // Then: Returns secret and QR code, emits event
      expect(result).toEqual(mockResponse);
      expect(result.secret).toBe('JBSWY3DPEHPK3PXP');
      expect(result.qr_code).toContain('data:image/png');
      expect(mockTwoFactorApi.beginSetup).toHaveBeenCalledTimes(1);
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.TwoFactorSetupStarted, {
        secret: mockResponse.secret,
      });
    });

    test('TEST-5: Begin 2FA setup when already enabled', async () => {
      // Given: 2FA is already enabled
      const error = new PassflowError({
        id: 'ALREADY_ENABLED',
        message: '2FA is already enabled for this user',
        status: 409,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.beginSetup.mockRejectedValue(error);

      // When/Then: API returns 409 Conflict
      await expect(twoFactorService.beginSetup()).rejects.toThrow();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          code: 'ALREADY_ENABLED',
        }),
      );
    });
  });

  describe('confirmSetup()', () => {
    test('TEST-6: Confirm 2FA setup with valid code', async () => {
      // Given: User has started setup, enters valid 6-digit TOTP code
      const mockResponse: TwoFactorConfirmResponse = {
        success: true,
        recovery_codes: ['ABCD-1234', 'EFGH-5678', 'IJKL-9012'],
      };
      mockTwoFactorApi.confirmSetup.mockResolvedValue(mockResponse);

      // When: confirmSetup() is called
      const result = await twoFactorService.confirmSetup('123456');

      // Then: Returns recovery codes and emits event
      expect(result).toEqual(mockResponse);
      expect(result.success).toBe(true);
      expect(result.recovery_codes).toHaveLength(3);
      expect(mockTwoFactorApi.confirmSetup).toHaveBeenCalledWith({ code: '123456' });
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.TwoFactorEnabled,
        expect.objectContaining({
          recoveryCodes: mockResponse.recovery_codes,
          clearRecoveryCodes: expect.any(Function),
        }),
      );
    });

    test('TEST-7: Confirm 2FA setup with invalid code', async () => {
      // Given: User enters invalid TOTP code
      const error = new PassflowError({
        id: 'INVALID_CODE',
        message: 'Invalid TOTP code',
        status: 400,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.confirmSetup.mockRejectedValue(error);

      // When/Then: API returns 400 Bad Request
      await expect(twoFactorService.confirmSetup('000000')).rejects.toThrow();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          code: 'INVALID_CODE',
        }),
      );
    });

    test('TEST-8: Confirm 2FA setup exceeds rate limit', async () => {
      // Given: User has failed 5 attempts
      const error = new PassflowError({
        id: 'TOO_MANY_ATTEMPTS',
        message: 'Too many failed attempts. Try again in 15 minutes.',
        status: 429,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.confirmSetup.mockRejectedValue(error);

      // When/Then: API returns 429 Too Many Requests
      await expect(twoFactorService.confirmSetup('123456')).rejects.toThrow();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          code: 'TOO_MANY_ATTEMPTS',
        }),
      );
    });

    test('TEST-9: 2fa:enabled event provides cleanup callback', async () => {
      // Given: Setup is confirmed successfully
      const mockResponse: TwoFactorConfirmResponse = {
        success: true,
        recovery_codes: ['ABCD-1234', 'EFGH-5678'],
      };
      mockTwoFactorApi.confirmSetup.mockResolvedValue(mockResponse);

      // When: confirmSetup() succeeds
      await twoFactorService.confirmSetup('123456');

      // Then: Event payload includes clearRecoveryCodes callback
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.TwoFactorEnabled,
        expect.objectContaining({
          recoveryCodes: expect.arrayContaining(['ABCD-1234', 'EFGH-5678']),
          clearRecoveryCodes: expect.any(Function),
        }),
      );

      // Verify callback works
      const eventCall = mockSubscribeStore.notify.mock.calls.find((call) => call[0] === PassflowEvent.TwoFactorEnabled);
      expect(eventCall).toBeDefined();
      if (!eventCall) throw new Error('Expected event call to be defined');
      const payload = eventCall[1];

      // Call the cleanup callback
      payload.clearRecoveryCodes();

      // Recovery codes should be cleared
      expect(mockResponse.recovery_codes).toEqual([]);
    });
  });

  // ===================================
  // Category 3: Login with 2FA Flow
  // ===================================

  describe('verify()', () => {
    test('TEST-10: Verify TOTP code successfully', async () => {
      // Given: User has signed in with password, 2FA is required, partial auth state is set
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      const mockResponse: TwoFactorVerifyResponse = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        success: true,
      };
      mockTwoFactorApi.verify.mockResolvedValue(mockResponse);

      // When: verify() is called
      const result = await twoFactorService.verify('123456');

      // Then: Returns tokens, emits event, clears state
      expect(result).toEqual(mockResponse);
      expect(mockTwoFactorApi.verify).toHaveBeenCalledWith({
        code: '123456',
        tfa_token: 'tfa-token-123',
      });
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.TwoFactorVerified, { tokens: mockResponse });
      expect(twoFactorService.isVerificationRequired()).toBe(false);
    });

    test('TEST-11: Verify TOTP code with invalid code', async () => {
      // Given: Partial auth state is set
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      const error = new PassflowError({
        id: 'INVALID_CODE',
        message: 'Invalid TOTP code',
        status: 400,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.verify.mockRejectedValue(error);

      // When/Then: API returns 400 Bad Request
      await expect(twoFactorService.verify('000000')).rejects.toThrow();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          code: 'INVALID_CODE',
        }),
      );
    });

    test('TEST-12: Verify TOTP code without partial auth state', async () => {
      // Given: No partial auth state is set
      // (service initialized without setPartialAuthState)

      // When/Then: Throws error
      await expect(twoFactorService.verify('123456')).rejects.toThrow(
        '2FA verification expired or not required. User must sign in first.',
      );
      expect(mockTwoFactorApi.verify).not.toHaveBeenCalled();
    });

    test('TEST-13: Verify TOTP code with expired partial auth state', async () => {
      // Given: Partial auth state was set 6 minutes ago
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      // Advance time by 6 minutes (360,000ms)
      vi.advanceTimersByTime(6 * 60 * 1000);

      // When/Then: Throws error due to expiration
      await expect(twoFactorService.verify('123456')).rejects.toThrow(
        '2FA verification expired or not required. User must sign in first.',
      );
      expect(twoFactorService.isVerificationRequired()).toBe(false);
      expect(mockTwoFactorApi.verify).not.toHaveBeenCalled();
    });

    test('TEST-14: Verify TOTP code without tfa_token', async () => {
      // Given: Partial auth state exists but missing tfaToken
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', undefined);

      // When/Then: Throws error
      await expect(twoFactorService.verify('123456')).rejects.toThrow('No TFA token found. User must sign in first.');
      expect(mockTwoFactorApi.verify).not.toHaveBeenCalled();
    });

    test('TEST-15: Verify TOTP code clears partial auth state on success', async () => {
      // Given: Partial auth state is set
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');
      expect(twoFactorService.isVerificationRequired()).toBe(true);

      const mockResponse: TwoFactorVerifyResponse = {
        access_token: 'mock-access-token',
        success: true,
      };
      mockTwoFactorApi.verify.mockResolvedValue(mockResponse);

      // When: verify() succeeds
      await twoFactorService.verify('123456');

      // Then: Partial auth state is cleared
      expect(twoFactorService.isVerificationRequired()).toBe(false);
      expect(sessionStorageMock.removeItem).toHaveBeenCalledWith('passflow_2fa_challenge');
    });
  });

  // ===================================
  // Category 4: Recovery Code Flow
  // ===================================

  describe('useRecoveryCode()', () => {
    test('TEST-16: Use recovery code successfully', async () => {
      // Given: Partial auth state is set, user has 8 recovery codes
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      const mockResponse: TwoFactorRecoveryResponse = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        success: true,
        remaining_recovery_codes: 7,
      };
      mockTwoFactorApi.useRecoveryCode.mockResolvedValue(mockResponse);

      // When: useRecoveryCode() is called
      const result = await twoFactorService.useRecoveryCode('ABCD-1234');

      // Then: Returns tokens with remaining codes, emits events
      expect(result).toEqual(mockResponse);
      expect(result.remaining_recovery_codes).toBe(7);
      expect(mockTwoFactorApi.useRecoveryCode).toHaveBeenCalledWith({
        recovery_code: 'ABCD-1234',
        tfa_token: 'tfa-token-123',
      });
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.TwoFactorRecoveryUsed,
        expect.objectContaining({
          tokens: mockResponse,
          remainingCodes: 7,
        }),
      );
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.TwoFactorVerified, { tokens: mockResponse });
    });

    test('TEST-17: Use recovery code with 2 remaining codes', async () => {
      // Given: Partial auth state is set, user has 2 recovery codes remaining
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      const mockResponse: TwoFactorRecoveryResponse = {
        access_token: 'mock-access-token',
        success: true,
        remaining_recovery_codes: 1,
      };
      mockTwoFactorApi.useRecoveryCode.mockResolvedValue(mockResponse);

      // When: useRecoveryCode() is called
      await twoFactorService.useRecoveryCode('ABCD-1234');

      // Then: Emits low recovery codes warning
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.TwoFactorRecoveryCodesLow,
        expect.objectContaining({
          tokens: mockResponse,
          remainingCodes: 1,
        }),
      );
    });

    test('TEST-18: Use last recovery code', async () => {
      // Given: Partial auth state is set, user has 1 recovery code remaining
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      const mockResponse: TwoFactorRecoveryResponse = {
        access_token: 'mock-access-token',
        success: true,
        remaining_recovery_codes: 0,
      };
      mockTwoFactorApi.useRecoveryCode.mockResolvedValue(mockResponse);

      // When: useRecoveryCode() is called
      await twoFactorService.useRecoveryCode('ABCD-1234');

      // Then: Emits exhaustion event
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.TwoFactorRecoveryCodesExhausted,
        expect.objectContaining({
          tokens: mockResponse,
        }),
      );
    });

    test('TEST-19: Use invalid recovery code', async () => {
      // Given: Partial auth state is set
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      const error = new PassflowError({
        id: 'INVALID_RECOVERY_CODE',
        message: 'Invalid recovery code',
        status: 400,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.useRecoveryCode.mockRejectedValue(error);

      // When/Then: API returns 400 Bad Request
      await expect(twoFactorService.useRecoveryCode('INVALID')).rejects.toThrow();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          code: 'INVALID_RECOVERY_CODE',
        }),
      );
    });

    test('TEST-20: Use recovery code without partial auth state', async () => {
      // Given: No partial auth state is set

      // When/Then: Throws error
      await expect(twoFactorService.useRecoveryCode('ABCD-1234')).rejects.toThrow(
        '2FA verification expired or not required. User must sign in first.',
      );
      expect(mockTwoFactorApi.useRecoveryCode).not.toHaveBeenCalled();
    });

    test('TEST-21: Use recovery code clears partial auth state on success', async () => {
      // Given: Partial auth state is set
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');
      expect(twoFactorService.isVerificationRequired()).toBe(true);

      const mockResponse: TwoFactorRecoveryResponse = {
        access_token: 'mock-access-token',
        success: true,
        remaining_recovery_codes: 5,
      };
      mockTwoFactorApi.useRecoveryCode.mockResolvedValue(mockResponse);

      // When: useRecoveryCode() succeeds
      await twoFactorService.useRecoveryCode('ABCD-1234');

      // Then: Partial auth state is cleared
      expect(twoFactorService.isVerificationRequired()).toBe(false);
      expect(sessionStorageMock.removeItem).toHaveBeenCalledWith('passflow_2fa_challenge');
    });
  });

  // ===================================
  // Category 5: Disable 2FA Flow
  // ===================================

  describe('disable()', () => {
    test('TEST-22: Disable 2FA with valid code', async () => {
      // Given: User is authenticated, 2FA is enabled
      const mockResponse: TwoFactorDisableResponse = {
        success: true,
      };
      mockTwoFactorApi.disable.mockResolvedValue(mockResponse);

      // When: disable() is called with valid code
      const result = await twoFactorService.disable('123456');

      // Then: Returns success and emits event
      expect(result).toEqual(mockResponse);
      expect(mockTwoFactorApi.disable).toHaveBeenCalledWith({ code: '123456' });
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.TwoFactorDisabled, {});
    });

    test('TEST-23: Disable 2FA with invalid code', async () => {
      // Given: User is authenticated, 2FA is enabled
      const error = new PassflowError({
        id: 'INVALID_CODE',
        message: 'Invalid TOTP code',
        status: 400,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.disable.mockRejectedValue(error);

      // When/Then: API returns 400 Bad Request
      await expect(twoFactorService.disable('000000')).rejects.toThrow();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          code: 'INVALID_CODE',
        }),
      );
    });

    test('TEST-24: Disable 2FA when not enabled', async () => {
      // Given: User is authenticated, 2FA is not enabled
      const error = new PassflowError({
        id: 'NOT_ENABLED',
        message: '2FA is not enabled for this user',
        status: 404,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.disable.mockRejectedValue(error);

      // When/Then: API returns 404 Not Found
      await expect(twoFactorService.disable('123456')).rejects.toThrow();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          code: 'NOT_ENABLED',
        }),
      );
    });
  });

  // ===================================
  // Category 6: Recovery Code Regeneration
  // ===================================

  describe('regenerateRecoveryCodes()', () => {
    test('TEST-25: Regenerate recovery codes with valid code', async () => {
      // Given: User is authenticated, 2FA is enabled
      const mockResponse: TwoFactorRegenerateResponse = {
        success: true,
        recovery_codes: ['NEW1-1111', 'NEW2-2222', 'NEW3-3333'],
      };
      mockTwoFactorApi.regenerateRecoveryCodes.mockResolvedValue(mockResponse);

      // When: regenerateRecoveryCodes() is called
      const result = await twoFactorService.regenerateRecoveryCodes('123456');

      // Then: Returns new codes
      expect(result).toEqual(mockResponse);
      expect(result.recovery_codes).toHaveLength(3);
      expect(mockTwoFactorApi.regenerateRecoveryCodes).toHaveBeenCalledWith({ code: '123456' });
    });

    test('TEST-26: Regenerate recovery codes with invalid code', async () => {
      // Given: User is authenticated, 2FA is enabled
      const error = new PassflowError({
        id: 'INVALID_CODE',
        message: 'Invalid TOTP code',
        status: 400,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.regenerateRecoveryCodes.mockRejectedValue(error);

      // When/Then: API returns 400 Bad Request
      await expect(twoFactorService.regenerateRecoveryCodes('000000')).rejects.toThrow();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          code: 'INVALID_CODE',
        }),
      );
    });

    test('TEST-27: Regenerate recovery codes when 2FA not enabled', async () => {
      // Given: User is authenticated, 2FA is not enabled
      const error = new PassflowError({
        id: 'NOT_ENABLED',
        message: '2FA is not enabled for this user',
        status: 404,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.regenerateRecoveryCodes.mockRejectedValue(error);

      // When/Then: API returns 404 Not Found
      await expect(twoFactorService.regenerateRecoveryCodes('123456')).rejects.toThrow();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          code: 'NOT_ENABLED',
        }),
      );
    });
  });

  // ===================================
  // Category 7: Partial Auth State Management
  // ===================================

  describe('isVerificationRequired()', () => {
    test('TEST-28: isVerificationRequired returns false by default', () => {
      // Given: No partial auth state is set

      // When: isVerificationRequired() is called
      const result = twoFactorService.isVerificationRequired();

      // Then: Returns false
      expect(result).toBe(false);
    });

    test('TEST-29: isVerificationRequired returns true when state is set', () => {
      // Given: Partial auth state is set
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      // When: isVerificationRequired() is called
      const result = twoFactorService.isVerificationRequired();

      // Then: Returns true
      expect(result).toBe(true);
    });

    test('TEST-30: isVerificationRequired returns false after 5-minute timeout', () => {
      // Given: Partial auth state was set 6 minutes ago
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      // Advance time by 6 minutes
      vi.advanceTimersByTime(6 * 60 * 1000);

      // When: isVerificationRequired() is called
      const result = twoFactorService.isVerificationRequired();

      // Then: Returns false and clears state
      expect(result).toBe(false);
      expect(sessionStorageMock.removeItem).toHaveBeenCalledWith('passflow_2fa_challenge');
    });
  });

  describe('partial auth state', () => {
    test('TEST-31: Set partial auth state with TwoFactorRequired event', () => {
      // Given: TwoFactorService is initialized
      expect(mockSubscribeStore.subscribe).toHaveBeenCalled();

      // Get the event listener function
      const subscribeCall = mockSubscribeStore.subscribe.mock.calls[0];
      const eventSubscriber = subscribeCall[0];

      // When: TwoFactorRequired event is emitted
      eventSubscriber.onAuthChange(PassflowEvent.TwoFactorRequired, {
        email: 'user@example.com',
        challengeId: 'challenge-123',
        tfaToken: 'tfa-token-123',
      });

      // Then: isVerificationRequired() returns true
      expect(twoFactorService.isVerificationRequired()).toBe(true);
    });

    test('TEST-32: Clear partial auth state on logout', () => {
      // Given: Partial auth state is set
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');
      expect(twoFactorService.isVerificationRequired()).toBe(true);

      // When: clearPartialAuthState() is called
      twoFactorService.clearPartialAuthState();

      // Then: isVerificationRequired() returns false
      expect(twoFactorService.isVerificationRequired()).toBe(false);
      expect(sessionStorageMock.removeItem).toHaveBeenCalledWith('passflow_2fa_challenge');
    });

    test('TEST-33: Persist partial auth state to sessionStorage', () => {
      // Given: Partial auth state is being set
      const email = 'user@example.com';
      const challengeId = 'challenge-123';
      const tfaToken = 'tfa-token-123';

      // When: setPartialAuthState() is called
      twoFactorService.setPartialAuthState(email, challengeId, tfaToken);

      // Then: State is stored in sessionStorage
      expect(sessionStorageMock.setItem).toHaveBeenCalledWith(
        'passflow_2fa_challenge',
        expect.stringContaining('challenge-123'),
      );

      // Verify stored data structure
      const storedData = JSON.parse(mockSessionStorage['passflow_2fa_challenge']);
      expect(storedData).toMatchObject({
        email,
        challengeId,
        tfaToken,
        timestamp: expect.any(Number),
        expiresAt: expect.any(Number),
      });
    });

    test('TEST-34: Recover partial auth state from sessionStorage', () => {
      // Given: sessionStorage contains valid partial auth state
      const storedState = {
        email: 'user@example.com',
        challengeId: 'challenge-123',
        tfaToken: 'tfa-token-123',
        timestamp: Date.now(),
        expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes from now
      };
      mockSessionStorage['passflow_2fa_challenge'] = JSON.stringify(storedState);

      // Create new service instance (simulates page refresh)
      const newService = new TwoFactorService(
        mockTwoFactorApi as unknown as TwoFactorApiClient,
        mockSubscribeStore as unknown as PassflowStore,
      );

      // Mock the API call
      const mockResponse: TwoFactorVerifyResponse = {
        access_token: 'mock-access-token',
        success: true,
      };
      mockTwoFactorApi.verify.mockResolvedValue(mockResponse);

      // When: verify() is called (triggers recovery)
      newService.verify('123456');

      // Then: State is recovered (verify was called with correct tfa_token)
      expect(mockTwoFactorApi.verify).toHaveBeenCalledWith({
        code: '123456',
        tfa_token: 'tfa-token-123',
      });
    });

    test('TEST-35: Do not recover expired state from sessionStorage', async () => {
      // Given: sessionStorage contains expired partial auth state
      const expiredState = {
        email: 'user@example.com',
        challengeId: 'challenge-123',
        timestamp: Date.now() - 6 * 60 * 1000, // 6 minutes ago
        expiresAt: Date.now() - 1 * 60 * 1000, // Expired 1 minute ago
      };
      mockSessionStorage['passflow_2fa_challenge'] = JSON.stringify(expiredState);

      // Create new service instance (simulates page refresh)
      const newService = new TwoFactorService(
        mockTwoFactorApi as unknown as TwoFactorApiClient,
        mockSubscribeStore as unknown as PassflowStore,
      );

      // When: verify() is called
      const verifyPromise = newService.verify('123456');

      // Then: Expired state is not recovered, sessionStorage is cleaned
      await expect(verifyPromise).rejects.toThrow('2FA verification expired or not required');

      // sessionStorage should be cleaned up during recovery attempt
      // The service's recoverPartialAuthState should have removed it
    });
  });

  // ===================================
  // Category 8: Event Emissions
  // ===================================

  describe('Event Emissions', () => {
    test('TEST-36: Emit 2fa:setup_started event on beginSetup', async () => {
      // Given: User calls beginSetup()
      const mockResponse: TwoFactorSetupResponse = {
        secret: 'JBSWY3DPEHPK3PXP',
        qr_code: 'data:image/png;base64,iVBORw0KGgo...',
      };
      mockTwoFactorApi.beginSetup.mockResolvedValue(mockResponse);

      // When: API returns success
      await twoFactorService.beginSetup();

      // Then: Event is emitted with secret
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.TwoFactorSetupStarted, {
        secret: mockResponse.secret,
      });
    });

    test('TEST-37: Emit 2fa:enabled event on confirmSetup', async () => {
      // Given: User calls confirmSetup() with valid code
      const mockResponse: TwoFactorConfirmResponse = {
        success: true,
        recovery_codes: ['ABCD-1234', 'EFGH-5678'],
      };
      mockTwoFactorApi.confirmSetup.mockResolvedValue(mockResponse);

      // When: API returns success with recovery codes
      await twoFactorService.confirmSetup('123456');

      // Then: Event is emitted with recovery codes and cleanup callback
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.TwoFactorEnabled,
        expect.objectContaining({
          recoveryCodes: mockResponse.recovery_codes,
          clearRecoveryCodes: expect.any(Function),
        }),
      );
    });

    test('TEST-38: Emit 2fa:verified event on successful verify', async () => {
      // Given: User calls verify() with valid code
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');
      const mockResponse: TwoFactorVerifyResponse = {
        access_token: 'mock-access-token',
        success: true,
      };
      mockTwoFactorApi.verify.mockResolvedValue(mockResponse);

      // When: API returns tokens
      await twoFactorService.verify('123456');

      // Then: Event is emitted with tokens
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.TwoFactorVerified, { tokens: mockResponse });
    });

    test('TEST-39: Emit 2fa:disabled event on disable', async () => {
      // Given: User calls disable() with valid code
      const mockResponse: TwoFactorDisableResponse = {
        success: true,
      };
      mockTwoFactorApi.disable.mockResolvedValue(mockResponse);

      // When: API returns success
      await twoFactorService.disable('123456');

      // Then: Event is emitted
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.TwoFactorDisabled, {});
    });

    test('TEST-40: Emit error event on API failures', async () => {
      // Given: Any 2FA method is called
      const error = new PassflowError({
        id: 'INVALID_CODE',
        message: 'Invalid TOTP code',
        status: 400,
        location: 'two-factor-service.test.ts',
        time: new Date().toISOString(),
      });
      mockTwoFactorApi.getStatus.mockRejectedValue(error);

      // When: API returns error
      await expect(twoFactorService.getStatus()).rejects.toThrow();

      // Then: Error event is emitted with error details
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({
          message: 'Invalid TOTP code',
          code: 'INVALID_CODE',
          originalError: error,
        }),
      );
    });
  });

  // ===================================
  // Category 9: Edge Cases
  // ===================================

  describe('Edge Cases', () => {
    test('TEST-41: Handle concurrent verification attempts', async () => {
      // Given: Partial auth state is set
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      const mockResponse: TwoFactorVerifyResponse = {
        access_token: 'mock-access-token',
        success: true,
      };
      mockTwoFactorApi.verify.mockResolvedValue(mockResponse);

      // When: Multiple verify() calls are made simultaneously
      const promise1 = twoFactorService.verify('123456');
      const promise2 = twoFactorService.verify('654321');

      await Promise.all([promise1, promise2]);

      // Then: Each call uses the same tfaToken
      expect(mockTwoFactorApi.verify).toHaveBeenCalledTimes(2);
      expect(mockTwoFactorApi.verify).toHaveBeenNthCalledWith(1, {
        code: '123456',
        tfa_token: 'tfa-token-123',
      });
      expect(mockTwoFactorApi.verify).toHaveBeenNthCalledWith(2, {
        code: '654321',
        tfa_token: 'tfa-token-123',
      });
    });

    test('TEST-42: Validate partial auth state timeout is 5 minutes', () => {
      // Given: Partial auth state is set
      const startTime = Date.now();
      twoFactorService.setPartialAuthState('user@example.com', 'challenge-123', 'tfa-token-123');

      // Get stored state
      const storedData = JSON.parse(mockSessionStorage['passflow_2fa_challenge']);

      // Then: Expiration should be 5 minutes (300000ms) from now
      const expectedExpiration = startTime + 5 * 60 * 1000;
      expect(storedData.expiresAt).toBe(expectedExpiration);

      // Verify state is valid at 4 minutes 59 seconds
      vi.advanceTimersByTime(4 * 60 * 1000 + 59 * 1000);
      expect(twoFactorService.isVerificationRequired()).toBe(true);

      // Verify state expires at 5 minutes 1 second
      vi.advanceTimersByTime(2 * 1000);
      expect(twoFactorService.isVerificationRequired()).toBe(false);
    });
  });
});
