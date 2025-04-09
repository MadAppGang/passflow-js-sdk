import { Mock, beforeEach, describe, expect, test, vi } from 'vitest';
import {
  AuthAPI,
  OS,
  PassflowAuthorizationResponse,
  PassflowPasswordlessResponse,
  PassflowSuccessResponse,
  PassflowUserPayload,
} from '../../lib/api';
import { DeviceService } from '../../lib/device-service';
import { AuthService } from '../../lib/services/auth-service';
import { StorageManager } from '../../lib/storage-manager';
import { PassflowEvent, PassflowStore } from '../../lib/store';
import { Token, TokenService, isTokenExpired, parseToken } from '../../lib/token-service';
import { ParsedTokens, Tokens } from '../../lib/types';

// Mock dependencies
vi.mock('../../lib/api/auth');
vi.mock('../../lib/device-service');
vi.mock('../../lib/storage-manager');
vi.mock('../../lib/token-service');
vi.mock('../../lib/store');
vi.mock('@simplewebauthn/browser', () => ({
  startAuthentication: vi.fn().mockResolvedValue({ id: 'auth-id' }),
  startRegistration: vi.fn().mockResolvedValue({ id: 'reg-id' }),
}));

describe('AuthService', () => {
  // Setup for all tests
  let authService: AuthService;
  let mockAuthApi: {
    signIn: Mock;
    signUp: Mock;
    passwordlessSignIn: Mock;
    passwordlessSignInComplete: Mock;
    logOut: Mock;
    refreshToken: Mock;
    sendPasswordResetEmail: Mock;
    resetPassword: Mock;
    passkeyRegisterStart: Mock;
    passkeyRegisterComplete: Mock;
    passkeyAuthenticateStart: Mock;
    passkeyAuthenticateComplete: Mock;
  };
  let mockDeviceService: {
    getDeviceId: Mock;
  };
  let mockStorageManager: {
    saveTokens: Mock;
    getTokens: Mock;
    getToken: Mock;
    deleteTokens: Mock;
    getDeviceId: Mock;
  };
  let mockSubscribeStore: {
    notify: Mock;
  };

  const mockScopes = ['profile', 'email'];
  const mockOrigin = 'https://example.com';
  const mockUrl = 'https://api.example.com';
  const mockAppId = 'test-app-id';
  const mockDeviceId = 'test-device-id';

  const mockTokens: Tokens = {
    access_token: 'mock-access-token',
    refresh_token: 'mock-refresh-token',
    id_token: 'mock-id-token',
    scopes: mockScopes,
  };

  const mockAuthResponse: PassflowAuthorizationResponse = {
    access_token: 'mock-access-token',
    refresh_token: 'mock-refresh-token',
    id_token: 'mock-id-token',
    scopes: mockScopes,
  };

  const mockParsedToken: Token = {
    aud: ['test-audience'],
    exp: Date.now() / 1000 + 3600,
    iat: Date.now() / 1000,
    iss: 'test-issuer',
    jti: 'test-jti',
    sub: 'test-subject',
    type: 'access',
  };

  const mockParsedTokens: ParsedTokens = {
    access_token: mockParsedToken,
    id_token: mockParsedToken,
    refresh_token: mockParsedToken,
    scopes: mockScopes,
  };

  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();

    // Create mock instances
    mockAuthApi = {
      signIn: vi.fn().mockResolvedValue(mockAuthResponse),
      signUp: vi.fn().mockResolvedValue(mockAuthResponse),
      passwordlessSignIn: vi.fn().mockResolvedValue({
        challenge_id: 'challenge-123',
        expires_at: new Date().toISOString(),
      } as PassflowPasswordlessResponse),
      passwordlessSignInComplete: vi.fn().mockResolvedValue(mockAuthResponse),
      logOut: vi.fn().mockResolvedValue({ result: 'ok' } as PassflowSuccessResponse),
      refreshToken: vi.fn().mockResolvedValue(mockAuthResponse),
      sendPasswordResetEmail: vi.fn().mockResolvedValue({ result: 'ok' } as PassflowSuccessResponse),
      resetPassword: vi.fn().mockResolvedValue(mockAuthResponse),
      passkeyRegisterStart: vi.fn().mockResolvedValue({
        challenge_id: 'challenge-123',
        publicKey: { user: { id: 'user-id' } },
      }),
      passkeyRegisterComplete: vi.fn().mockResolvedValue(mockAuthResponse),
      passkeyAuthenticateStart: vi.fn().mockResolvedValue({
        challenge_id: 'challenge-123',
        publicKey: {},
      }),
      passkeyAuthenticateComplete: vi.fn().mockResolvedValue(mockAuthResponse),
    };

    mockDeviceService = {
      getDeviceId: vi.fn().mockReturnValue(mockDeviceId),
    };

    mockStorageManager = {
      saveTokens: vi.fn(),
      getTokens: vi.fn().mockReturnValue(mockTokens),
      getToken: vi.fn().mockReturnValue(mockTokens.refresh_token),
      deleteTokens: vi.fn(),
      getDeviceId: vi.fn().mockReturnValue(mockDeviceId),
    };

    // Mock token service functions directly
    vi.mocked(isTokenExpired).mockReturnValue(false);
    vi.mocked(parseToken).mockReturnValue(mockParsedToken);

    mockSubscribeStore = {
      notify: vi.fn(),
    };

    // Create AuthService instance
    authService = new AuthService(
      mockAuthApi as unknown as AuthAPI,
      mockDeviceService as unknown as DeviceService,
      mockStorageManager as unknown as StorageManager,
      mockSubscribeStore as unknown as PassflowStore,
      mockScopes,
      true, // createTenantForNewUser
      mockOrigin,
      mockUrl,
      {}, // sessionCallbacks
      mockAppId,
    );
  });

  describe('signIn', () => {
    test('should call AuthAPI signIn with correct parameters', async () => {
      const payload = { email: 'test@example.com', password: 'password123' };

      await authService.signIn(payload);

      expect(mockAuthApi.signIn).toHaveBeenCalledWith({ ...payload, scopes: mockScopes }, mockDeviceId, OS.web);
    });

    test('should save tokens and emit SignIn event', async () => {
      const payload = { email: 'test@example.com', password: 'password123' };

      await authService.signIn(payload);

      expect(mockStorageManager.saveTokens).toHaveBeenCalledWith(mockAuthResponse);
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.SignIn, { tokens: mockAuthResponse });
    });
  });

  describe('signUp', () => {
    test('should call AuthAPI signUp with correct parameters', async () => {
      const mockUser: PassflowUserPayload = {
        password: 'password123',
        email: 'test@example.com',
        given_name: 'Test',
        family_name: 'User',
      };

      const payload = {
        email: 'test@example.com',
        password: 'password123',
        user: mockUser,
      };

      await authService.signUp(payload);

      expect(mockAuthApi.signUp).toHaveBeenCalledWith({
        ...payload,
        scopes: mockScopes,
        create_tenant: true,
      });
    });

    test('should save tokens and emit Register event', async () => {
      const mockUser: PassflowUserPayload = {
        password: 'password123',
        email: 'test@example.com',
        given_name: 'Test',
        family_name: 'User',
      };

      const payload = {
        email: 'test@example.com',
        password: 'password123',
        user: mockUser,
      };

      await authService.signUp(payload);

      expect(mockStorageManager.saveTokens).toHaveBeenCalledWith(mockAuthResponse);
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.Register, { tokens: mockAuthResponse });
    });
  });

  describe('logOut', () => {
    test('should call AuthAPI logOut with correct parameters', async () => {
      await authService.logOut();

      expect(mockAuthApi.logOut).toHaveBeenCalledWith(mockDeviceId, mockTokens.refresh_token, false);
    });

    test('should delete tokens and emit SignOut event', async () => {
      await authService.logOut();

      expect(mockStorageManager.deleteTokens).toHaveBeenCalled();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.SignOut, {});
    });
  });

  describe('refreshToken', () => {
    test('should call AuthAPI refreshToken with correct parameters', async () => {
      await authService.refreshToken();

      expect(mockAuthApi.refreshToken).toHaveBeenCalledWith(mockTokens.refresh_token, mockScopes, mockTokens.access_token);
    });

    test('should save tokens and emit Refresh event', async () => {
      await authService.refreshToken();

      expect(mockStorageManager.saveTokens).toHaveBeenCalledWith({
        ...mockAuthResponse,
        scopes: mockScopes,
      });
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.Refresh, {
        tokens: expect.objectContaining(mockAuthResponse),
      });
    });

    test('should throw error if no tokens are available', async () => {
      mockStorageManager.getTokens.mockReturnValueOnce(undefined);

      await expect(authService.refreshToken()).rejects.toThrow('No tokens found');
    });

    test('should throw error if no refresh token is available', async () => {
      mockStorageManager.getTokens.mockReturnValueOnce({ access_token: 'token', scopes: [] });

      await expect(authService.refreshToken()).rejects.toThrow('No refresh token found');
    });
  });

  describe('isAuthenticated', () => {
    test('should return false if no tokens', () => {
      const result = authService.isAuthenticated(undefined as unknown as ParsedTokens);
      expect(result).toBe(false);
    });

    test('should return true if tokens are valid', () => {
      const result = authService.isAuthenticated(mockParsedTokens);
      expect(result).toBe(true);
    });
  });

  describe('getTokens', () => {
    test('should return tokens if valid', async () => {
      const tokens = await authService.getTokens(false);
      expect(tokens).toEqual(mockTokens);
    });

    test('should return undefined if no tokens in storage', async () => {
      mockStorageManager.getTokens.mockReturnValueOnce(undefined);
      const tokens = await authService.getTokens(false);
      expect(tokens).toBeUndefined();
    });
  });

  describe('authRedirectUrl', () => {
    test('should generate correct redirect URL', () => {
      // Mock window.location.href which is used in the method
      const originalWindowLocation = window.location;
      Object.defineProperty(window, 'location', {
        writable: true,
        value: { href: 'https://example.com' },
      });

      const url = authService.authRedirectUrl({
        redirectUrl: 'https://app.example.com/callback',
      });

      expect(url).toContain('web');
      expect(url).toContain('appId=test-app-id');
      expect(url).toContain('redirectto=https://app.example.com/callback');
      expect(url).toContain('scopes=profile,email');

      // Restore window.location
      Object.defineProperty(window, 'location', {
        writable: true,
        value: originalWindowLocation,
      });
    });
  });
});
