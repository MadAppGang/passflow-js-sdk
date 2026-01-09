import { Mock, beforeEach, describe, expect, test, vi } from 'vitest';
import {
  AuthAPI,
  OS,
  PassflowAuthorizationResponse,
  PassflowLogoutResponse,
  PassflowPasswordlessResponse,
  PassflowSuccessResponse,
  PassflowUserPayload,
} from '../../lib/api';
import { DeviceService } from '../../lib/device';
import { AuthService } from '../../lib/services/auth-service';
import { TokenCacheService } from '../../lib/services/token-cache-service';
import { StorageManager } from '../../lib/storage';
import { PassflowEvent, PassflowStore } from '../../lib/store';
import { Token, TokenService, isTokenExpired, parseToken } from '../../lib/token';
import { ParsedTokens, Tokens } from '../../lib/types';

// Mock dependencies
vi.mock('../../lib/api/auth');
vi.mock('../../lib/device');
vi.mock('../../lib/storage');
vi.mock('../../lib/token');
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
  let mockTokenCacheService: {
    setTokensCache: Mock;
    getTokens: Mock;
    getParsedTokens: Mock;
    isExpired: Mock;
    getTokensWithRefresh: Mock;
    initialize: Mock;
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
      logOut: vi.fn().mockResolvedValue({ status: 'ok' } as PassflowLogoutResponse),
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

    mockTokenCacheService = {
      setTokensCache: vi.fn(),
      getTokens: vi.fn().mockReturnValue(mockTokens),
      getParsedTokens: vi.fn().mockReturnValue(mockParsedTokens),
      isExpired: vi.fn().mockReturnValue(false),
      getTokensWithRefresh: vi.fn().mockResolvedValue(mockTokens),
      initialize: vi.fn(),
      startTokenCheck: vi.fn(),
      isRefreshing: false,
      tokenExpiredFlag: false,
    };

    // Create AuthService instance
    authService = new AuthService(
      mockAuthApi as unknown as AuthAPI,
      mockDeviceService as unknown as DeviceService,
      mockStorageManager as unknown as StorageManager,
      mockSubscribeStore as unknown as PassflowStore,
      mockTokenCacheService as unknown as TokenCacheService,
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
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.SignIn, {
        tokens: mockAuthResponse,
        parsedTokens: mockParsedTokens,
      });
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
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(PassflowEvent.Register, {
        tokens: mockAuthResponse,
        parsedTokens: mockParsedTokens,
      });
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
        parsedTokens: mockParsedTokens,
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

  describe('signIn validation', () => {
    test('should throw error for invalid email format', async () => {
      const payload = { email: 'invalid-email', password: 'password123' };

      await expect(authService.signIn(payload)).rejects.toThrow('Invalid email format');
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({ code: 'VALIDATION_ERROR' })
      );
    });

    test('should throw error for invalid username format', async () => {
      const payload = { username: 'ab', password: 'password123' }; // Too short

      await expect(authService.signIn(payload)).rejects.toThrow('Invalid username format');
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({ code: 'VALIDATION_ERROR' })
      );
    });

    test('should throw error for invalid phone format', async () => {
      const payload = { phone: '12345', password: 'password123' }; // Invalid format

      await expect(authService.signIn(payload)).rejects.toThrow('Invalid phone number format');
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({ code: 'VALIDATION_ERROR' })
      );
    });

    test('should handle 2FA required response', async () => {
      const twoFaResponse = {
        requires_2fa: true,
        challenge_id: 'challenge-123',
      };
      mockAuthApi.signIn.mockResolvedValueOnce(twoFaResponse);

      const payload = { email: 'test@example.com', password: 'password123' };
      const result = await authService.signIn(payload);

      expect(result).toEqual(twoFaResponse);
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.TwoFactorRequired,
        expect.objectContaining({ challengeId: 'challenge-123' })
      );
      // Should NOT save tokens or emit SignIn
      expect(mockStorageManager.saveTokens).not.toHaveBeenCalled();
    });

    test('should handle signIn API error', async () => {
      mockAuthApi.signIn.mockRejectedValueOnce(new Error('Network error'));

      const payload = { email: 'test@example.com', password: 'password123' };

      await expect(authService.signIn(payload)).rejects.toThrow('Network error');
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({ message: 'Network error' })
      );
    });
  });

  describe('signUp validation', () => {
    test('should throw error for invalid email in user payload', async () => {
      const payload = {
        email: 'test@example.com',
        password: 'password123',
        user: { email: 'invalid-email', password: 'password123' },
      };

      await expect(authService.signUp(payload)).rejects.toThrow('Invalid email format');
    });

    test('should throw error for invalid phone in user payload', async () => {
      const payload = {
        email: 'test@example.com',
        password: 'password123',
        user: { email: 'test@example.com', password: 'password123', phone_number: '12345' },
      };

      await expect(authService.signUp(payload)).rejects.toThrow('Invalid phone number format');
    });

    test('should handle signUp API error', async () => {
      mockAuthApi.signUp.mockRejectedValueOnce(new Error('Registration failed'));

      const payload = {
        email: 'test@example.com',
        password: 'password123',
        user: { email: 'test@example.com', password: 'password123' },
      };

      await expect(authService.signUp(payload)).rejects.toThrow('Registration failed');
    });
  });

  describe('passwordlessSignIn', () => {
    test('should call passwordlessSignIn with correct parameters', async () => {
      const payload = { email: 'test@example.com' };

      await authService.passwordlessSignIn(payload);

      expect(mockAuthApi.passwordlessSignIn).toHaveBeenCalledWith(
        expect.objectContaining({ email: 'test@example.com', scopes: mockScopes }),
        mockDeviceId,
        OS.web
      );
    });

    test('should throw error for invalid email', async () => {
      const payload = { email: 'invalid-email' };

      await expect(authService.passwordlessSignIn(payload)).rejects.toThrow('Invalid email format');
    });

    test('should throw error for invalid phone', async () => {
      const payload = { phone: '12345' };

      await expect(authService.passwordlessSignIn(payload)).rejects.toThrow('Invalid phone number format');
    });

    test('should handle passwordlessSignIn API error', async () => {
      mockAuthApi.passwordlessSignIn.mockRejectedValueOnce(new Error('Failed to send link'));

      const payload = { email: 'test@example.com' };

      await expect(authService.passwordlessSignIn(payload)).rejects.toThrow('Failed to send link');
    });
  });

  describe('passwordlessSignInComplete', () => {
    test('should complete passwordless sign in', async () => {
      const payload = { challenge_id: 'challenge-123', code: '123456' };

      await authService.passwordlessSignInComplete(payload);

      expect(mockAuthApi.passwordlessSignInComplete).toHaveBeenCalled();
      expect(mockStorageManager.saveTokens).toHaveBeenCalled();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.SignIn,
        expect.any(Object)
      );
    });

    test('should handle passwordlessSignInComplete API error', async () => {
      mockAuthApi.passwordlessSignInComplete.mockRejectedValueOnce(new Error('Invalid code'));

      const payload = { challenge_id: 'challenge-123', code: '123456' };

      await expect(authService.passwordlessSignInComplete(payload)).rejects.toThrow('Invalid code');
    });
  });

  describe('logOut', () => {
    test('should handle logout failure', async () => {
      mockAuthApi.logOut.mockResolvedValueOnce({ status: 'error' });

      await expect(authService.logOut()).rejects.toThrow('Logout failed');
    });
  });

  describe('sendPasswordResetEmail', () => {
    test('should send password reset email', async () => {
      const payload = { email: 'test@example.com' };

      await authService.sendPasswordResetEmail(payload);

      expect(mockAuthApi.sendPasswordResetEmail).toHaveBeenCalledWith(payload);
    });

    test('should handle sendPasswordResetEmail API error', async () => {
      mockAuthApi.sendPasswordResetEmail.mockRejectedValueOnce(new Error('Email not found'));

      const payload = { email: 'test@example.com' };

      await expect(authService.sendPasswordResetEmail(payload)).rejects.toThrow('Email not found');
    });
  });

  describe('resetPassword', () => {
    test('should reset password successfully', async () => {
      await authService.resetPassword('newPassword123');

      expect(mockAuthApi.resetPassword).toHaveBeenCalledWith('newPassword123', mockScopes, undefined);
      expect(mockStorageManager.saveTokens).toHaveBeenCalled();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.SignIn,
        expect.any(Object)
      );
    });

    test('should handle resetPassword API error', async () => {
      mockAuthApi.resetPassword.mockRejectedValueOnce(new Error('Invalid reset token'));

      await expect(authService.resetPassword('newPassword123')).rejects.toThrow('Invalid reset token');
    });
  });

  describe('passkeyRegister', () => {
    test('should register passkey successfully', async () => {
      const payload = { email: 'test@example.com' };

      await authService.passkeyRegister(payload);

      expect(mockAuthApi.passkeyRegisterStart).toHaveBeenCalled();
      expect(mockAuthApi.passkeyRegisterComplete).toHaveBeenCalled();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Register,
        expect.any(Object)
      );
    });

    test('should handle passkeyRegister API error', async () => {
      mockAuthApi.passkeyRegisterStart.mockRejectedValueOnce(new Error('WebAuthn not supported'));

      const payload = { email: 'test@example.com' };

      await expect(authService.passkeyRegister(payload)).rejects.toThrow('WebAuthn not supported');
    });
  });

  describe('passkeyAuthenticate', () => {
    test('should authenticate with passkey successfully', async () => {
      const payload = { email: 'test@example.com' };

      await authService.passkeyAuthenticate(payload);

      expect(mockAuthApi.passkeyAuthenticateStart).toHaveBeenCalled();
      expect(mockAuthApi.passkeyAuthenticateComplete).toHaveBeenCalled();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.SignIn,
        expect.any(Object)
      );
    });

    test('should handle passkeyAuthenticate API error', async () => {
      mockAuthApi.passkeyAuthenticateStart.mockRejectedValueOnce(new Error('Passkey not found'));

      const payload = { email: 'test@example.com' };

      await expect(authService.passkeyAuthenticate(payload)).rejects.toThrow('Passkey not found');
    });
  });

  describe('submitSessionCheck', () => {
    test('should call createSession callback when tokens exist', async () => {
      const createSession = vi.fn();
      const expiredSession = vi.fn();

      // Create a new auth service with callbacks
      const authServiceWithCallbacks = new AuthService(
        mockAuthApi as unknown as AuthAPI,
        mockDeviceService as unknown as DeviceService,
        mockStorageManager as unknown as StorageManager,
        mockSubscribeStore as unknown as PassflowStore,
        mockTokenCacheService as unknown as TokenCacheService,
        mockScopes,
        true,
        mockOrigin,
        mockUrl,
        { createSession, expiredSession },
        mockAppId,
      );

      await authServiceWithCallbacks.submitSessionCheck();

      expect(createSession).toHaveBeenCalledWith({
        tokens: mockTokens,
        parsedTokens: mockParsedTokens,
      });
      expect(expiredSession).not.toHaveBeenCalled();
    });

    test('should call expiredSession callback when no tokens', async () => {
      mockStorageManager.getTokens.mockReturnValue(undefined);
      const createSession = vi.fn();
      const expiredSession = vi.fn();

      const authServiceWithCallbacks = new AuthService(
        mockAuthApi as unknown as AuthAPI,
        mockDeviceService as unknown as DeviceService,
        mockStorageManager as unknown as StorageManager,
        mockSubscribeStore as unknown as PassflowStore,
        mockTokenCacheService as unknown as TokenCacheService,
        mockScopes,
        true,
        mockOrigin,
        mockUrl,
        { createSession, expiredSession },
        mockAppId,
      );

      await authServiceWithCallbacks.submitSessionCheck();

      expect(expiredSession).toHaveBeenCalled();
      expect(createSession).not.toHaveBeenCalled();
    });
  });

  describe('getTokens with refresh', () => {
    test('should refresh expired tokens when doRefresh is true', async () => {
      vi.mocked(isTokenExpired).mockReturnValue(true);

      await authService.getTokens(true);

      expect(mockAuthApi.refreshToken).toHaveBeenCalled();
    });

    test('should return undefined for expired tokens when doRefresh is false', async () => {
      vi.mocked(isTokenExpired).mockReturnValue(true);

      const result = await authService.getTokens(false);

      expect(result).toBeUndefined();
      expect(mockAuthApi.refreshToken).not.toHaveBeenCalled();
    });

    test('should handle getTokens error gracefully', async () => {
      mockStorageManager.getTokens.mockImplementation(() => {
        throw new Error('Storage error');
      });

      const result = await authService.getTokens(false);

      expect(result).toBeUndefined();
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({ message: 'Storage error' })
      );
    });
  });

  describe('isAuthenticated error handling', () => {
    test('should return false and emit error on exception', () => {
      vi.mocked(isTokenExpired).mockImplementation(() => {
        throw new Error('Token parsing error');
      });

      const result = authService.isAuthenticated(mockParsedTokens);

      expect(result).toBe(false);
      expect(mockSubscribeStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({ message: 'Token parsing error' })
      );
    });
  });

  describe('createFederatedAuthUrl', () => {
    test('should create correct federated auth URL', () => {
      const payload = { provider: 'google' };

      const url = authService.createFederatedAuthUrl(payload);

      expect(url).toContain('/auth/federated/start/google');
      expect(url).toContain('appId=test-app-id');
      expect(url).toContain('scopes=profile%20email');
    });

    test('should include invite_token when provided', () => {
      const payload = { provider: 'google', invite_token: 'invite-123' };

      const url = authService.createFederatedAuthUrl(payload);

      expect(url).toContain('invite_token=invite-123');
    });
  });
});
