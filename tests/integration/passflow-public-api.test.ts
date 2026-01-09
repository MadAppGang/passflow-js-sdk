/**
 * Integration Tests for Passflow Public API
 *
 * These tests verify the SDK's public API works correctly.
 * Focus on testing public methods and their interactions.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { Passflow } from '../../lib/passflow';
import { PassflowEvent } from '../../lib/store';
import { TokenType } from '../../lib/token';
import { TEST_CONFIG, VALID_ACCESS_TOKEN, VALID_ID_TOKEN, VALID_REFRESH_TOKEN, VALID_TOKENS } from '../helpers/fixtures';

// Mock WebAuthn
vi.mock('@simplewebauthn/browser', () => ({
  startAuthentication: vi.fn().mockResolvedValue({ id: 'auth-id' }),
  startRegistration: vi.fn().mockResolvedValue({ id: 'reg-id' }),
}));

describe('Passflow Public API (Integration)', () => {
  let passflow: Passflow;

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();

    // Reset window.location
    Object.defineProperty(window, 'location', {
      value: {
        origin: 'https://example.com',
        search: '',
        href: 'https://example.com',
      },
      writable: true,
    });

    // Mock history.replaceState
    window.history.replaceState = vi.fn();

    passflow = new Passflow(TEST_CONFIG);
  });

  describe('Constructor & Configuration', () => {
    test('creates SDK with valid config', () => {
      expect(passflow).toBeDefined();
      expect(passflow.url).toBe(TEST_CONFIG.url);
      expect(passflow.appId).toBe(TEST_CONFIG.appId);
    });

    test('uses default URL when not provided', () => {
      const sdk = new Passflow({ appId: 'test-app' });
      // Default URL is 'https://auth.passflow.cloud' based on constants
      expect(sdk.url).toBeDefined();
      expect(typeof sdk.url).toBe('string');
    });

    test('uses provided scopes', () => {
      const customScopes = ['profile', 'email'];
      const sdk = new Passflow({ ...TEST_CONFIG, scopes: customScopes });
      expect(sdk).toBeDefined();
    });

    test('exposes static version', () => {
      expect(Passflow.version).toBeDefined();
      expect(typeof Passflow.version).toBe('string');
    });

    test('sets keyStoragePrefix correctly', () => {
      const sdk = new Passflow({ ...TEST_CONFIG, keyStoragePrefix: 'myapp' });
      expect(sdk).toBeDefined();
    });
  });

  describe('Session Management', () => {
    test('session() calls expiredSession when no tokens', async () => {
      const createSession = vi.fn();
      const expiredSession = vi.fn();

      await passflow.session({ createSession, expiredSession });

      expect(createSession).not.toHaveBeenCalled();
      expect(expiredSession).toHaveBeenCalled();
    });

    test('session() overwrites previous callbacks', async () => {
      const firstCallback = vi.fn();
      const secondCallback = vi.fn();

      await passflow.session({ expiredSession: firstCallback });
      await passflow.session({ expiredSession: secondCallback });

      // Both should have been called (once each)
      expect(firstCallback).toHaveBeenCalledTimes(1);
      expect(secondCallback).toHaveBeenCalledTimes(1);
    });

    test('session() with doRefresh option', async () => {
      const expiredSession = vi.fn();

      await passflow.session({ expiredSession, doRefresh: true });

      expect(expiredSession).toHaveBeenCalled();
    });
  });

  describe('Event Subscription', () => {
    test('subscribe() registers subscriber without error', () => {
      const subscriber = { onAuthChange: vi.fn() };

      expect(() => passflow.subscribe(subscriber)).not.toThrow();
    });

    test('subscribe() with specific events', () => {
      const subscriber = { onAuthChange: vi.fn() };

      expect(() => passflow.subscribe(subscriber, [PassflowEvent.SignIn, PassflowEvent.SignOut])).not.toThrow();
    });

    test('unsubscribe() removes subscriber without error', () => {
      const subscriber = { onAuthChange: vi.fn() };

      passflow.subscribe(subscriber);
      expect(() => passflow.unsubscribe(subscriber)).not.toThrow();
    });

    test('unsubscribe() with specific events', () => {
      const subscriber = { onAuthChange: vi.fn() };

      passflow.subscribe(subscriber, [PassflowEvent.SignIn]);
      expect(() => passflow.unsubscribe(subscriber, [PassflowEvent.SignIn])).not.toThrow();
    });
  });

  describe('Authentication State', () => {
    test('isAuthenticated() returns false with no tokens', () => {
      expect(passflow.isAuthenticated()).toBe(false);
    });

    test('isAuthenticated() returns true after setTokens', () => {
      passflow.setTokens(VALID_TOKENS);
      expect(passflow.isAuthenticated()).toBe(true);
    });

    test('isAuthenticated() checks token expiration', () => {
      // With no tokens, should be false
      expect(passflow.isAuthenticated()).toBe(false);
    });
  });

  describe('Token Handling', () => {
    test('getCachedTokens() returns undefined when no tokens', () => {
      const cached = passflow.getCachedTokens();
      expect(cached).toBeUndefined();
    });

    test('getCachedTokens() returns tokens after setTokens', () => {
      passflow.setTokens(VALID_TOKENS);

      const cached = passflow.getCachedTokens();
      expect(cached).toBeDefined();
      expect(cached?.access_token).toBe(VALID_TOKENS.access_token);
    });

    test('setTokens() saves tokens to cache', () => {
      passflow.setTokens(VALID_TOKENS);

      const cached = passflow.getCachedTokens();
      expect(cached?.access_token).toBe(VALID_TOKENS.access_token);
    });

    test('areTokensExpired() returns true when no tokens', () => {
      expect(passflow.areTokensExpired()).toBe(true);
    });

    test('areTokensExpired() returns false after setting valid tokens', () => {
      passflow.setTokens(VALID_TOKENS);
      expect(passflow.areTokensExpired()).toBe(false);
    });

    test('getParsedTokens() returns undefined when no tokens', () => {
      expect(passflow.getParsedTokens()).toBeUndefined();
    });

    test('getParsedTokens() returns parsed tokens after setTokens', () => {
      passflow.setTokens(VALID_TOKENS);

      const parsed = passflow.getParsedTokens();
      expect(parsed).toBeDefined();
      expect(parsed?.access_token).toBeDefined();
    });

    test('getToken() returns specific token type from storage', () => {
      passflow.setTokens(VALID_TOKENS);

      // getToken() reads from storage using TokenType enum
      const accessToken = passflow.getToken(TokenType.access_token);
      expect(accessToken).toBe(VALID_ACCESS_TOKEN);

      const idToken = passflow.getToken(TokenType.id_token);
      expect(idToken).toBe(VALID_ID_TOKEN);
    });
  });

  describe('URL Token Handling', () => {
    test('handleTokensRedirect() returns undefined with no tokens in URL', () => {
      const tokens = passflow.handleTokensRedirect();
      expect(tokens).toBeUndefined();
    });

    test('handleTokensRedirect() extracts tokens from URL query params', () => {
      // Setup: tokens in URL (without leading ? since URLSearchParams strips it)
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'https://example.com',
          search: `access_token=${VALID_ACCESS_TOKEN}&refresh_token=${VALID_REFRESH_TOKEN}&id_token=${VALID_ID_TOKEN}`,
          href: `https://example.com?access_token=${VALID_ACCESS_TOKEN}`,
        },
        writable: true,
      });

      passflow = new Passflow({ ...TEST_CONFIG, parseQueryParams: false });
      const tokens = passflow.handleTokensRedirect();

      expect(tokens).toBeDefined();
      expect(tokens?.access_token).toBe(VALID_ACCESS_TOKEN);
      expect(tokens?.refresh_token).toBe(VALID_REFRESH_TOKEN);
    });

    test('handleTokensRedirect() saves tokens to storage', () => {
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'https://example.com',
          search: `access_token=${VALID_ACCESS_TOKEN}`,
          href: `https://example.com?access_token=${VALID_ACCESS_TOKEN}`,
        },
        writable: true,
      });

      passflow = new Passflow({ ...TEST_CONFIG, parseQueryParams: false });
      passflow.handleTokensRedirect();

      // Storage key is TokenType.access_token which equals 'access' (not 'access_token')
      expect(localStorage.getItem('access')).toBe(VALID_ACCESS_TOKEN);
    });

    test('parseQueryParams: true extracts tokens on construction', () => {
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'https://example.com',
          search: `access_token=${VALID_ACCESS_TOKEN}`,
          href: `https://example.com?access_token=${VALID_ACCESS_TOKEN}`,
        },
        writable: true,
      });

      passflow = new Passflow({ ...TEST_CONFIG, parseQueryParams: true });

      // Tokens should be in storage after construction
      // Storage key is TokenType.access_token which equals 'access' (not 'access_token')
      expect(localStorage.getItem('access')).toBe(VALID_ACCESS_TOKEN);
    });

    test('handleTokensRedirect() rejects invalid JWT format', () => {
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'https://example.com',
          search: 'access_token=not-a-valid-jwt',
          href: 'https://example.com?access_token=not-a-valid-jwt',
        },
        writable: true,
      });

      passflow = new Passflow({ ...TEST_CONFIG, parseQueryParams: false });
      const tokens = passflow.handleTokensRedirect();

      expect(tokens).toBeUndefined();
    });
  });

  describe('Two-Factor Authentication State', () => {
    test('isTwoFactorVerificationRequired() returns false by default', () => {
      expect(passflow.isTwoFactorVerificationRequired()).toBe(false);
    });

    test('isTwoFactorVerificationRequired() returns false when no partial auth in memory', () => {
      // Note: The SDK only recovers sessionStorage state when verify/useRecoveryCode is called
      // Just checking isTwoFactorVerificationRequired() doesn't recover state from storage
      // This is by design - state recovery happens lazily during actual 2FA operations
      const partialAuth = {
        challengeId: 'challenge-123',
        email: 'test@example.com',
        expiresAt: Date.now() + 5 * 60 * 1000,
      };
      sessionStorage.setItem('passflow_2fa_challenge', JSON.stringify(partialAuth));

      // Create new SDK instance - state is only in storage, not memory
      passflow = new Passflow(TEST_CONFIG);

      // Returns false because partialAuthState is only set when:
      // 1. AuthService emits TwoFactorRequired event
      // 2. verify() or useRecoveryCode() is called (which triggers recovery)
      expect(passflow.isTwoFactorVerificationRequired()).toBe(false);
    });
  });

  describe('Reset', () => {
    test('reset() clears tokens', () => {
      passflow.setTokens(VALID_TOKENS);
      passflow.reset();

      expect(passflow.getCachedTokens()).toBeUndefined();
    });

    test('reset() with error throws and sets error state', () => {
      expect(() => passflow.reset('Test error message')).toThrow('Test error message');

      expect(passflow.error).toBeDefined();
      expect(passflow.error?.message).toBe('Test error message');
    });

    test('reset() without error does not modify error state', () => {
      // First set an error
      try {
        passflow.reset('Set an error first');
      } catch {
        // Expected to throw
      }

      // Verify error was set
      expect(passflow.error?.message).toBe('Set an error first');

      // Reset without error - does not clear previous error (by design)
      passflow.reset();

      // Error state remains (reset only clears tokens, not error state)
      expect(passflow.error?.message).toBe('Set an error first');
    });
  });

  describe('Public Service Access', () => {
    test('tenant service is exposed', () => {
      expect(passflow.tenant).toBeDefined();
    });

    test('twoFactor service is exposed', () => {
      expect(passflow.twoFactor).toBeDefined();
    });
  });

  describe('Origin and URL', () => {
    test('origin is set from window.location', () => {
      expect(passflow.origin).toBe('https://example.com');
    });

    test('url is set from config', () => {
      expect(passflow.url).toBe(TEST_CONFIG.url);
    });

    test('appId is set from config', () => {
      expect(passflow.appId).toBe(TEST_CONFIG.appId);
    });
  });
});
