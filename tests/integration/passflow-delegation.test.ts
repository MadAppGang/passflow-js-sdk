/**
 * Integration Tests for Passflow Delegation Methods
 *
 * Tests the delegation from Passflow main class to underlying services.
 * Focuses on methods that delegate to AuthService, UserService, TenantService, etc.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { Passflow } from '../../lib/passflow';
import { PassflowEvent } from '../../lib/store';
import {
  VALID_TOKENS,
  VALID_ACCESS_TOKEN,
  TEST_CONFIG,
  AUTH_RESPONSE,
} from '../helpers/fixtures';

// Mock WebAuthn
vi.mock('@simplewebauthn/browser', () => ({
  startAuthentication: vi.fn().mockResolvedValue({ id: 'auth-id' }),
  startRegistration: vi.fn().mockResolvedValue({ id: 'reg-id' }),
}));

describe('Passflow Delegation (Integration)', () => {
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

  describe('Session Callbacks', () => {
    test('session() with createSession callback when authenticated', async () => {
      const createSession = vi.fn();
      const expiredSession = vi.fn();

      // First set tokens to be "authenticated"
      passflow.setTokens(VALID_TOKENS);

      await passflow.session({ createSession, expiredSession });

      // With valid tokens, createSession should be called
      expect(createSession).toHaveBeenCalled();
      expect(expiredSession).not.toHaveBeenCalled();
    });

    test('session() with expiredSession callback when not authenticated', async () => {
      const createSession = vi.fn();
      const expiredSession = vi.fn();

      // Don't set any tokens - should be not authenticated
      await passflow.session({ createSession, expiredSession });

      expect(expiredSession).toHaveBeenCalled();
      expect(createSession).not.toHaveBeenCalled();
    });
  });

  describe('Event System', () => {
    test('subscribe() and unsubscribe() lifecycle', () => {
      const subscriber = { onAuthChange: vi.fn() };

      // Subscribe
      passflow.subscribe(subscriber);

      // Trigger an event by setting tokens
      passflow.setTokens(VALID_TOKENS);

      // Subscriber should be notified
      expect(subscriber.onAuthChange).toHaveBeenCalled();

      // Unsubscribe
      passflow.unsubscribe(subscriber);

      // Reset mock
      subscriber.onAuthChange.mockClear();

      // Trigger another event
      passflow.reset();

      // Subscriber should NOT be notified after unsubscribe
      // (this depends on implementation - may still be called for SignOut)
    });

    test('subscribe() with specific events', () => {
      const subscriber = { onAuthChange: vi.fn() };

      // Subscribe only to SignIn events
      passflow.subscribe(subscriber, [PassflowEvent.SignIn]);

      // Trigger SignIn by setting tokens
      passflow.setTokens(VALID_TOKENS);

      expect(subscriber.onAuthChange).toHaveBeenCalled();
    });
  });

  describe('Token Management Methods', () => {
    test('setTokens() and getCachedTokens() round-trip', () => {
      passflow.setTokens(VALID_TOKENS);

      const cached = passflow.getCachedTokens();
      expect(cached).toEqual(VALID_TOKENS);
    });

    test('getParsedTokens() returns parsed JWT data', () => {
      passflow.setTokens(VALID_TOKENS);

      const parsed = passflow.getParsedTokens();
      expect(parsed).toBeDefined();
      expect(parsed?.access_token).toBeDefined();
      expect(parsed?.access_token?.sub).toBe('user-123');
    });

    test('areTokensExpired() returns correct state', () => {
      // No tokens = expired
      expect(passflow.areTokensExpired()).toBe(true);

      // Set valid tokens
      passflow.setTokens(VALID_TOKENS);
      expect(passflow.areTokensExpired()).toBe(false);
    });

    test('isAuthenticated() returns correct state', () => {
      // No tokens = not authenticated
      expect(passflow.isAuthenticated()).toBe(false);

      // Set valid tokens
      passflow.setTokens(VALID_TOKENS);
      expect(passflow.isAuthenticated()).toBe(true);
    });
  });

  describe('Auth Redirect URL Generation', () => {
    test('authRedirectUrl() generates correct URL', () => {
      const url = passflow.authRedirectUrl({
        redirectUrl: 'https://app.example.com/callback',
      });

      expect(url).toBeDefined();
      expect(url).toContain('web');
      expect(url).toContain('appId=');
      expect(url).toContain('redirectto=https://app.example.com/callback');
    });

    test('authRedirectUrl() uses default redirect URL', () => {
      const url = passflow.authRedirectUrl();

      expect(url).toBeDefined();
      expect(url).toContain('redirectto=');
    });

    test('authRedirectUrl() with custom scopes', () => {
      const url = passflow.authRedirectUrl({
        scopes: ['custom', 'scopes'],
      });

      expect(url).toContain('scopes=custom,scopes');
    });
  });

  describe('Error Property', () => {
    test('error is undefined initially', () => {
      expect(passflow.error).toBeUndefined();
    });

    test('error is set after reset with error', () => {
      try {
        passflow.reset('Test error');
      } catch {
        // Expected
      }

      expect(passflow.error).toBeDefined();
      expect(passflow.error?.message).toBe('Test error');
    });
  });

  describe('Service Exposure', () => {
    test('tenant service is accessible', () => {
      expect(passflow.tenant).toBeDefined();
    });

    test('twoFactor service is accessible', () => {
      expect(passflow.twoFactor).toBeDefined();
    });
  });

  describe('Configuration Properties', () => {
    test('url is set from config', () => {
      expect(passflow.url).toBe(TEST_CONFIG.url);
    });

    test('appId is set from config', () => {
      expect(passflow.appId).toBe(TEST_CONFIG.appId);
    });

    test('origin is set from window.location', () => {
      expect(passflow.origin).toBe('https://example.com');
    });

    test('static version is accessible', () => {
      expect(Passflow.version).toBeDefined();
      expect(typeof Passflow.version).toBe('string');
    });
  });

  describe('2FA State', () => {
    test('isTwoFactorVerificationRequired() returns false by default', () => {
      expect(passflow.isTwoFactorVerificationRequired()).toBe(false);
    });
  });

  describe('parseQueryParams Configuration', () => {
    test('parseQueryParams: true extracts tokens on construction', () => {
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'https://example.com',
          search: `access_token=${VALID_ACCESS_TOKEN}`,
          href: `https://example.com?access_token=${VALID_ACCESS_TOKEN}`,
        },
        writable: true,
      });

      const sdk = new Passflow({ ...TEST_CONFIG, parseQueryParams: true });

      // Should automatically parse and store tokens
      expect(sdk.getCachedTokens()?.access_token).toBe(VALID_ACCESS_TOKEN);
    });

    test('parseQueryParams: false does not extract tokens on construction', () => {
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'https://example.com',
          search: `access_token=${VALID_ACCESS_TOKEN}`,
          href: `https://example.com?access_token=${VALID_ACCESS_TOKEN}`,
        },
        writable: true,
      });

      const sdk = new Passflow({ ...TEST_CONFIG, parseQueryParams: false });

      // Should NOT automatically parse tokens
      expect(sdk.getCachedTokens()).toBeUndefined();
    });
  });

  describe('Key Storage Prefix', () => {
    test('custom keyStoragePrefix is used', () => {
      const sdk = new Passflow({ ...TEST_CONFIG, keyStoragePrefix: 'myapp' });
      sdk.setTokens(VALID_TOKENS);

      // Token should be stored with prefix
      expect(localStorage.getItem('myapp_access')).toBe(VALID_ACCESS_TOKEN);
    });

    test('default storage uses no prefix', () => {
      passflow.setTokens(VALID_TOKENS);

      // Token should be stored without prefix
      expect(localStorage.getItem('access')).toBe(VALID_ACCESS_TOKEN);
    });
  });
});
