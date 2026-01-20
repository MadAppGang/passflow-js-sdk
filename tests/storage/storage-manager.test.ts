/// <reference types="vitest" />

import type { Mock } from 'vitest';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { StorageManager } from '../../lib/storage/index';
import { TokenType } from '../../lib/token/token';
import { TokenDeliveryMode } from '../../lib/types';
import { FakeStorage } from './fake-storage';

// Create a type for our mock functions
type MockFn = Mock & { mockReset: () => void };

describe('storage manager', () => {
  let storageManager: StorageManager;
  let fakeStorage: FakeStorage;
  let getSpy: MockFn;
  let setSpy: MockFn;
  let removeSpy: MockFn;

  beforeEach(() => {
    fakeStorage = new FakeStorage();
    storageManager = new StorageManager({ storage: fakeStorage });
    getSpy = vi.spyOn(fakeStorage, 'getItem') as MockFn;
    setSpy = vi.spyOn(fakeStorage, 'setItem') as MockFn;
    removeSpy = vi.spyOn(fakeStorage, 'removeItem') as MockFn;
  });

  afterEach(() => {
    vi.clearAllMocks();
    getSpy.mockReset();
    setSpy.mockReset();
    removeSpy.mockReset();
  });

  describe('managing tokens', () => {
    test('should get null, no tokens exists', () => {
      const token = storageManager.getToken(TokenType.access_token);
      expect(token).toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(1);
    });

    test('should get token', () => {
      storageManager.saveTokens({ access_token: 'access' });
      let token = storageManager.getToken(TokenType.access_token);
      expect(token).not.toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(1);
      expect(setSpy).toHaveBeenCalledTimes(1);
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(2);
      expect(setSpy).toHaveBeenCalledTimes(1);
      token = storageManager.getToken(TokenType.id_token);
      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
    });

    test('should get null for unsupported token type', () => {
      storageManager.saveTokens({ access_token: 'access' });
      const token = storageManager.getToken(TokenType.reset_token);
      expect(token).toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(1);
      expect(setSpy).toHaveBeenCalledTimes(1);
    });

    test('delete all tokens', () => {
      storageManager.saveTokens({
        access_token: 'access',
        id_token: 'id',
        refresh_token: 'refresh',
      });

      let token = storageManager.getToken(TokenType.access_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).not.toBeUndefined();

      storageManager.deleteTokens();
      token = storageManager.getToken(TokenType.access_token);
      expect(token).toBeUndefined();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).toBeUndefined();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).toBeUndefined();

      expect(getSpy).toHaveBeenCalledTimes(6);
      expect(setSpy).toHaveBeenCalledTimes(3);
      // deleteTokens now also clears cookie mode ID token (5 removals instead of 4)
      expect(removeSpy).toHaveBeenCalledTimes(5);
    });

    test('delete one tokens', () => {
      storageManager.saveTokens({
        access_token: 'access',
        id_token: 'id',
        refresh_token: 'refresh',
      });

      let token = storageManager.getToken(TokenType.access_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).not.toBeUndefined();

      storageManager.deleteToken(TokenType.id_token);
      token = storageManager.getToken(TokenType.access_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).toBeUndefined();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.reset_token);
      expect(token).toBeUndefined();

      expect(getSpy).toHaveBeenCalledTimes(7);
      expect(setSpy).toHaveBeenCalledTimes(3);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });

    test('get tokens test', () => {
      storageManager.saveTokens({
        access_token: 'access',
        id_token: 'id',
        refresh_token: 'refresh',
        scopes: ['scope1', 'scope2'],
      });
      const tokens = storageManager.getTokens();
      expect(tokens).not.toBeUndefined();
      expect(tokens?.access_token).not.toBeUndefined();
      expect(tokens?.id_token).not.toBeUndefined();
      expect(tokens?.refresh_token).not.toBeUndefined();
      expect(tokens?.scopes).not.toBeUndefined();
      // getTokens now also checks delivery mode (5 gets instead of 4)
      expect(getSpy).toHaveBeenCalledTimes(5);
      expect(setSpy).toHaveBeenCalledTimes(4);
      expect(removeSpy).toHaveBeenCalledTimes(0);
    });
  });

  describe('managing additional storage data', () => {
    test('get device id', () => {
      const did = storageManager.getDeviceId();
      expect(did).toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(1);
    });

    test('set device id', () => {
      let did = storageManager.getDeviceId();
      expect(did).toBeUndefined();

      storageManager.setDeviceId('device-1234');
      did = storageManager.getDeviceId();
      expect(did).not.toBeUndefined();

      storageManager.deleteDeviceId();
      did = storageManager.getDeviceId();
      expect(did).toBeUndefined();

      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });

    test('persist invitation token', () => {
      let invitation = storageManager.getInvitationToken();
      expect(invitation).toBeUndefined();

      storageManager.setInvitationToken('invitation-tokne-1234');
      invitation = storageManager.getInvitationToken();
      expect(invitation).not.toBeUndefined();

      storageManager.deleteInvitationToken();
      invitation = storageManager.getInvitationToken();
      expect(invitation).toBeUndefined();

      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });

    test('persist redirection url', () => {
      let redirectUrl = storageManager.getPreviousRedirectUrl();
      expect(redirectUrl).toBeUndefined();

      storageManager.setPreviousRedirectUrl('redirect-url-1234');
      redirectUrl = storageManager.getPreviousRedirectUrl();
      expect(redirectUrl).not.toBeUndefined();

      storageManager.deletePreviousRedirectUrl();
      redirectUrl = storageManager.getPreviousRedirectUrl();
      expect(redirectUrl).toBeUndefined();

      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe('cookie mode support', () => {
    describe('conditional token storage', () => {
      test('should save only ID token in cookie mode', () => {
        storageManager.saveTokens(
          {
            access_token: 'access123',
            id_token: 'id123',
            refresh_token: 'refresh123',
          },
          TokenDeliveryMode.Cookie,
        );

        // ID token should be saved with namespaced key
        const idToken = storageManager.getIdToken();
        expect(idToken).toBe('id123');

        // Access and refresh tokens should NOT be saved
        const accessToken = storageManager.getToken(TokenType.access_token);
        const refreshToken = storageManager.getToken(TokenType.refresh_token);
        expect(accessToken).toBeUndefined();
        expect(refreshToken).toBeUndefined();
      });

      test('should save all tokens in JSON mode', () => {
        storageManager.saveTokens(
          {
            access_token: 'access123',
            id_token: 'id123',
            refresh_token: 'refresh123',
          },
          TokenDeliveryMode.JsonBody,
        );

        // All tokens should be saved
        const accessToken = storageManager.getToken(TokenType.access_token);
        const idToken = storageManager.getToken(TokenType.id_token);
        const refreshToken = storageManager.getToken(TokenType.refresh_token);
        expect(accessToken).toBe('access123');
        expect(idToken).toBe('id123');
        expect(refreshToken).toBe('refresh123');
      });

      test('should save all tokens when no delivery mode specified (default)', () => {
        storageManager.saveTokens({
          access_token: 'access123',
          id_token: 'id123',
          refresh_token: 'refresh123',
        });

        // All tokens should be saved (backward compatibility)
        const accessToken = storageManager.getToken(TokenType.access_token);
        const idToken = storageManager.getToken(TokenType.id_token);
        const refreshToken = storageManager.getToken(TokenType.refresh_token);
        expect(accessToken).toBe('access123');
        expect(idToken).toBe('id123');
        expect(refreshToken).toBe('refresh123');
      });
    });

    describe('conditional token retrieval', () => {
      test('should return only ID token in cookie mode', () => {
        // Set delivery mode to cookie
        storageManager.setDeliveryMode(TokenDeliveryMode.Cookie);

        // Save ID token
        storageManager.setIdToken('id123');

        // Get tokens
        const tokens = storageManager.getTokens();
        expect(tokens).toBeDefined();
        expect(tokens?.id_token).toBe('id123');
        expect(tokens?.access_token).toBeUndefined(); // Cookie mode: access_token not in localStorage
      });

      test('should return all tokens in JSON mode', () => {
        // Set delivery mode to JSON
        storageManager.setDeliveryMode(TokenDeliveryMode.JsonBody);

        // Save all tokens
        storageManager.saveTokens({
          access_token: 'access123',
          id_token: 'id123',
          refresh_token: 'refresh123',
        });

        // Get tokens
        const tokens = storageManager.getTokens();
        expect(tokens).toBeDefined();
        expect(tokens?.access_token).toBe('access123');
        expect(tokens?.id_token).toBe('id123');
        expect(tokens?.refresh_token).toBe('refresh123');
      });

      test('should return undefined when no ID token in cookie mode', () => {
        // Set delivery mode to cookie
        storageManager.setDeliveryMode(TokenDeliveryMode.Cookie);

        // Get tokens without saving any
        const tokens = storageManager.getTokens();
        expect(tokens).toBeUndefined();
      });
    });

    describe('delivery mode persistence', () => {
      test('should set and get delivery mode', () => {
        storageManager.setDeliveryMode(TokenDeliveryMode.Cookie);
        const mode = storageManager.getDeliveryMode();
        expect(mode).toBe(TokenDeliveryMode.Cookie);
      });

      test('should clear delivery mode', () => {
        storageManager.setDeliveryMode(TokenDeliveryMode.Cookie);
        expect(storageManager.getDeliveryMode()).toBe(TokenDeliveryMode.Cookie);

        storageManager.clearDeliveryMode();
        expect(storageManager.getDeliveryMode()).toBeUndefined();
      });

      test('should return undefined for invalid delivery mode', () => {
        // Manually set invalid mode in storage
        fakeStorage.setItem('passflow_delivery_mode', 'invalid_mode');
        const mode = storageManager.getDeliveryMode();
        expect(mode).toBeUndefined();
      });

      test('should persist across instances', () => {
        storageManager.setDeliveryMode(TokenDeliveryMode.Mobile);

        // Create new instance with same storage
        const newStorageManager = new StorageManager({ storage: fakeStorage });
        const mode = newStorageManager.getDeliveryMode();
        expect(mode).toBe(TokenDeliveryMode.Mobile);
      });
    });

    describe('ID token methods', () => {
      test('should set and get ID token', () => {
        storageManager.setIdToken('id_token_123');
        const token = storageManager.getIdToken();
        expect(token).toBe('id_token_123');
      });

      test('should clear ID token', () => {
        storageManager.setIdToken('id_token_123');
        expect(storageManager.getIdToken()).toBe('id_token_123');

        storageManager.clearIdToken();
        expect(storageManager.getIdToken()).toBeUndefined();
      });

      test('should use namespaced key', () => {
        storageManager.setIdToken('id_token_123');
        const directValue = fakeStorage.getItem('passflow_id_token');
        expect(directValue).toBe('id_token_123');
      });

      test('should be cleared by deleteTokens', () => {
        storageManager.setIdToken('id_token_123');
        storageManager.deleteTokens();
        expect(storageManager.getIdToken()).toBeUndefined();
      });
    });

    describe('CSRF token methods', () => {
      test('should set and get CSRF token', () => {
        storageManager.setCsrfToken('csrf_123');
        const token = storageManager.getCsrfToken();
        expect(token).toBe('csrf_123');
      });

      test('should clear CSRF token', () => {
        storageManager.setCsrfToken('csrf_123');
        expect(storageManager.getCsrfToken()).toBe('csrf_123');

        storageManager.clearCsrfToken();
        expect(storageManager.getCsrfToken()).toBeUndefined();
      });

      test('should use namespaced key', () => {
        storageManager.setCsrfToken('csrf_123');
        const directValue = fakeStorage.getItem('passflow_csrf_token');
        expect(directValue).toBe('csrf_123');
      });

      test('should persist across instances', () => {
        storageManager.setCsrfToken('csrf_123');

        // Create new instance with same storage
        const newStorageManager = new StorageManager({ storage: fakeStorage });
        const token = newStorageManager.getCsrfToken();
        expect(token).toBe('csrf_123');
      });
    });

    describe('storage key namespacing', () => {
      test('should use passflow_ prefix for all new keys', () => {
        storageManager.setDeliveryMode(TokenDeliveryMode.Cookie);
        storageManager.setIdToken('id123');
        storageManager.setCsrfToken('csrf123');

        expect(fakeStorage.getItem('passflow_delivery_mode')).toBe('cookie');
        expect(fakeStorage.getItem('passflow_id_token')).toBe('id123');
        expect(fakeStorage.getItem('passflow_csrf_token')).toBe('csrf123');
      });

      test('should not conflict with existing keys', () => {
        // Save tokens normally
        storageManager.saveTokens({
          access_token: 'access123',
          id_token: 'id123',
        });

        // Save cookie mode ID token
        storageManager.setIdToken('id_cookie');

        // Both should exist independently
        const jsonIdToken = storageManager.getToken(TokenType.id_token);
        const cookieIdToken = storageManager.getIdToken();
        expect(jsonIdToken).toBe('id123');
        expect(cookieIdToken).toBe('id_cookie');
      });
    });
  });
});
