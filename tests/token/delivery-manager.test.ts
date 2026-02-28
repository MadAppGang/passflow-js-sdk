/// <reference types="vitest" />

import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { StorageManager } from '../../lib/storage/index';
import { SessionState, TokenDeliveryManager, TokenDeliveryMode } from '../../lib/token/delivery-manager';
import { FakeStorage } from '../storage/fake-storage';

describe('TokenDeliveryManager', () => {
  let storageManager: StorageManager;
  let fakeStorage: FakeStorage;
  let deliveryManager: TokenDeliveryManager;

  beforeEach(() => {
    fakeStorage = new FakeStorage();
    storageManager = new StorageManager({ storage: fakeStorage });
    deliveryManager = new TokenDeliveryManager(storageManager);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('initialization', () => {
    test('should default to JsonBody mode', () => {
      expect(deliveryManager.getMode()).toBe(TokenDeliveryMode.JsonBody);
      expect(deliveryManager.isJsonMode()).toBe(true);
      expect(deliveryManager.isCookieMode()).toBe(false);
      expect(deliveryManager.isMobileMode()).toBe(false);
    });

    test('should default to Unknown session state', () => {
      expect(deliveryManager.getSessionState()).toBe(SessionState.Unknown);
      expect(deliveryManager.isSessionUnknown()).toBe(true);
      expect(deliveryManager.isSessionValid()).toBe(false);
      expect(deliveryManager.isSessionInvalid()).toBe(false);
    });

    test('should not be initialized on construction', () => {
      expect(deliveryManager.isInitialized()).toBe(false);
    });

    test('should load persisted mode from storage', () => {
      fakeStorage.setItem('passflow_delivery_mode', TokenDeliveryMode.Cookie);
      const newManager = new TokenDeliveryManager(storageManager);
      expect(newManager.getMode()).toBe(TokenDeliveryMode.Cookie);
      expect(newManager.isCookieMode()).toBe(true);
      expect(newManager.isInitialized()).toBe(true);
    });

    test('should load persisted session state from storage', () => {
      fakeStorage.setItem('passflow_session_state', SessionState.Valid);
      const newManager = new TokenDeliveryManager(storageManager);
      expect(newManager.getSessionState()).toBe(SessionState.Valid);
      expect(newManager.isSessionValid()).toBe(true);
    });

    test('should ignore invalid persisted mode', () => {
      fakeStorage.setItem('passflow_delivery_mode', 'invalid_mode');
      const newManager = new TokenDeliveryManager(storageManager);
      expect(newManager.getMode()).toBe(TokenDeliveryMode.JsonBody);
      expect(newManager.isInitialized()).toBe(false);
    });

    test('should ignore invalid persisted session state', () => {
      fakeStorage.setItem('passflow_session_state', 'invalid_state');
      const newManager = new TokenDeliveryManager(storageManager);
      expect(newManager.getSessionState()).toBe(SessionState.Unknown);
    });
  });

  describe('mode management', () => {
    test('should set and get mode', () => {
      deliveryManager.setMode(TokenDeliveryMode.Cookie);
      expect(deliveryManager.getMode()).toBe(TokenDeliveryMode.Cookie);
      expect(deliveryManager.isCookieMode()).toBe(true);
      expect(deliveryManager.isJsonMode()).toBe(false);
    });

    test('should set initialized flag when mode is set', () => {
      expect(deliveryManager.isInitialized()).toBe(false);
      deliveryManager.setMode(TokenDeliveryMode.Cookie);
      expect(deliveryManager.isInitialized()).toBe(true);
    });

    test('should persist mode to storage when set', () => {
      deliveryManager.setMode(TokenDeliveryMode.Cookie);
      expect(fakeStorage.getItem('passflow_delivery_mode')).toBe(TokenDeliveryMode.Cookie);
    });

    test('should support all delivery modes', () => {
      deliveryManager.setMode(TokenDeliveryMode.JsonBody);
      expect(deliveryManager.isJsonMode()).toBe(true);

      deliveryManager.setMode(TokenDeliveryMode.Cookie);
      expect(deliveryManager.isCookieMode()).toBe(true);

      deliveryManager.setMode(TokenDeliveryMode.Mobile);
      expect(deliveryManager.isMobileMode()).toBe(true);
    });
  });

  describe('session state management', () => {
    test('should set session valid', () => {
      deliveryManager.setSessionValid();
      expect(deliveryManager.getSessionState()).toBe(SessionState.Valid);
      expect(deliveryManager.isSessionValid()).toBe(true);
      expect(deliveryManager.isSessionUnknown()).toBe(false);
      expect(deliveryManager.isSessionInvalid()).toBe(false);
    });

    test('should set session invalid', () => {
      deliveryManager.setSessionInvalid();
      expect(deliveryManager.getSessionState()).toBe(SessionState.Invalid);
      expect(deliveryManager.isSessionInvalid()).toBe(true);
      expect(deliveryManager.isSessionValid()).toBe(false);
      expect(deliveryManager.isSessionUnknown()).toBe(false);
    });

    test('should set session unknown', () => {
      deliveryManager.setSessionValid();
      deliveryManager.setSessionUnknown();
      expect(deliveryManager.getSessionState()).toBe(SessionState.Unknown);
      expect(deliveryManager.isSessionUnknown()).toBe(true);
      expect(deliveryManager.isSessionValid()).toBe(false);
    });

    test('should persist session state to storage', () => {
      deliveryManager.setSessionValid();
      expect(fakeStorage.getItem('passflow_session_state')).toBe(SessionState.Valid);

      deliveryManager.setSessionInvalid();
      expect(fakeStorage.getItem('passflow_session_state')).toBe(SessionState.Invalid);

      deliveryManager.setSessionUnknown();
      expect(fakeStorage.getItem('passflow_session_state')).toBe(SessionState.Unknown);
    });

    test('should handle session state transitions', () => {
      // Unknown -> Valid
      expect(deliveryManager.isSessionUnknown()).toBe(true);
      deliveryManager.setSessionValid();
      expect(deliveryManager.isSessionValid()).toBe(true);

      // Valid -> Invalid
      deliveryManager.setSessionInvalid();
      expect(deliveryManager.isSessionInvalid()).toBe(true);

      // Invalid -> Valid
      deliveryManager.setSessionValid();
      expect(deliveryManager.isSessionValid()).toBe(true);
    });
  });

  describe('reset functionality', () => {
    test('should reset to initial state', () => {
      deliveryManager.setMode(TokenDeliveryMode.Cookie);
      deliveryManager.setSessionValid();

      deliveryManager.reset();

      expect(deliveryManager.getMode()).toBe(TokenDeliveryMode.JsonBody);
      expect(deliveryManager.getSessionState()).toBe(SessionState.Unknown);
      expect(deliveryManager.isInitialized()).toBe(false);
    });

    test('should clear persisted data on reset', () => {
      deliveryManager.setMode(TokenDeliveryMode.Cookie);
      deliveryManager.setSessionValid();

      expect(fakeStorage.getItem('passflow_delivery_mode')).toBe(TokenDeliveryMode.Cookie);
      expect(fakeStorage.getItem('passflow_session_state')).toBe(SessionState.Valid);

      deliveryManager.reset();

      expect(fakeStorage.getItem('passflow_delivery_mode')).toBeNull();
      expect(fakeStorage.getItem('passflow_session_state')).toBeNull();
    });
  });

  describe('persistence across instances', () => {
    test('should persist mode across manager instances', () => {
      deliveryManager.setMode(TokenDeliveryMode.Cookie);

      const newManager = new TokenDeliveryManager(storageManager);
      expect(newManager.getMode()).toBe(TokenDeliveryMode.Cookie);
      expect(newManager.isCookieMode()).toBe(true);
      expect(newManager.isInitialized()).toBe(true);
    });

    test('should persist session state across manager instances', () => {
      deliveryManager.setSessionValid();

      const newManager = new TokenDeliveryManager(storageManager);
      expect(newManager.getSessionState()).toBe(SessionState.Valid);
      expect(newManager.isSessionValid()).toBe(true);
    });

    test('should persist both mode and state', () => {
      deliveryManager.setMode(TokenDeliveryMode.Cookie);
      deliveryManager.setSessionValid();

      const newManager = new TokenDeliveryManager(storageManager);
      expect(newManager.getMode()).toBe(TokenDeliveryMode.Cookie);
      expect(newManager.getSessionState()).toBe(SessionState.Valid);
      expect(newManager.isCookieMode()).toBe(true);
      expect(newManager.isSessionValid()).toBe(true);
    });
  });

  describe('error handling', () => {
    test('should handle storage errors gracefully when loading mode', () => {
      const brokenStorage = {
        getItem: vi.fn(() => {
          throw new Error('Storage error');
        }),
        setItem: vi.fn(),
        removeItem: vi.fn(),
      };

      const brokenStorageManager = new StorageManager({ storage: brokenStorage });

      const newManager = new TokenDeliveryManager(brokenStorageManager);

      expect(newManager.getMode()).toBe(TokenDeliveryMode.JsonBody);
    });

    test('should handle storage errors gracefully when persisting mode', () => {
      const brokenStorage = {
        getItem: vi.fn(() => null),
        setItem: vi.fn(() => {
          throw new Error('Storage error');
        }),
        removeItem: vi.fn(),
      };

      const brokenStorageManager = new StorageManager({ storage: brokenStorage });

      const newManager = new TokenDeliveryManager(brokenStorageManager);
      newManager.setMode(TokenDeliveryMode.Cookie);

      // Should not throw, just silently fail
      expect(newManager.getMode()).toBe(TokenDeliveryMode.Cookie);
    });

    test('should handle storage errors gracefully during reset', () => {
      const brokenStorage = {
        getItem: vi.fn(() => null),
        setItem: vi.fn(),
        removeItem: vi.fn(() => {
          throw new Error('Storage error');
        }),
      };

      const brokenStorageManager = new StorageManager({ storage: brokenStorage });

      const newManager = new TokenDeliveryManager(brokenStorageManager);
      newManager.reset();

      // Should not throw, just silently fail
      expect(newManager.getMode()).toBe(TokenDeliveryMode.JsonBody);
    });
  });

  describe('storage key namespacing', () => {
    test('should use namespaced storage keys', () => {
      deliveryManager.setMode(TokenDeliveryMode.Cookie);
      deliveryManager.setSessionValid();

      expect(fakeStorage.data.has('passflow_delivery_mode')).toBe(true);
      expect(fakeStorage.data.has('passflow_session_state')).toBe(true);
    });

    test('should not conflict with other storage keys', () => {
      fakeStorage.setItem('delivery_mode', 'other_value');
      fakeStorage.setItem('session_state', 'other_value');

      deliveryManager.setMode(TokenDeliveryMode.Cookie);
      deliveryManager.setSessionValid();

      expect(fakeStorage.getItem('delivery_mode')).toBe('other_value');
      expect(fakeStorage.getItem('session_state')).toBe('other_value');
      expect(fakeStorage.getItem('passflow_delivery_mode')).toBe(TokenDeliveryMode.Cookie);
      expect(fakeStorage.getItem('passflow_session_state')).toBe(SessionState.Valid);
    });
  });
});
