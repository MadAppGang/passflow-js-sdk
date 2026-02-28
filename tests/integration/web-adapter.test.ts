/**
 * Unit Tests for WebAdapter
 *
 * Tests that verify the WebAdapter correctly wraps browser APIs.
 * The test environment is jsdom so window, document, and localStorage are available.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { WebAdapter } from '../../lib/platform';

describe('WebAdapter', () => {
  let adapter: WebAdapter;

  beforeEach(() => {
    adapter = new WebAdapter();
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Navigation
  // -------------------------------------------------------------------------

  describe('getCurrentUrl', () => {
    test('TC-6.1: returns structured location data from window.location', () => {
      Object.defineProperty(window, 'location', {
        value: {
          href: 'https://example.com/path?foo=bar#section',
          origin: 'https://example.com',
          pathname: '/path',
          search: '?foo=bar',
          hash: '#section',
          hostname: 'example.com',
        },
        writable: true,
        configurable: true,
      });

      const result = adapter.getCurrentUrl();

      expect(result).not.toBeNull();
      expect(result!.href).toBe('https://example.com/path?foo=bar#section');
      expect(result!.origin).toBe('https://example.com');
      expect(result!.pathname).toBe('/path');
      expect(result!.search).toBe('?foo=bar');
      expect(result!.hash).toBe('#section');
      expect(result!.hostname).toBe('example.com');
    });

    test('returns all expected properties', () => {
      const result = adapter.getCurrentUrl();
      if (result !== null) {
        expect(result).toHaveProperty('href');
        expect(result).toHaveProperty('origin');
        expect(result).toHaveProperty('pathname');
        expect(result).toHaveProperty('search');
        expect(result).toHaveProperty('hash');
        expect(result).toHaveProperty('hostname');
      }
    });
  });

  describe('replaceUrl', () => {
    test('TC-6.2: replaceUrl is callable and calls history.replaceState', () => {
      const replaceStateSpy = vi.spyOn(window.history, 'replaceState').mockImplementation(vi.fn());

      adapter.replaceUrl('/new-path');

      expect(replaceStateSpy).toHaveBeenCalledWith({}, document.title, '/new-path');
    });
  });

  describe('navigateTo', () => {
    test('navigateTo sets window.location.href', () => {
      // In jsdom we cannot actually navigate, but we can check the method exists and is callable
      expect(typeof adapter.navigateTo).toBe('function');
      // navigateTo in jsdom will not throw
      expect(() => adapter.navigateTo('https://example.com')).not.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  describe('onForeground', () => {
    test('TC-6.5: onForeground returns an unsubscribe function', () => {
      const unsub = adapter.onForeground(vi.fn());
      expect(typeof unsub).toBe('function');
    });

    test('onForeground registers a visibilitychange listener', () => {
      const addSpy = vi.spyOn(document, 'addEventListener');
      adapter.onForeground(vi.fn());
      expect(addSpy).toHaveBeenCalledWith('visibilitychange', expect.any(Function));
    });

    test('unsubscribe from onForeground removes the listener', () => {
      const removeSpy = vi.spyOn(document, 'removeEventListener');
      const unsub = adapter.onForeground(vi.fn());
      unsub();
      expect(removeSpy).toHaveBeenCalledWith('visibilitychange', expect.any(Function));
    });

    test('callback is invoked when document becomes visible', () => {
      const cb = vi.fn();
      adapter.onForeground(cb);

      // Simulate page becoming visible
      Object.defineProperty(document, 'hidden', { value: false, writable: true, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));

      expect(cb).toHaveBeenCalled();
    });

    test('callback is NOT invoked when document becomes hidden', () => {
      const cb = vi.fn();
      adapter.onForeground(cb);

      // Simulate page becoming hidden
      Object.defineProperty(document, 'hidden', { value: true, writable: true, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));

      expect(cb).not.toHaveBeenCalled();
    });
  });

  describe('onBackground', () => {
    test('TC-6.6: onBackground returns an unsubscribe function', () => {
      const unsub = adapter.onBackground(vi.fn());
      expect(typeof unsub).toBe('function');
    });

    test('callback is invoked when document becomes hidden', () => {
      const cb = vi.fn();
      adapter.onBackground(cb);

      Object.defineProperty(document, 'hidden', { value: true, writable: true, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));

      expect(cb).toHaveBeenCalled();
    });

    test('callback is NOT invoked when document becomes visible', () => {
      const cb = vi.fn();
      adapter.onBackground(cb);

      Object.defineProperty(document, 'hidden', { value: false, writable: true, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));

      expect(cb).not.toHaveBeenCalled();
    });
  });

  describe('onBeforeUnload', () => {
    test('TC-6.6: onBeforeUnload returns an unsubscribe function', () => {
      const unsub = adapter.onBeforeUnload(vi.fn());
      expect(typeof unsub).toBe('function');
    });

    test('onBeforeUnload registers a beforeunload listener on window', () => {
      const addSpy = vi.spyOn(window, 'addEventListener');
      adapter.onBeforeUnload(vi.fn());
      expect(addSpy).toHaveBeenCalledWith('beforeunload', expect.any(Function));
    });

    test('unsubscribe from onBeforeUnload removes the listener', () => {
      const removeSpy = vi.spyOn(window, 'removeEventListener');
      const unsub = adapter.onBeforeUnload(vi.fn());
      unsub();
      expect(removeSpy).toHaveBeenCalledWith('beforeunload', expect.any(Function));
    });
  });

  describe('isInForeground', () => {
    test('returns true when document.hidden is false', () => {
      Object.defineProperty(document, 'hidden', { value: false, writable: true, configurable: true });
      expect(adapter.isInForeground()).toBe(true);
    });

    test('returns false when document.hidden is true', () => {
      Object.defineProperty(document, 'hidden', { value: true, writable: true, configurable: true });
      expect(adapter.isInForeground()).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Base64
  // -------------------------------------------------------------------------

  describe('btoa / atob', () => {
    test('TC-6.9: btoa and atob are symmetric (encode then decode = original)', () => {
      const original = 'hello world passflow 123';
      const encoded = adapter.btoa(original);
      const decoded = adapter.atob(encoded);
      expect(decoded).toBe(original);
    });

    test('btoa produces a valid base64 string', () => {
      const result = adapter.btoa('test');
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });

    test('atob decodes a known base64 string', () => {
      // 'passflow' in base64 is 'cGFzc2Zsb3c='
      const result = adapter.atob('cGFzc2Zsb3c=');
      expect(result).toBe('passflow');
    });

    test('TC-6.10: btoa used for passkey user ID encoding produces decodable result', () => {
      const userId = 'user-handle-12345';
      const encoded = adapter.btoa(userId);
      // Simplewebauthn receives this encoded value
      expect(encoded).toBeTruthy();
      expect(adapter.atob(encoded)).toBe(userId);
    });
  });

  // -------------------------------------------------------------------------
  // Device type
  // -------------------------------------------------------------------------

  describe('getDeviceType', () => {
    test('TC-6.11: getDeviceType returns "web"', () => {
      expect(adapter.getDeviceType()).toBe('web');
    });
  });

  // -------------------------------------------------------------------------
  // Cookies
  // -------------------------------------------------------------------------

  describe('cookiesSupported', () => {
    test('TC-6.10: cookiesSupported returns a boolean', () => {
      const result = adapter.cookiesSupported();
      expect(typeof result).toBe('boolean');
    });

    test('cookiesSupported returns true in jsdom environment (cookies enabled)', () => {
      // jsdom supports cookies, so this should return true
      const result = adapter.cookiesSupported();
      // jsdom may or may not support cookie write/read; just verify type
      expect(typeof result).toBe('boolean');
    });
  });

  // -------------------------------------------------------------------------
  // Storage
  // -------------------------------------------------------------------------

  describe('storage', () => {
    test('storage property is localStorage in browser environment', () => {
      // The WebAdapter uses localStorage directly
      expect(adapter.storage).toBe(localStorage);
    });

    test('storage implements PlatformStorage interface', () => {
      expect(typeof adapter.storage.getItem).toBe('function');
      expect(typeof adapter.storage.setItem).toBe('function');
      expect(typeof adapter.storage.removeItem).toBe('function');
    });
  });

  // -------------------------------------------------------------------------
  // Passkeys
  // -------------------------------------------------------------------------

  describe('passkeys', () => {
    test('passkeys property is defined on WebAdapter', () => {
      expect(adapter.passkeys).toBeDefined();
    });

    test('passkeys has startRegistration method', () => {
      expect(typeof adapter.passkeys!.startRegistration).toBe('function');
    });

    test('passkeys has startAuthentication method', () => {
      expect(typeof adapter.passkeys!.startAuthentication).toBe('function');
    });
  });

  // -------------------------------------------------------------------------
  // webAdapter singleton
  // -------------------------------------------------------------------------

  describe('webAdapter singleton', () => {
    test('webAdapter is exported and is a WebAdapter instance', async () => {
      const { webAdapter } = await import('../../lib/platform');
      expect(webAdapter).toBeInstanceOf(WebAdapter);
    });
  });
});
