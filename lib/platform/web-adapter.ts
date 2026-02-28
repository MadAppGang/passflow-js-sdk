import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { POPUP_HEIGHT, POPUP_POLL_INTERVAL_MS, POPUP_TIMEOUT_MS, POPUP_WIDTH } from '../constants';
import {
  type AuthCallbackResult,
  type CurrentUrlInfo,
  type OpenAuthUrlOptions,
  type PasskeySupport,
  type PlatformAdapter,
  type PlatformStorage,
  PopupClosedError,
} from './types';

export class WebAdapter implements PlatformAdapter {
  // ----------------------------------------------------------------
  // Storage
  // Replaces: StorageManager constructor default `storage ?? localStorage`
  // File: lib/storage/index.ts line 41
  // ----------------------------------------------------------------
  get storage(): PlatformStorage {
    if (typeof localStorage === 'undefined') {
      // SSR/Node environment: return a no-op storage that never throws
      return {
        getItem: () => null,
        // biome-ignore lint/suspicious/noEmptyBlockStatements: intentional no-op for SSR
        setItem: () => {},
        // biome-ignore lint/suspicious/noEmptyBlockStatements: intentional no-op for SSR
        removeItem: () => {},
      };
    }
    return localStorage;
  }

  // ----------------------------------------------------------------
  // Navigation
  // ----------------------------------------------------------------

  /**
   * Replaces:
   *   window.location.origin  (passflow.ts:95, axios-client.ts:49)
   *   window.location.search  (passflow.ts:338,416, auth-service.ts:610,826)
   *   window.location.hash    (passflow.ts:342)
   *   window.location.href    (auth-service.ts:826)
   *   window.location.pathname (passflow.ts:429,441,443)
   *   window?.location?.hostname (user-service.ts:57)
   */
  getCurrentUrl(): CurrentUrlInfo | null {
    if (typeof window === 'undefined') return null;
    return {
      href: window.location.href,
      origin: window.location.origin,
      pathname: window.location.pathname,
      search: window.location.search,
      hash: window.location.hash,
      hostname: window.location.hostname,
    };
  }

  /**
   * Replaces:
   *   window.history.replaceState({}, document.title, ...)
   *   (passflow.ts:429, 441, 443)
   */
  replaceUrl(url: string): void {
    if (typeof window === 'undefined') return;
    window.history.replaceState({}, document.title, url);
  }

  /**
   * Replaces:
   *   window.location.href = url
   *   (auth-service.ts:795, 813, 845, passflow.ts indirectly)
   */
  navigateTo(url: string): void {
    if (typeof window === 'undefined') return;
    window.location.href = url;
  }

  // ----------------------------------------------------------------
  // Lifecycle
  // ----------------------------------------------------------------

  /**
   * Replaces:
   *   document.addEventListener('visibilitychange', handler) where !document.hidden
   *   (token-cache-service.ts:134-145)
   */
  onForeground(callback: () => void): () => void {
    if (typeof document === 'undefined')
      return () => {
        /* no-op in SSR */
      };
    const handler = () => {
      if (!document.hidden) callback();
    };
    document.addEventListener('visibilitychange', handler);
    return () => document.removeEventListener('visibilitychange', handler);
  }

  /**
   * Replaces:
   *   document.addEventListener('visibilitychange', handler) where document.hidden
   *   (token-cache-service.ts:134-145, complementary to onForeground)
   *
   * NOTE: Not currently called by the SDK. Included in the interface for
   * React Native adapter compatibility (future use).
   */
  onBackground(callback: () => void): () => void {
    if (typeof document === 'undefined')
      return () => {
        /* no-op in SSR */
      };
    const handler = () => {
      if (document.hidden) callback();
    };
    document.addEventListener('visibilitychange', handler);
    return () => document.removeEventListener('visibilitychange', handler);
  }

  /**
   * Replaces:
   *   window.addEventListener('beforeunload', ...)
   *   (token-cache-service.ts:151)
   */
  onBeforeUnload(callback: () => void): () => void {
    if (typeof window === 'undefined')
      return () => {
        /* no-op in SSR */
      };
    window.addEventListener('beforeunload', callback);
    return () => window.removeEventListener('beforeunload', callback);
  }

  /**
   * Replaces:
   *   typeof document !== 'undefined' && document.hidden
   *   (token-cache-service.ts:112)
   */
  isInForeground(): boolean {
    if (typeof document === 'undefined') return true;
    return !document.hidden;
  }

  // ----------------------------------------------------------------
  // Auth UI
  // ----------------------------------------------------------------

  /**
   * Replaces:
   *   window.open(passflowURL, '_blank', `width=...,height=...`)
   *   + polling loop with popupWindow.location.href/search
   *   + window.location.href = origin (post-auth redirect)
   *   (auth-service.ts:741-805)
   *
   *   window.location.href = passflowURL (redirect mode)
   *   (auth-service.ts:813)
   */
  openAuthUrl(url: string, options: OpenAuthUrlOptions = {}): Promise<AuthCallbackResult> {
    const mode = options.mode ?? 'popup';

    if (mode === 'redirect') {
      // Full-page redirect — page will reload; promise never resolves
      window.location.href = url;
      return new Promise(() => {
        /* intentionally never resolves — page navigates away */
      });
    }

    if (mode === 'deeplink') {
      return Promise.reject(
        new Error(
          'openAuthUrl: "deeplink" mode is not supported on web. ' +
            'Use "popup" or "redirect" instead, or provide a native platform adapter.',
        ),
      );
    }

    // Popup mode (default)
    const width = options.width ?? POPUP_WIDTH;
    const height = options.height ?? POPUP_HEIGHT;
    const expectedReturnOrigin = options.expectedReturnOrigin ?? window.location.origin;

    const popupWindow = window.open(url, '_blank', `width=${width},height=${height}`);

    if (!popupWindow) {
      // Popup blocked — fall back to redirect
      window.location.href = url;
      return new Promise(() => {
        /* intentionally never resolves — falling back to redirect */
      });
    }

    return new Promise<AuthCallbackResult>((resolve, reject) => {
      const startTime = Date.now();

      const checkInterval = setInterval(() => {
        if (popupWindow.closed) {
          clearInterval(checkInterval);
          reject(new PopupClosedError());
          return;
        }

        if (Date.now() - startTime > POPUP_TIMEOUT_MS) {
          clearInterval(checkInterval);
          popupWindow.close();
          reject(new Error('Authentication popup timed out'));
          return;
        }

        try {
          if (popupWindow.location.href.startsWith(expectedReturnOrigin)) {
            const callbackSearch = popupWindow.location.search;
            const callbackHash = popupWindow.location.hash;
            clearInterval(checkInterval);
            popupWindow.close();
            resolve({ callbackSearch, callbackHash });
          }
        } catch {
          // Expected cross-origin error — continue polling
        }
      }, POPUP_POLL_INTERVAL_MS);
    });
  }

  // ----------------------------------------------------------------
  // Passkeys
  // ----------------------------------------------------------------

  /**
   * Replaces:
   *   startRegistration({ optionsJSON: publicKey }) from @simplewebauthn/browser
   *   (auth-service.ts:645-646, user-service.ts:65)
   *
   *   startAuthentication({ optionsJSON: publicKey }) from @simplewebauthn/browser
   *   (auth-service.ts:681)
   */
  readonly passkeys: PasskeySupport = {
    startRegistration: (options) => startRegistration({ optionsJSON: options }),
    startAuthentication: (options) => startAuthentication({ optionsJSON: options }),
  };

  // ----------------------------------------------------------------
  // Base64
  // ----------------------------------------------------------------

  /**
   * Replaces:
   *   btoa(publicKey.user.id)
   *   (auth-service.ts:644, user-service.ts:64)
   */
  btoa(str: string): string {
    return btoa(str);
  }

  /**
   * Replaces:
   *   window.atob(base64) / Buffer.from(base64, 'base64').toString('utf-8')
   *   (token/service.ts:26-27)
   */
  atob(str: string): string {
    if (typeof window !== 'undefined' && typeof window.atob === 'function') {
      return window.atob(str);
    }
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(str, 'base64').toString('utf-8');
    }
    throw new Error('No Base64 decoding method available in this environment');
  }

  // ----------------------------------------------------------------
  // Cookies
  // ----------------------------------------------------------------

  /**
   * Replaces:
   *   document.cookie write/read test
   *   (axios-client.ts:221-223)
   */
  cookiesSupported(): boolean {
    if (typeof document === 'undefined') return false;
    try {
      document.cookie = 'passflow_test=1; SameSite=Lax';
      const enabled = document.cookie.indexOf('passflow_test=1') !== -1;
      document.cookie = 'passflow_test=; expires=Thu, 01 Jan 1970 00:00:00 UTC';
      return enabled;
    } catch {
      return false;
    }
  }

  // ----------------------------------------------------------------
  // Device
  // ----------------------------------------------------------------

  /**
   * Replaces:
   *   Hardcoded 'web' string in DEVICE_TYPE_HEADER_KEY header
   *   (axios-client.ts:91)
   *   OS.web enum value (auth-service.ts:244, 358, 637, 676, user-service.ts:55)
   */
  getDeviceType(): 'web' | 'ios' | 'android' {
    return 'web';
  }
}

/**
 * Singleton instance used as the default adapter.
 * Exported so consuming code can reference it without allocating a new instance.
 */
export const webAdapter = new WebAdapter();
