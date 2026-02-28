import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';

import type { Storage } from '../storage';

// ----------------------------------------------------------------
// Storage
// ----------------------------------------------------------------

/**
 * Synchronous key-value storage interface.
 * Compatible with localStorage (web) and react-native-mmkv (RN).
 * Alias of the Storage type in lib/storage/index.ts to maintain a single source of truth.
 */
export type PlatformStorage = Storage;

// ----------------------------------------------------------------
// Navigation
// ----------------------------------------------------------------

/**
 * Result returned by getCurrentUrl().
 * Provides structured access to URL components so adapters don't
 * need to parse a URL string themselves.
 */
export type CurrentUrlInfo = {
  /** Full URL string, e.g. "https://app.com/callback?access_token=abc#hash" */
  href: string;
  /** Origin, e.g. "https://app.com" */
  origin: string;
  /** Pathname, e.g. "/callback" */
  pathname: string;
  /** Query string including "?", e.g. "?access_token=abc" */
  search: string;
  /** Hash including "#", e.g. "#access_token=abc" */
  hash: string;
  /** Hostname without port, e.g. "app.com" */
  hostname: string;
};

// ----------------------------------------------------------------
// Auth UI
// ----------------------------------------------------------------

/**
 * Options passed to openAuthUrl(). Adapters can use these to decide
 * whether to open a popup, redirect, or use a deep link.
 */
export type OpenAuthUrlOptions = {
  /**
   * Preferred presentation mode. Adapters may ignore this and use
   * whatever makes sense for the platform.
   * - "popup": Open in a popup window (web default)
   * - "redirect": Full-page redirect (web fallback)
   * - "deeplink": Open with a deep link (React Native)
   */
  mode?: 'popup' | 'redirect' | 'deeplink';
  /** Popup width hint (web only) */
  width?: number;
  /** Popup height hint (web only) */
  height?: number;
  /** Origin to watch for the popup to return to (web popup mode only) */
  expectedReturnOrigin?: string;
};

/**
 * Result returned when the auth flow completes.
 * The adapter is responsible for detecting when auth is done and
 * returning the tokens from the callback URL.
 */
export type AuthCallbackResult = {
  /** Raw query string from the callback URL, e.g. "?access_token=abc" */
  callbackSearch: string;
  /** Raw hash from the callback URL, e.g. "#access_token=abc" */
  callbackHash: string;
};

// ----------------------------------------------------------------
// Passkeys (optional)
// ----------------------------------------------------------------

/**
 * Optional passkey support. Adapters that do not support passkeys
 * return undefined from these methods. The calling code must check
 * for undefined before using the result.
 */
export type PasskeySupport = {
  /**
   * Start a passkey registration ceremony.
   * @returns Registration response, or undefined if not supported.
   */
  startRegistration(options: PublicKeyCredentialCreationOptionsJSON): Promise<RegistrationResponseJSON | undefined>;

  /**
   * Start a passkey authentication ceremony.
   * @returns Authentication response, or undefined if not supported.
   */
  startAuthentication(options: PublicKeyCredentialRequestOptionsJSON): Promise<AuthenticationResponseJSON | undefined>;
};

// ----------------------------------------------------------------
// Errors
// ----------------------------------------------------------------

/**
 * Error thrown when the authentication popup is closed by the user
 * before authentication completes. Use `instanceof PopupClosedError`
 * for type-safe error discrimination instead of string matching.
 */
export class PopupClosedError extends Error {
  constructor(message = 'Authentication popup was closed') {
    super(message);
    this.name = 'PopupClosedError';
  }
}

// ----------------------------------------------------------------
// Main Interface
// ----------------------------------------------------------------

/**
 * PlatformAdapter abstracts all platform-specific APIs that the
 * Passflow SDK needs. Implement this interface to add support for
 * a new platform (e.g. React Native).
 *
 * All methods have sensible defaults in WebAdapter. You only need
 * to implement what your platform supports.
 */
export interface PlatformAdapter {
  // ------ Storage ------

  /**
   * Synchronous key-value storage for tokens and SDK state.
   * Must be synchronous. Use localStorage on web, MMKV on React Native.
   */
  readonly storage: PlatformStorage;

  // ------ Navigation ------

  /**
   * Returns the current URL of the application.
   * On web: wraps window.location.
   * On React Native: implement using your routing library (e.g. Linking.getInitialURL).
   *
   * May return null in environments where URL is not meaningful (e.g. during SSR).
   */
  getCurrentUrl(): CurrentUrlInfo | null;

  /**
   * Navigates to the given URL, replacing the current history entry.
   * On web: window.history.replaceState(...)
   * On React Native: no-op or use your router's replace method.
   */
  replaceUrl(url: string): void;

  /**
   * Navigates to the given URL, performing a full navigation.
   * On web: window.location.href = url
   * On React Native: use Linking.openURL or your router.
   */
  navigateTo(url: string): void;

  // ------ Lifecycle ------

  /**
   * Register a callback invoked when the app comes to the foreground
   * (page becomes visible / app resumes).
   * Returns an unsubscribe function.
   *
   * On web: document.addEventListener('visibilitychange', ...)
   * On React Native: AppState.addEventListener('change', ...)
   */
  onForeground(callback: () => void): () => void;

  /**
   * Register a callback invoked when the app goes to the background
   * (page hidden / app suspended).
   * Returns an unsubscribe function.
   *
   * On web: document.addEventListener('visibilitychange', ...)
   * On React Native: AppState.addEventListener('change', ...)
   *
   * NOTE: This method is intentionally not called by the SDK internally.
   * It is part of the interface to support React Native adapters which need
   * to perform cleanup (e.g., flush queues) when the app is backgrounded.
   * Web adapters may implement it as a no-op or use visibilitychange.
   */
  onBackground(callback: () => void): () => void;

  /**
   * Register a callback invoked just before the page/app is closed.
   * Returns an unsubscribe function.
   *
   * On web: window.addEventListener('beforeunload', ...)
   * On React Native: implement as a no-op (RN handles cleanup differently).
   */
  onBeforeUnload(callback: () => void): () => void;

  /**
   * Returns true if the app is currently in the foreground (page visible).
   * On web: !document.hidden
   * On React Native: AppState.currentState === 'active'
   */
  isInForeground(): boolean;

  // ------ Auth UI ------

  /**
   * Opens a URL for federated/OAuth authentication.
   *
   * Web implementation:
   *   - "popup" mode: Opens a popup via window.open(), polls for the callback,
   *     resolves when the popup returns to expectedReturnOrigin.
   *   - "redirect" mode: Full-page redirect (window.location.href = url).
   *     Returns a Promise that never resolves (page navigates away).
   *
   * React Native implementation:
   *   - Opens the URL via Linking.openURL() with a deep link scheme.
   *   - Resolves when the deep link callback is received.
   *
   * @returns Promise that resolves with the callback URL tokens,
   *          or rejects if auth fails or is cancelled.
   *          In redirect mode on web, the promise may never resolve.
   */
  openAuthUrl(url: string, options?: OpenAuthUrlOptions): Promise<AuthCallbackResult>;

  // ------ Passkeys ------

  /**
   * Optional passkey support. If the platform does not support passkeys,
   * this property is undefined. The SDK checks for undefined before calling.
   */
  readonly passkeys?: PasskeySupport;

  // ------ Base64 ------

  /**
   * Encodes a string to Base64.
   * On web: btoa(str)
   * On React Native: use base64-js or Buffer.
   */
  btoa(str: string): string;

  /**
   * Decodes a Base64 string.
   * On web: atob(str) or Buffer fallback for SSR.
   * On React Native: use base64-js or Buffer.
   */
  atob(str: string): string;

  // ------ Cookies ------

  /**
   * Returns true if the platform supports HTTP cookies.
   * On web: true (with a quick write/read test).
   * On React Native: false. Cookie mode is not available.
   *
   * When this returns false, cookie token delivery mode must not be used.
   * The SDK will throw a descriptive error if cookie mode is configured
   * on a platform where cookies are not supported.
   */
  cookiesSupported(): boolean;

  // ------ Device ------

  /**
   * Returns the platform/device type.
   * Used to set the X-Device-Type header on API requests.
   */
  getDeviceType(): 'web' | 'ios' | 'android';
}
