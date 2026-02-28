/**
 * Token Delivery Manager
 *
 * Manages token delivery mode state and session validity for the SDK.
 * Supports three delivery modes: JSON body, cookie, and mobile.
 * Persists delivery mode to storage for session continuity.
 *
 * @module token/delivery-manager
 */

import type { StorageManager } from '../storage';

export enum TokenDeliveryMode {
  JsonBody = 'json_body',
  Cookie = 'cookie',
  Mobile = 'mobile',
  /**
   * BFF (Backend-for-Frontend) mode.
   * Tokens are sent to BFF server which stores them in httpOnly cookies.
   * Only ID token is kept locally for user info display.
   */
  BFF = 'bff',
}

export enum SessionState {
  Unknown = 'unknown', // Initial state, not yet determined
  Valid = 'valid', // Session is valid (cookie mode trust state)
  Invalid = 'invalid', // Received 401, session expired
}

export class TokenDeliveryManager {
  private mode: TokenDeliveryMode = TokenDeliveryMode.JsonBody;
  private sessionState: SessionState = SessionState.Unknown;
  private isInitializedFlag = false;

  private readonly STORAGE_PREFIX = 'passflow_';
  private readonly DELIVERY_MODE_KEY = `${this.STORAGE_PREFIX}delivery_mode`;
  private readonly SESSION_STATE_KEY = `${this.STORAGE_PREFIX}session_state`;

  constructor(private storageManager: StorageManager) {
    this.loadPersistedMode();
    this.loadPersistedSessionState();
  }

  /**
   * Set the token delivery mode
   */
  setMode(mode: TokenDeliveryMode): void {
    this.mode = mode;
    this.isInitializedFlag = true;
    this.persistMode();
  }

  /**
   * Get the current token delivery mode
   */
  getMode(): TokenDeliveryMode {
    return this.mode;
  }

  /**
   * Check if currently in cookie mode
   */
  isCookieMode(): boolean {
    return this.mode === TokenDeliveryMode.Cookie;
  }

  /**
   * Check if currently in JSON body mode
   */
  isJsonMode(): boolean {
    return this.mode === TokenDeliveryMode.JsonBody;
  }

  /**
   * Check if currently in mobile mode
   */
  isMobileMode(): boolean {
    return this.mode === TokenDeliveryMode.Mobile;
  }

  /**
   * Check if currently in BFF mode
   */
  isBFFMode(): boolean {
    return this.mode === TokenDeliveryMode.BFF;
  }

  /**
   * Check if delivery mode has been initialized from a server response
   */
  isInitialized(): boolean {
    return this.isInitializedFlag;
  }

  /**
   * Mark session as valid (successful authentication or token refresh)
   */
  setSessionValid(): void {
    this.sessionState = SessionState.Valid;
    this.persistSessionState();
  }

  /**
   * Mark session as invalid (received 401 or logout)
   */
  setSessionInvalid(): void {
    this.sessionState = SessionState.Invalid;
    this.persistSessionState();
  }

  /**
   * Reset session state to unknown (used during authentication flows)
   */
  setSessionUnknown(): void {
    this.sessionState = SessionState.Unknown;
    this.persistSessionState();
  }

  /**
   * Check if session is valid
   */
  isSessionValid(): boolean {
    return this.sessionState === SessionState.Valid;
  }

  /**
   * Check if session state is unknown (not yet determined)
   */
  isSessionUnknown(): boolean {
    return this.sessionState === SessionState.Unknown;
  }

  /**
   * Check if session is invalid
   */
  isSessionInvalid(): boolean {
    return this.sessionState === SessionState.Invalid;
  }

  /**
   * Get current session state
   */
  getSessionState(): SessionState {
    return this.sessionState;
  }

  /**
   * Reset delivery manager to initial state
   */
  reset(): void {
    this.mode = TokenDeliveryMode.JsonBody;
    this.sessionState = SessionState.Unknown;
    this.isInitializedFlag = false;
    this.clearPersistedMode();
    this.clearPersistedSessionState();
  }

  /**
   * Load persisted delivery mode from storage
   */
  private loadPersistedMode(): void {
    try {
      const persistedMode = this.storageManager['storage'].getItem(this.DELIVERY_MODE_KEY);
      if (persistedMode) {
        // Validate that the persisted mode is a valid enum value
        if (Object.values(TokenDeliveryMode).includes(persistedMode as TokenDeliveryMode)) {
          this.mode = persistedMode as TokenDeliveryMode;
          this.isInitializedFlag = true;
        }
      }
    } catch (_error) {
      // Silently ignore storage errors during load
    }
  }

  /**
   * Load persisted session state from storage
   */
  private loadPersistedSessionState(): void {
    try {
      const persistedState = this.storageManager['storage'].getItem(this.SESSION_STATE_KEY);
      if (persistedState) {
        // Validate that the persisted state is a valid enum value
        if (Object.values(SessionState).includes(persistedState as SessionState)) {
          this.sessionState = persistedState as SessionState;
        }
      }
    } catch (_error) {
      // Silently ignore storage errors during load
    }
  }

  /**
   * Persist delivery mode to storage
   */
  private persistMode(): void {
    try {
      this.storageManager['storage'].setItem(this.DELIVERY_MODE_KEY, this.mode);
    } catch (_error) {
      // Silently ignore storage errors during persist
    }
  }

  /**
   * Persist session state to storage
   */
  private persistSessionState(): void {
    try {
      this.storageManager['storage'].setItem(this.SESSION_STATE_KEY, this.sessionState);
    } catch (_error) {
      // Silently ignore storage errors during persist
    }
  }

  /**
   * Clear persisted delivery mode from storage
   */
  private clearPersistedMode(): void {
    try {
      this.storageManager['storage'].removeItem(this.DELIVERY_MODE_KEY);
    } catch (_error) {
      // Silently ignore storage errors during clear
    }
  }

  /**
   * Clear persisted session state from storage
   */
  private clearPersistedSessionState(): void {
    try {
      this.storageManager['storage'].removeItem(this.SESSION_STATE_KEY);
    } catch (_error) {
      // Silently ignore storage errors during clear
    }
  }
}
