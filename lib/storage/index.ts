/**
 * Storage Manager
 *
 * Abstraction layer over browser localStorage for token and data persistence.
 * Supports custom storage implementations for testing and alternative platforms.
 * Handles key prefixing for multi-app scenarios.
 *
 * @module storage
 */

import { TokenType } from '../token';
import { TokenDeliveryMode, Tokens } from '../types';

export type Storage = {
  setItem: (key: string, value: string) => void;
  getItem: (key: string) => string | null;
  removeItem: (key: string) => void;
};

export interface StorageManagerParams {
  storage?: Storage;
  prefix?: string;
}

export class StorageManager {
  private keyStoragePrefix = '';
  readonly scopes = `${this.keyStoragePrefix}tokens_scopes`;
  readonly deviceId = `${this.keyStoragePrefix}passflowDeviceId`;
  readonly invitationToken = `${this.keyStoragePrefix}passflowInvitationToken`;
  readonly previousRedirectUrl = `${this.keyStoragePrefix}passflowPreviousRedirectUrl`;

  // Namespaced keys for cookie mode support
  private readonly STORAGE_PREFIX = 'passflow_';
  private readonly ID_TOKEN_KEY = `${this.STORAGE_PREFIX}id_token`;
  private readonly CSRF_TOKEN_KEY = `${this.STORAGE_PREFIX}csrf_token`;
  private readonly DELIVERY_MODE_KEY = `${this.STORAGE_PREFIX}delivery_mode`;

  private storage: Storage;

  constructor({ storage, prefix }: StorageManagerParams = {}) {
    this.storage = storage ?? localStorage;
    this.keyStoragePrefix = prefix ? `${prefix}_` : '';
  }

  /**
   * Save tokens to storage with conditional logic based on delivery mode
   * In cookie/BFF mode: ONLY save ID token (not access/refresh tokens)
   * In JSON mode: save all tokens (existing behavior)
   */
  saveTokens(tokens: Tokens, deliveryMode?: TokenDeliveryMode): void {
    const { id_token, access_token, refresh_token, scopes } = tokens;

    if (deliveryMode === TokenDeliveryMode.Cookie || deliveryMode === TokenDeliveryMode.BFF) {
      // Cookie/BFF mode: ONLY save ID token (access/refresh in HttpOnly cookies)
      if (id_token) {
        this.storage.setItem(this.ID_TOKEN_KEY, id_token);
      }
      // Do NOT save access_token or refresh_token in localStorage
    } else {
      // JSON mode: save all tokens (existing behavior)
      if (id_token) this.storage.setItem(this.getKeyForTokenType(TokenType.id_token), id_token);
      if (access_token) this.storage.setItem(this.getKeyForTokenType(TokenType.access_token), access_token);
      if (refresh_token) this.storage.setItem(this.getKeyForTokenType(TokenType.refresh_token), refresh_token);
      if (scopes) this.storage.setItem(this.scopes, scopes.join(','));
    }
  }

  getToken(tokenType: TokenType): string | undefined {
    const key = this.getKeyForTokenType(tokenType);
    return this.storage.getItem(key) ?? undefined;
  }

  /**
   * Get tokens from storage with conditional logic based on delivery mode
   * In cookie/BFF mode: return ID token only (access/refresh in HttpOnly cookies)
   * In JSON mode: return all stored tokens (existing behavior)
   */
  getTokens(): Tokens | undefined {
    const mode = this.getDeliveryMode();

    if (mode === TokenDeliveryMode.Cookie || mode === TokenDeliveryMode.BFF) {
      // Cookie/BFF mode: return ID token only (access/refresh in HttpOnly cookies)
      const idToken = this.storage.getItem(this.ID_TOKEN_KEY);
      if (!idToken) return undefined;
      return {
        id_token: idToken,
        // access_token and refresh_token are in HttpOnly cookies, not localStorage
      };
    }

    // JSON mode: return all stored tokens (existing behavior)
    const access = this.storage.getItem(this.getKeyForTokenType(TokenType.access_token));
    if (!access) return undefined;
    return {
      access_token: access,
      id_token: this.storage.getItem(this.getKeyForTokenType(TokenType.id_token)) ?? undefined,
      refresh_token: this.storage.getItem(this.getKeyForTokenType(TokenType.refresh_token)) ?? undefined,
      scopes: this.storage.getItem(this.scopes)?.split(',') ?? undefined,
    };
  }

  getScopes(): string[] | undefined {
    return this.storage.getItem(this.scopes)?.split(',') ?? undefined;
  }

  deleteToken(tokenType: TokenType): void {
    const key = this.getKeyForTokenType(tokenType);
    this.storage.removeItem(key);
  }

  deleteTokens(): void {
    // Clear JSON mode tokens
    this.storage.removeItem(this.getKeyForTokenType(TokenType.id_token));
    this.storage.removeItem(this.getKeyForTokenType(TokenType.access_token));
    this.storage.removeItem(this.getKeyForTokenType(TokenType.refresh_token));
    this.storage.removeItem(this.scopes);

    // Clear cookie mode ID token
    this.clearIdToken();
  }

  getDeviceId(): string | undefined {
    return this.storage.getItem(this.deviceId) ?? undefined;
  }

  setDeviceId(deviceId: string): void {
    this.storage.setItem(this.deviceId, deviceId);
  }

  deleteDeviceId(): void {
    this.storage.removeItem(this.deviceId);
  }

  setInvitationToken(token: string): void {
    this.storage.setItem(this.invitationToken, token);
  }

  getInvitationToken(): string | undefined {
    return this.storage.getItem(this.invitationToken) ?? undefined;
  }

  deleteInvitationToken(): void {
    this.storage.removeItem(this.invitationToken);
  }

  setPreviousRedirectUrl(url: string): void {
    this.storage.setItem(this.previousRedirectUrl, url);
  }

  getPreviousRedirectUrl(): string | undefined {
    return this.storage.getItem(this.previousRedirectUrl) ?? undefined;
  }

  deletePreviousRedirectUrl(): void {
    this.storage.removeItem(this.previousRedirectUrl);
  }

  // Delivery mode storage methods

  /**
   * Set the token delivery mode in storage
   */
  setDeliveryMode(mode: TokenDeliveryMode): void {
    try {
      this.storage.setItem(this.DELIVERY_MODE_KEY, mode);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  /**
   * Get the token delivery mode from storage
   */
  getDeliveryMode(): TokenDeliveryMode | undefined {
    try {
      const mode = this.storage.getItem(this.DELIVERY_MODE_KEY);
      if (mode && Object.values(TokenDeliveryMode).includes(mode as TokenDeliveryMode)) {
        return mode as TokenDeliveryMode;
      }
    } catch (_error) {
      // Silently ignore storage errors
    }
    return undefined;
  }

  /**
   * Clear the delivery mode from storage
   */
  clearDeliveryMode(): void {
    try {
      this.storage.removeItem(this.DELIVERY_MODE_KEY);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  // ID token storage methods (for cookie mode)

  /**
   * Get the ID token from storage (cookie mode)
   */
  getIdToken(): string | undefined {
    try {
      return this.storage.getItem(this.ID_TOKEN_KEY) ?? undefined;
    } catch (_error) {
      // Silently ignore storage errors
      return undefined;
    }
  }

  /**
   * Set the ID token in storage (cookie mode)
   */
  setIdToken(token: string): void {
    try {
      this.storage.setItem(this.ID_TOKEN_KEY, token);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  /**
   * Clear the ID token from storage
   */
  clearIdToken(): void {
    try {
      this.storage.removeItem(this.ID_TOKEN_KEY);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  // CSRF token storage methods

  /**
   * Get the CSRF token from storage
   */
  getCsrfToken(): string | undefined {
    try {
      return this.storage.getItem(this.CSRF_TOKEN_KEY) ?? undefined;
    } catch (_error) {
      // Silently ignore storage errors
      return undefined;
    }
  }

  /**
   * Set the CSRF token in storage
   */
  setCsrfToken(token: string): void {
    try {
      this.storage.setItem(this.CSRF_TOKEN_KEY, token);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  /**
   * Clear the CSRF token from storage
   */
  clearCsrfToken(): void {
    try {
      this.storage.removeItem(this.CSRF_TOKEN_KEY);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  private getKeyForTokenType(tokenType: TokenType): string {
    return `${this.keyStoragePrefix}${tokenType}`;
  }
}
