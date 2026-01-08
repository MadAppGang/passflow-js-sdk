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
import { Tokens } from '../types';

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

  private storage: Storage;

  constructor({ storage, prefix }: StorageManagerParams = {}) {
    this.storage = storage ?? localStorage;
    this.keyStoragePrefix = prefix ? `${prefix}_` : '';
  }

  saveTokens(tokens: Tokens): void {
    const { id_token, access_token, refresh_token, scopes } = tokens;
    if (id_token) this.storage.setItem(this.getKeyForTokenType(TokenType.id_token), id_token);
    if (access_token) this.storage.setItem(this.getKeyForTokenType(TokenType.access_token), access_token);
    if (refresh_token) this.storage.setItem(this.getKeyForTokenType(TokenType.refresh_token), refresh_token);
    if (scopes) this.storage.setItem(this.scopes, scopes.join(','));
  }

  getToken(tokenType: TokenType): string | undefined {
    const key = this.getKeyForTokenType(tokenType);
    return this.storage.getItem(key) ?? undefined;
  }

  getTokens(): Tokens | undefined {
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
    this.storage.removeItem(this.getKeyForTokenType(TokenType.id_token));
    this.storage.removeItem(this.getKeyForTokenType(TokenType.access_token));
    this.storage.removeItem(this.getKeyForTokenType(TokenType.refresh_token));
    this.storage.removeItem(this.scopes);
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

  private getKeyForTokenType(tokenType: TokenType): string {
    return `${this.keyStoragePrefix}${tokenType}`;
  }
}
