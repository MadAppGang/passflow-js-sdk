import { TokenType } from '../token-service';
import { Tokens } from '../types';

export type Storage = {
  setItem: (key: string, value: string) => void;
  getItem: (key: string) => string | null;
  removeItem: (key: string) => void;
};

export class StorageManager {
  readonly idToken = TokenType.id_token;
  readonly accessToken = TokenType.access_token;
  readonly refreshToken = TokenType.refresh_token;
  readonly scopes = 'tokens_scopes';
  readonly deviceId = 'passflowDeviceId';
  readonly invitationToken = 'passflowInvitationToken';
  readonly previousRedirectUrl = 'passflowPreviousRedirectUrl';

  private storage: Storage;

  constructor(storage?: Storage) {
    this.storage = storage ?? localStorage;
  }

  saveTokens(tokens: Tokens): void {
    const { id_token, access_token, refresh_token, scopes } = tokens;
    if (id_token) this.storage.setItem(this.idToken, id_token);
    if (access_token) this.storage.setItem(this.accessToken, access_token);
    if (refresh_token) this.storage.setItem(this.refreshToken, refresh_token);
    if (scopes) this.storage.setItem(this.scopes, scopes.join(','));
  }

  getToken(tokenType: TokenType): string | undefined {
    return this.storage.getItem(tokenType) ?? undefined;
  }

  getTokens(): Tokens | undefined {
    const access = this.storage.getItem(this.accessToken);
    if (!access) return undefined;
    return {
      access_token: access,
      id_token: this.storage.getItem(this.idToken) ?? undefined,
      refresh_token: this.storage.getItem(this.refreshToken) ?? undefined,
      scopes: this.storage.getItem(this.scopes)?.split(',') ?? undefined,
    };
  }

  deleteToken(tokenType: TokenType): void {
    this.storage.removeItem(tokenType);
  }

  deleteTokens(): void {
    this.deleteToken(this.idToken);
    this.deleteToken(this.accessToken);
    this.deleteToken(this.refreshToken);
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
}
