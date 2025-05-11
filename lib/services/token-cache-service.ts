import { isTokenExpired, parseToken } from '../token-service';
import type { ParsedTokens, Tokens } from '../types';
import { StorageManager } from '../storage-manager';
import { AuthAPI } from '../api';
import { ErrorPayload, PassflowEvent, PassflowStore } from '../store';

export class TokenCacheService {
  tokensCache: Tokens | undefined;
  parsedTokensCache: ParsedTokens | undefined;

  private checkInterval: NodeJS.Timeout | null = null;
  private readonly CHECK_INTERVAL = 10;
  isRefreshing = false;
  isExpired = false;

  constructor(
    private storageManager: StorageManager,
    private authApi: AuthAPI,
    private subscribeStore: PassflowStore,
  ) {
    this.storageManager = storageManager;
    this.authApi = authApi;
  }

  initialize() {
    try {
      const tokens = this.storageManager.getTokens();
      if (!tokens || !tokens.access_token) {
        this.startTokenCheck();
        return;
      }

      const access = parseToken(tokens.access_token);

      if (isTokenExpired(access)) {
        this.isExpired = true;
        this.stopTokenCheck();
        this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: true });
      } else {
        this.setTokensCache(tokens);
        this.startTokenCheck();
      }
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to get tokens',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      this.setTokensCache(undefined);
    }
  }

  private async refreshTokensCache(tokens: Tokens) {
    if (this.isRefreshing) return;

    try {
      this.isRefreshing = true;
      this.subscribeStore.notify(PassflowEvent.RefreshStart, {});

      const response = await this.authApi.refreshToken(tokens?.refresh_token ?? '', tokens.scopes ?? [], tokens.access_token);
      this.setTokensCache(response);

      this.subscribeStore.notify(PassflowEvent.Refresh, { tokens: response });
      this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: false });
      this.isExpired = false;
      this.startTokenCheck();
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to get tokens',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      this.setTokensCache(undefined);
    } finally {
      this.isRefreshing = false;
    }
  }

  startTokenCheck() {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }

    if (this.isExpired) return;

    this.checkInterval = setInterval(() => {
      if (this.isRefreshing || this.isExpired) return;

      if (this.tokensCacheIsExpired() && !this.isExpired) {
        this.isExpired = true;
        this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: true });
        this.stopTokenCheck();
      }
    }, this.CHECK_INTERVAL);
  }

  private stopTokenCheck() {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  setTokensCache(tokens: Tokens | undefined): void {
    this.tokensCache = tokens;
    if (tokens) {
      this.parsedTokensCache = {
        access_token: parseToken(tokens.access_token),
        id_token: tokens.id_token ? parseToken(tokens.id_token) : undefined,
        refresh_token: tokens.refresh_token ? parseToken(tokens.refresh_token) : undefined,
        scopes: tokens.scopes,
      };
    } else {
      this.parsedTokensCache = undefined;
    }
  }

  getTokensCache() {
    return this.tokensCache;
  }

  async getTokensCacheWithRefresh() {
    try {
      if (!this.tokensCache) return this.tokensCache;

      const access = parseToken(this.tokensCache.access_token);

      if (isTokenExpired(access) && !this.isExpired) {
        await this.refreshTokensCache(this.tokensCache);
        return this.tokensCache;
      } else {
        return this.tokensCache;
      }
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to get tokens',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      return undefined;
    }
  }

  getParsedTokenCache() {
    return this.parsedTokensCache;
  }

  tokensCacheIsExpired() {
    if (!this.tokensCache) return true;
    const access = parseToken(this.tokensCache.access_token);
    return isTokenExpired(access);
  }
}
