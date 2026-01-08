import { AuthAPI } from '../api';
import { StorageManager } from '../storage';
import { ErrorPayload, PassflowEvent, PassflowStore } from '../store';
import { isTokenExpired, parseToken } from '../token';
import type { ParsedTokens, Tokens } from '../types';

export class TokenCacheService {
  tokensCache: Tokens | undefined;
  parsedTokensCache: ParsedTokens | undefined;

  private checkInterval: NodeJS.Timeout | null = null;
  private readonly CHECK_INTERVAL = 60000; // 1 minute (was 10ms)
  private visibilityChangeHandler: (() => void) | null = null;
  isRefreshing = false;
  tokenExpiredFlag = false;

  constructor(
    private storageManager: StorageManager,
    private authApi: AuthAPI,
    private subscribeStore: PassflowStore,
  ) {
    this.storageManager = storageManager;
    this.authApi = authApi;
    this.setupPageUnloadHandler();
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
        this.tokenExpiredFlag = true;
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

      this.subscribeStore.notify(PassflowEvent.Refresh, { tokens: response, parsedTokens: this.getParsedTokens() });
      this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: false });
      this.tokenExpiredFlag = false;
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

    if (this.tokenExpiredFlag) return;

    // Setup Page Visibility API listener
    this.setupVisibilityListener();

    this.checkInterval = setInterval(() => {
      // Skip check if page is hidden
      if (typeof document !== 'undefined' && document.hidden) {
        return;
      }

      if (this.isRefreshing || this.tokenExpiredFlag) return;

      if (this.isExpired() && !this.tokenExpiredFlag) {
        this.tokenExpiredFlag = true;
        this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: true });
        this.stopTokenCheck();
      }
    }, this.CHECK_INTERVAL);
  }

  private setupVisibilityListener() {
    if (typeof document === 'undefined') return;

    // Remove previous listener if exists
    if (this.visibilityChangeHandler) {
      document.removeEventListener('visibilitychange', this.visibilityChangeHandler);
    }

    this.visibilityChangeHandler = () => {
      if (!document.hidden && this.checkInterval) {
        // Page became visible, do immediate check
        if (!this.isRefreshing && !this.tokenExpiredFlag && this.isExpired()) {
          this.tokenExpiredFlag = true;
          this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: true });
          this.stopTokenCheck();
        }
      }
    };

    document.addEventListener('visibilitychange', this.visibilityChangeHandler);
  }

  private setupPageUnloadHandler() {
    if (typeof window === 'undefined') return;

    window.addEventListener('beforeunload', () => {
      this.destroy();
    });
  }

  private stopTokenCheck() {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }

    if (this.visibilityChangeHandler && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this.visibilityChangeHandler);
      this.visibilityChangeHandler = null;
    }
  }

  /**
   * Cleanup method to stop all intervals and remove event listeners.
   * Should be called when the service is no longer needed.
   */
  destroy() {
    this.stopTokenCheck();
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

  getTokens() {
    return this.tokensCache;
  }

  async getTokensWithRefresh() {
    try {
      if (!this.tokensCache) return this.tokensCache;

      const access = parseToken(this.tokensCache.access_token);

      if (isTokenExpired(access) && !this.tokenExpiredFlag) {
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

  getParsedTokens() {
    return this.parsedTokensCache;
  }

  isExpired() {
    if (!this.tokensCache) return true;
    const access = parseToken(this.tokensCache.access_token);
    return isTokenExpired(access);
  }
}
