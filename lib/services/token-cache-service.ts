import { AuthAPI } from '../api';
import type { PlatformAdapter } from '../platform';
import { webAdapter } from '../platform';
import { StorageManager } from '../storage';
import { ErrorPayload, PassflowEvent, PassflowStore } from '../store';
import { isTokenExpired, parseToken } from '../token';
import type { ParsedTokens, Tokens } from '../types';

export class TokenCacheService {
  tokensCache: Tokens | undefined;
  parsedTokensCache: ParsedTokens | undefined;

  private checkInterval: NodeJS.Timeout | null = null;
  private readonly CHECK_INTERVAL = 60000; // 1 minute (was 10ms)
  private unsubscribeForeground: (() => void) | null = null;
  private unsubscribeUnload: (() => void) | null = null;
  isRefreshing = false;
  tokenExpiredFlag = false;

  constructor(
    private storageManager: StorageManager,
    private authApi: AuthAPI,
    private subscribeStore: PassflowStore,
    private platform: PlatformAdapter = webAdapter,
  ) {
    this.storageManager = storageManager;
    this.authApi = authApi;
    this.setupLifecycleListeners();
  }

  initialize() {
    try {
      const tokens = this.storageManager.getTokens();
      if (!tokens) {
        // No tokens to watch. Polling would emit spurious TokenCacheExpired
        // events for logged-out users; wait for a sign-in to (re-)initialize.
        return;
      }

      // Cookie mode: access_token may not be in storage (only ID token)
      // In cookie mode, we cache whatever tokens we have (likely just ID token)
      if (!tokens.access_token) {
        this.setTokensCache(tokens);
        this.startTokenCheck();
        return;
      }

      // JSON mode: check access_token expiry
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

      // Mark session as expired to prevent infinite refresh loops
      this.tokenExpiredFlag = true;
      this.setTokensCache(undefined);
      this.stopTokenCheck();

      // Clear stored tokens since refresh failed
      this.storageManager.deleteTokens();

      // Notify that session has expired - app should redirect to login
      this.subscribeStore.notify(PassflowEvent.SessionExpired, { reason: 'refresh_failed' });
    } finally {
      this.isRefreshing = false;
    }
  }

  startTokenCheck() {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }

    if (this.tokenExpiredFlag) return;

    // Setup lifecycle listeners for foreground/visibility checks
    this.setupLifecycleListeners();

    this.checkInterval = setInterval(() => {
      // Skip check if page is not in foreground
      if (!this.platform.isInForeground()) {
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

  private setupLifecycleListeners(): void {
    // Clean up existing listeners before setting up new ones
    if (this.unsubscribeForeground) {
      this.unsubscribeForeground();
      this.unsubscribeForeground = null;
    }

    this.unsubscribeForeground = this.platform.onForeground(() => {
      if (this.checkInterval && !this.isRefreshing && !this.tokenExpiredFlag && this.isExpired()) {
        this.tokenExpiredFlag = true;
        this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: true });
        this.stopTokenCheck();
      }
    });

    if (!this.unsubscribeUnload) {
      this.unsubscribeUnload = this.platform.onBeforeUnload(() => {
        this.destroy();
      });
    }
  }

  private stopTokenCheck() {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }

    if (this.unsubscribeForeground) {
      this.unsubscribeForeground();
      this.unsubscribeForeground = null;
    }
  }

  /**
   * Cleanup method to stop all intervals and remove event listeners.
   * Should be called when the service is no longer needed.
   */
  destroy() {
    this.stopTokenCheck();
    if (this.unsubscribeUnload) {
      this.unsubscribeUnload();
      this.unsubscribeUnload = null;
    }
  }

  setTokensCache(tokens: Tokens | undefined): void {
    this.tokensCache = tokens;

    // Cookie mode: Only ID token may be available (access/refresh tokens in HttpOnly cookies)
    // JSON mode: All tokens expected
    // Handle partial data gracefully for cookie mode
    if (tokens) {
      // Parse available tokens (some may be undefined in cookie mode)
      this.parsedTokensCache = {
        access_token: tokens.access_token ? parseToken(tokens.access_token) : undefined,
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

      // Cookie mode: access_token may not be available (in HttpOnly cookie)
      // In cookie mode, we cannot check expiry client-side, so just return tokens
      // Server will handle refresh via 401 response and axios interceptor
      if (!this.tokensCache.access_token) {
        return this.tokensCache;
      }

      // JSON mode: check and refresh if needed
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

    // Cookie mode: access_token may not be available (in HttpOnly cookie)
    // In cookie mode, we can't check expiry client-side, so return false
    // and let the server respond with 401 when the cookie expires
    if (!this.tokensCache.access_token) {
      return false; // Assume valid in cookie mode, server will validate
    }

    const access = parseToken(this.tokensCache.access_token);
    return isTokenExpired(access);
  }
}
