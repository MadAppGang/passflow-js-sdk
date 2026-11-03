import { AuthAPI } from '../api';
import { notifyError } from '../error-report';
import type { PlatformAdapter } from '../platform';
import { webAdapter } from '../platform';
import type { RefreshController } from '../refresh/controller';
import { StorageManager } from '../storage';
import { OperationErrorPayload, PassflowEvent, PassflowStore } from '../store';
import { isTokenExpired, parseToken } from '../token';
import type { ParsedTokens, Tokens } from '../types';

export class TokenCacheService {
  tokensCache: Tokens | undefined;
  parsedTokensCache: ParsedTokens | undefined;

  private checkInterval: NodeJS.Timeout | null = null;
  private readonly CHECK_INTERVAL = 60000; // 1 minute (was 10ms)
  private unsubscribeForeground: (() => void) | null = null;
  private unsubscribeUnload: (() => void) | null = null;
  private refreshController: Pick<RefreshController, 'refresh' | 'busy'> | undefined;
  /**
   * Set when the expiry check (`initialize()`, the 60 s check, foreground) finds the access token
   * expired, with `TokenCacheExpired{isExpired:true}`. Output only: it never gates a refresh. The
   * refresh controller clears it on every `Refresh`.
   */
  tokenExpiredFlag = false;

  /**
   * `authApi` is no longer used here (the refresh controller sends every refresh); the parameter
   * stays so the constructor's signature does not change.
   */
  constructor(
    private storageManager: StorageManager,
    _authApi: AuthAPI,
    private subscribeStore: PassflowStore,
    private platform: PlatformAdapter = webAdapter,
  ) {
    this.storageManager = storageManager;
    this.setupLifecycleListeners();
  }

  /** Whether this instance has a refresh cycle (waiting, in flight, a retry or a successor pending). */
  get isRefreshing(): boolean {
    return this.refreshController?.busy ?? false;
  }

  /**
   * Connects `getTokensWithRefresh()` to the instance's refresh controller. `Passflow` calls it at
   * construction. Without it, `getTokensWithRefresh()` returns the cache and sends nothing.
   */
  attachRefreshController(controller: Pick<RefreshController, 'refresh' | 'busy'> | undefined): void {
    this.refreshController = controller;
  }

  /**
   * Starts the expiry check. `Passflow.subscribe()` calls it on every subscribe, so it must be
   * safe to repeat:
   * - A filled cache wins over storage. The cache only moves forward (the refresh controller
   *   and its fence own every later change), while storage can still hold an older pair of the
   *   same session (a held tab). Reading storage here would move the cache back.
   * - `TokenCacheExpired{isExpired:true}` fires only when the expired state changes, not on
   *   every call.
   */
  initialize() {
    try {
      const cached = this.tokensCache;
      const tokens = cached ?? this.storageManager.getTokens();
      if (!tokens) {
        // No tokens to watch. Polling would emit spurious TokenCacheExpired
        // events for logged-out users; wait for a sign-in to (re-)initialize.
        return;
      }

      // Cookie mode: access_token may not be in storage (only ID token)
      // In cookie mode, we cache whatever tokens we have (likely just ID token)
      if (!tokens.access_token) {
        if (!cached) this.setTokensCache(tokens);
        this.startTokenCheck();
        return;
      }

      // JSON mode: check access_token expiry
      const access = parseToken(tokens.access_token);

      if (isTokenExpired(access)) {
        this.stopTokenCheck();
        if (!this.tokenExpiredFlag) {
          this.tokenExpiredFlag = true;
          this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: true });
        }
      } else {
        if (!cached) this.setTokensCache(tokens);
        this.startTokenCheck();
      }
    } catch (error) {
      const errorPayload: OperationErrorPayload = {
        operation: 'tokens.load',
        message: error instanceof Error ? error.message : 'Failed to get tokens',
        originalError: error,
      };
      notifyError(this.subscribeStore, errorPayload);
      this.setTokensCache(undefined);
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

  /**
   * Stops the expiry check and its foreground listener. Public so the refresh controller can stop
   * it when a session ends in this tab (it is called optionally: test fakes may lack it).
   */
  stopTokenCheck() {
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

  /**
   * The cached tokens, refreshed first when the access token has expired (trigger `token-check`).
   *
   * It asks the refresh controller, which starts a refresh or joins the one pending, and returns
   * the cache whatever the outcome: the new tokens, the kept ones after a failure that did not end
   * the session, `undefined` once it ended. It never rejects; the controller reports the failure.
   */
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

      if (isTokenExpired(access) && this.refreshController) {
        try {
          await this.refreshController.refresh({ trigger: 'token-check' });
        } catch {
          // Reported by the controller; the tokens it kept (or none, at a session end) are returned.
        }
      }
      return this.tokensCache;
    } catch (error) {
      const errorPayload: OperationErrorPayload = {
        operation: 'tokens.get',
        message: error instanceof Error ? error.message : 'Failed to get tokens',
        originalError: error,
      };
      notifyError(this.subscribeStore, errorPayload);
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
