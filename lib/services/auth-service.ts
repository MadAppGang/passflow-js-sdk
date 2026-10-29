import axios from 'axios';
import {
  AuthAPI,
  PassflowAuthorizationResponse,
  PassflowError,
  PassflowFederatedAuthExtendedPayload,
  PassflowFederatedAuthPayload,
  PassflowPasskeyAuthenticateStartPayload,
  PassflowPasskeyRegisterStartPayload,
  PassflowPasswordlessResponse,
  PassflowPasswordlessSignInCompletePayload,
  PassflowPasswordlessSignInPayload,
  PassflowSendPasswordResetEmailPayload,
  PassflowSignInPayload,
  PassflowSignUpPayload,
  PassflowSuccessResponse,
  PassflowValidationResponse,
  TokenExchangeConfig,
  type UpgradeRefreshField,
  getOSFromDeviceType,
} from '../api';
import { DeviceService } from '../device';
import { type PlatformAdapter, PopupClosedError } from '../platform';
import { webAdapter } from '../platform';
import { StorageManager } from '../storage';
import { ErrorPayload, PassflowEvent, PassflowStore } from '../store';
import { TokenType, isTokenExpired, parseToken } from '../token';
import { TokenDeliveryManager, TokenDeliveryMode } from '../token/delivery-manager';
import { ParsedTokens, Tokens } from '../types';
import { UpgradeSessionChangedError, UpgradeTransportError } from '../upgrade/errors';
import { type UpgradeSessionPin, readSessionPin, sessionPinMatches } from '../upgrade/session';
import { isValidEmail, isValidPhoneNumber, isValidUsername } from '../utils/validation';
import { TokenCacheService } from './token-cache-service';

/**
 * Service for handling authentication related functionality
 */
export class AuthService {
  private tokenDeliveryManager: TokenDeliveryManager;
  private tokenExchangeConfig?: TokenExchangeConfig;

  constructor(
    private authApi: AuthAPI,
    private deviceService: DeviceService,
    private storageManager: StorageManager,
    private subscribeStore: PassflowStore,
    private tokenCacheService: TokenCacheService,
    private scopes: string[],
    private createTenantForNewUser: boolean,
    private url: string,
    private sessionCallbacks: {
      createSession?: ({ tokens, parsedTokens }: { tokens?: Tokens; parsedTokens?: ParsedTokens }) => Promise<void>;
      expiredSession?: () => Promise<void>;
    },
    private appId?: string,
    tokenExchangeConfig?: TokenExchangeConfig,
    private platform: PlatformAdapter = webAdapter,
  ) {
    this.tokenExchangeConfig = tokenExchangeConfig;
    this.tokenDeliveryManager = new TokenDeliveryManager(storageManager);

    // If token exchange is enabled, set BFF mode immediately
    if (tokenExchangeConfig?.enabled) {
      this.tokenDeliveryManager.setMode(TokenDeliveryMode.BFF);
    }

    // Initialize session state on page load (cookie/BFF mode only)
    this.initializeSession();
  }

  /**
   * Initialize session state on page load for cookie/BFF mode
   */
  private async initializeSession(): Promise<void> {
    if (this.tokenDeliveryManager.isCookieMode() || this.tokenDeliveryManager.isBFFMode()) {
      // Cookie/BFF mode: validate session with server
      await this.restoreSession();
    }
  }

  /**
   * Restore session for cookie/BFF mode on page load
   * Validates that HttpOnly cookies are still valid
   * @returns true if session is valid, false otherwise
   */
  async restoreSession(): Promise<boolean> {
    // BFF mode: validate session with BFF endpoint
    if (this.tokenDeliveryManager.isBFFMode() && this.tokenExchangeConfig?.statusUrl) {
      try {
        const response = await fetch(this.tokenExchangeConfig.statusUrl, {
          method: 'GET',
          credentials: 'include', // Include httpOnly cookies
        });

        if (response.ok) {
          const data = await response.json();
          if (data.authenticated) {
            this.tokenDeliveryManager.setSessionValid();
            return true;
          }
        }

        this.tokenDeliveryManager.setSessionInvalid();
        return false;
      } catch (_error) {
        this.tokenDeliveryManager.setSessionInvalid();
        return false;
      }
    }

    if (!this.tokenDeliveryManager.isCookieMode()) {
      return false; // Only applicable to cookie mode
    }

    try {
      // Call lightweight endpoint to validate session
      // This uses the HttpOnly cookies automatically
      const response = await this.authApi.validateSession();

      if (response.valid) {
        this.tokenDeliveryManager.setSessionValid();

        // If response includes user info, emit event
        if (response.user) {
          this.subscribeStore.notify(PassflowEvent.SessionRestored, response.user);
        }

        return true;
      } else {
        this.tokenDeliveryManager.setSessionInvalid();
        return false;
      }
    } catch (_error) {
      // Session invalid or network error
      this.tokenDeliveryManager.setSessionInvalid();
      return false;
    }
  }

  /**
   * Process successful authentication response
   * Handles token storage, session state, CSRF tokens
   * In BFF mode, forwards tokens to BFF server
   */
  private async processAuthResponse(response: PassflowAuthorizationResponse, scopes: string[]): Promise<void> {
    // BFF mode overrides server-returned delivery mode
    if (this.tokenExchangeConfig?.enabled) {
      // Don't change mode from BFF
    } else if ('token_delivery' in response && response.token_delivery) {
      // Detect and update delivery mode from server
      this.tokenDeliveryManager.setMode(response.token_delivery as TokenDeliveryMode);
    }

    // Mark session as valid after successful auth
    this.tokenDeliveryManager.setSessionValid();

    // BFF mode: forward tokens to BFF server
    if (this.tokenDeliveryManager.isBFFMode() && this.tokenExchangeConfig?.callbackUrl) {
      await this.forwardTokensToBFF(response);
    }

    // Save tokens (conditional based on delivery mode)
    // In BFF mode, only ID token is saved locally
    response.scopes = scopes;
    this.storageManager.saveTokens(response, this.tokenDeliveryManager.getMode());
    this.tokenCacheService.setTokensCache(response);

    // Store CSRF token if present (cookie mode)
    if (response.csrf_token) {
      this.storageManager.setCsrfToken(response.csrf_token);
    }
  }

  /**
   * Reports whether a sign-in response is still waiting on its second factor,
   * and when it is, hands the 2FA token on.
   *
   * Every sign-in path can end this way: the server answers with a
   * `tfa_token` (or `requires_2fa`) in place of tokens. That response is not
   * a session, so on `true` the caller returns it as it is — without
   * `processAuthResponse`, a `SignIn`/`Register` event or a session check.
   * The `TwoFactorRequired` event is what the TwoFactorService listens to, so
   * its verify and recovery calls can carry the token.
   */
  private handlePendingSecondFactor(
    response: Pick<PassflowAuthorizationResponse, 'requires_2fa' | 'challenge_id' | 'tfa_token'>,
    email?: string,
  ): boolean {
    if (response.requires_2fa !== true && !response.tfa_token) {
      return false;
    }
    this.subscribeStore.notify(PassflowEvent.TwoFactorRequired, {
      email: email || '',
      challengeId: response.challenge_id || '',
      tfaToken: response.tfa_token || '',
    });
    return true;
  }

  /**
   * Forward tokens to BFF server for httpOnly cookie storage
   */
  private async forwardTokensToBFF(tokens: PassflowAuthorizationResponse): Promise<void> {
    if (!this.tokenExchangeConfig?.callbackUrl) {
      return;
    }
    const response = await fetch(this.tokenExchangeConfig.callbackUrl, {
      method: 'POST',
      credentials: 'include', // Include/set httpOnly cookies
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        id_token: tokens.id_token,
        // expires_in is returned by the server but not typed in the SDK
        expires_in: (tokens as Record<string, unknown>).expires_in,
      }),
    });

    if (!response.ok) {
      throw new Error(`BFF token storage failed: ${response.status}`);
    }
  }

  async signIn(payload: PassflowSignInPayload): Promise<PassflowAuthorizationResponse> {
    // Validate input before API call
    if ('email' in payload && payload.email) {
      if (!isValidEmail(payload.email)) {
        const error = new Error('Invalid email format');
        const errorPayload: ErrorPayload = {
          message: 'Invalid email format',
          originalError: error,
          code: 'VALIDATION_ERROR',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        throw error;
      }
    }

    if ('username' in payload && payload.username) {
      if (!isValidUsername(payload.username)) {
        const error = new Error(
          'Invalid username format. Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens',
        );
        const errorPayload: ErrorPayload = {
          message:
            'Invalid username format. Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens',
          originalError: error,
          code: 'VALIDATION_ERROR',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        throw error;
      }
    }

    if ('phone' in payload && payload.phone) {
      if (!isValidPhoneNumber(payload.phone)) {
        const error = new Error('Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)');
        const errorPayload: ErrorPayload = {
          message: 'Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)',
          originalError: error,
          code: 'VALIDATION_ERROR',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        throw error;
      }
    }

    this.subscribeStore.notify(PassflowEvent.SignInStart, { email: payload.email });
    const deviceId = this.deviceService.getDeviceId();
    const os = getOSFromDeviceType(this.platform.getDeviceType());
    payload.scopes = payload.scopes ?? this.scopes;

    try {
      const response = await this.authApi.signIn(payload, deviceId, os);
      if (this.handlePendingSecondFactor(response, payload.email)) {
        return response;
      }

      await this.processAuthResponse(response, payload.scopes);
      this.subscribeStore.notify(PassflowEvent.SignIn, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Sign in failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async signUp(payload: PassflowSignUpPayload): Promise<PassflowAuthorizationResponse> {
    // Validate user input before API call
    if (payload.user.email && !isValidEmail(payload.user.email)) {
      const error = new Error('Invalid email format');
      const errorPayload: ErrorPayload = {
        message: 'Invalid email format',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }

    if (payload.user.phone_number && !isValidPhoneNumber(payload.user.phone_number)) {
      const error = new Error('Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)');
      const errorPayload: ErrorPayload = {
        message: 'Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }

    this.subscribeStore.notify(PassflowEvent.RegisterStart, { email: payload.user.email });
    payload.scopes = payload.scopes ?? this.scopes;
    payload.create_tenant = this.createTenantForNewUser;

    try {
      const response = await this.authApi.signUp(payload);
      if (this.handlePendingSecondFactor(response, payload.user.email)) {
        return response;
      }

      await this.processAuthResponse(response, payload.scopes);
      this.subscribeStore.notify(PassflowEvent.Register, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Sign up failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async passwordlessSignIn(payload: PassflowPasswordlessSignInPayload): Promise<PassflowPasswordlessResponse> {
    // Validate input before API call
    if (payload.email && !isValidEmail(payload.email)) {
      const error = new Error('Invalid email format');
      const errorPayload: ErrorPayload = {
        message: 'Invalid email format',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }

    if (payload.phone && !isValidPhoneNumber(payload.phone)) {
      const error = new Error('Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)');
      const errorPayload: ErrorPayload = {
        message: 'Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }

    this.subscribeStore.notify(PassflowEvent.SignInStart, { email: payload.email });
    payload.scopes = payload.scopes ?? this.scopes;
    const deviceId = this.deviceService.getDeviceId();
    const os = getOSFromDeviceType(this.platform.getDeviceType());

    try {
      const response = await this.authApi.passwordlessSignIn(payload, deviceId, os);
      // Don't emit SignIn event yet since this is just the first step (magic link sent)
      // We'll emit SignIn when passwordlessSignInComplete is called
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to send passwordless sign-in link',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async passwordlessSignInComplete(payload: PassflowPasswordlessSignInCompletePayload): Promise<PassflowValidationResponse> {
    this.subscribeStore.notify(PassflowEvent.SignInStart, {});
    payload.scopes = payload.scopes ?? this.scopes;
    payload.device = this.deviceService.getDeviceId();

    try {
      const response = await this.authApi.passwordlessSignInComplete(payload);
      if (this.handlePendingSecondFactor(response)) {
        return response;
      }

      await this.processAuthResponse(response, payload.scopes);
      this.subscribeStore.notify(PassflowEvent.SignIn, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Passwordless sign in failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async logOut() {
    // BFF mode: call BFF logout endpoint to clear httpOnly cookies
    if (this.tokenDeliveryManager.isBFFMode() && this.tokenExchangeConfig?.logoutUrl) {
      try {
        const response = await fetch(this.tokenExchangeConfig.logoutUrl, {
          method: 'POST',
          credentials: 'include', // Include httpOnly cookies
        });

        if (!response.ok) {
          // Logout endpoint returned error - ignore and continue with local cleanup
          // Server-side session cleanup is best-effort, local cleanup is critical
        }
      } catch (_error) {
        // Network error during logout - ignore and continue with local cleanup
        // User experience is better if we silently handle logout failures
      }
    } else {
      // Regular mode: call passflow logout API
      const refreshToken = this.storageManager.getToken(TokenType.refresh_token);
      const deviceId = this.storageManager.getDeviceId();

      try {
        // Call logout API (works in both cookie and JSON modes)
        // Cookie mode: server reads refresh token from HttpOnly cookie
        // JSON mode: uses refresh_token from storage
        const response = await this.authApi.logOut(deviceId, refreshToken, !this.appId);
        if (response.status !== 'ok') {
          throw new Error('Logout failed');
        }
      } catch (_error) {
        // Logout API call failed - ignore and continue with local cleanup
        // User experience is better if we silently handle logout failures
      }
    }

    // Clear all local state (both modes)
    this.storageManager.deleteTokens();
    this.storageManager.clearIdToken();
    this.storageManager.clearCsrfToken();
    this.tokenDeliveryManager.reset();
    this.subscribeStore.notify(PassflowEvent.SignOut, {});
  }

  /**
   * The session and user identity this client currently holds, or `undefined`
   * when none is readable.
   *
   * Read from the stored access token's claims, which is the same source every
   * other client-side session fact comes from. In a delivery mode that keeps
   * the access token out of reach — a cookie-mode or BFF session — there is
   * nothing to read and the answer is `undefined`.
   */
  readSessionPin(): UpgradeSessionPin | undefined {
    const token = this.storageManager.getToken(TokenType.access_token);
    if (!token) {
      return undefined;
    }
    try {
      return readSessionPin(parseToken(token) as { sub?: unknown; sid?: unknown });
    } catch {
      return undefined;
    }
  }

  /**
   * Refuses to APPLY tokens that belong to a different principal (§13.4
   * revision 6 / H2).
   *
   * Called immediately before the rotated tokens are written, which is the only
   * place the check cannot be bypassed: the epoch guard around `prepare` and
   * `commit` runs before the server call, and token application happens after
   * it returns, so a logout and re-login in between let user A's flight write
   * over user B's session.
   *
   * It throws `UpgradeSessionChangedError`, so the elevation terminates as
   * §13.3's `session changed mid-flight` on every surface — the outcome class
   * itself, not a transport failure that happens to carry the kind: this is the
   * only entry point into token application, so a caller holding the promise
   * directly (`AuthService.refreshToken`) must see the same `code` a waiter
   * behind the controller does. It does NOT invalidate
   * anything: `setSessionInvalid()` runs off a positive allow-list elsewhere,
   * and the live user is never logged out as a side effect of someone else's
   * abandoned flight. Fail-closed on token application, fail-open on session
   * state — two different axes.
   */
  private assertSessionPin(pin: UpgradeSessionPin | undefined): void {
    if (!pin) {
      // No pin was captured when the flight started, which means this delivery
      // mode exposes no readable identity at all. There is nothing to compare,
      // so the epoch guard is the only protection in force — stated, not
      // silently assumed.
      return;
    }
    if (sessionPinMatches(pin, this.readSessionPin())) {
      return;
    }
    // biome-ignore lint/suspicious/noConsole: §13.4 revision 6 / C41 requires one visible `warn` on this path. A discarded elevation that left no trace is indistinguishable from a feature that silently never fired, and this is the fail-open diagnostic rule the whole module is built on.
    console.warn(
      '[passflow] the session or user changed while a step-up upgrade was in flight; the elevated tokens were discarded and the live session was left untouched.',
    );
    throw new UpgradeSessionChangedError('The session changed during verification, so the elevated tokens were discarded');
  }

  /**
   * Refreshes the session, optionally committing an assurance upgrade.
   *
   * This is the ONLY token-storing path for all four delivery modes, which is
   * why the upgrade commit goes through here rather than posting to
   * `/auth/refresh` directly: it saves the rotated tokens, updates the cache and
   * emits `Refresh`. Bypassing it would elevate the session on the server and
   * leave the client holding stale tokens — everything looks fine until the next
   * request 401s.
   *
   * An upgrade commit changes the error handling in one specific way: a 4xx is
   * NOT treated as a dead session. The server answers a wrong code with a 401,
   * and tearing the session down there is the logout-at-step-up defect. The
   * upgrade transport classifies those failures and invalidates the session
   * itself when the 401 turns out to be a genuine expiry.
   */
  async refreshToken(upgrade?: UpgradeRefreshField, pin?: UpgradeSessionPin): Promise<PassflowAuthorizationResponse> {
    this.subscribeStore.notify(PassflowEvent.RefreshStart, {});

    // BFF mode cannot carry an upgrade, and the refusal has to come BEFORE the
    // network call: the BFF refresh endpoint is the customer's own, posted to
    // with an empty body, so there is nowhere to put `{upgrade:{...}}` without a
    // customer-backend change. Refusing early is what lets the UI show
    // "unavailable" instead of asking for a code that can never be submitted.
    if (upgrade && this.tokenDeliveryManager.isBFFMode()) {
      throw new UpgradeTransportError({
        kind: 'unavailable',
        message: 'Step-up verification cannot be committed through a BFF refresh endpoint',
      });
    }

    // BFF mode: call BFF refresh endpoint
    if (this.tokenDeliveryManager.isBFFMode() && this.tokenExchangeConfig?.refreshUrl) {
      try {
        const response = await fetch(this.tokenExchangeConfig.refreshUrl, {
          method: 'POST',
          credentials: 'include', // Include httpOnly cookies
        });

        if (!response.ok) {
          this.tokenDeliveryManager.setSessionInvalid();
          throw new Error('BFF token refresh failed');
        }

        const data = await response.json();

        // Update session state
        this.tokenDeliveryManager.setSessionValid();

        // If BFF returns id_token, update local storage
        if (data.id_token) {
          this.storageManager.setIdToken(data.id_token);
        }

        this.subscribeStore.notify(PassflowEvent.Refresh, {
          tokens: data,
          parsedTokens: this.tokenCacheService.getParsedTokens(),
        });
        this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: false });
        this.tokenCacheService.isRefreshing = false;
        this.tokenCacheService.tokenExpiredFlag = false;
        return data;
      } catch (error) {
        this.tokenDeliveryManager.setSessionInvalid();
        const errorPayload: ErrorPayload = {
          message: error instanceof Error ? error.message : 'Token refresh failed',
          originalError: error,
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        throw error;
      }
    }

    // Cookie mode: Server reads refresh token from HttpOnly cookie
    if (this.tokenDeliveryManager.isCookieMode()) {
      try {
        // Call refresh endpoint - browser sends HttpOnly cookies automatically
        const response = upgrade
          ? await this.authApi.refreshToken('', this.scopes, undefined, upgrade)
          : await this.authApi.refreshToken('', this.scopes);

        // The pin is verified BEFORE anything is applied — see `assertSessionPin`.
        this.assertSessionPin(pin);

        // Update session state
        this.tokenDeliveryManager.setSessionValid();

        // Process response (stores ID token, CSRF token)
        await this.processAuthResponse(response, this.scopes);

        this.subscribeStore.notify(PassflowEvent.Refresh, {
          tokens: response,
          parsedTokens: this.tokenCacheService.getParsedTokens(),
        });
        this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: false });
        this.tokenCacheService.isRefreshing = false;
        this.tokenCacheService.tokenExpiredFlag = false;
        return response;
      } catch (error) {
        // A failed upgrade commit is not a failed session: the four recoverable
        // upgrade errors all arrive as a bare 401. Classification — and the
        // invalidation a genuine expiry still deserves — belongs to the upgrade
        // transport, which knows it issued the request.
        if (!upgrade) {
          this.tokenDeliveryManager.setSessionInvalid();
        }
        const errorPayload: ErrorPayload = {
          message: error instanceof Error ? error.message : 'Token refresh failed',
          originalError: error,
          code: error instanceof PassflowError ? error.id : undefined,
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        throw error;
      }
    }

    // JSON mode: Existing behavior
    const tokens = this.storageManager.getTokens();
    if (!tokens) {
      const error = new Error('No tokens found');
      const errorPayload: ErrorPayload = {
        message: 'No tokens found',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    } else if (!tokens?.refresh_token) {
      const error = new Error('No refresh token found');
      const errorPayload: ErrorPayload = {
        message: 'No refresh token found',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }

    const oldScopes = tokens?.scopes ?? this.scopes;
    try {
      // The `upgrade` argument is passed only when there is one, rather than as
      // an explicit `undefined`: the ordinary refresh call stays byte-identical
      // to what it was before step-up existed.
      const refresh = tokens?.refresh_token ?? '';
      const access = tokens?.access_token;
      const response = upgrade
        ? await this.authApi.refreshToken(refresh, oldScopes, access, upgrade)
        : await this.authApi.refreshToken(refresh, oldScopes, access);
      // The pin is verified BEFORE the tokens are written — see
      // `assertSessionPin`. This is the line H2 exists for: `saveTokens` is the
      // moment user A's rotated tokens would land in user B's storage.
      this.assertSessionPin(pin);

      response.scopes = oldScopes;
      this.storageManager.saveTokens(response);
      this.tokenCacheService.setTokensCache(response);
      this.subscribeStore.notify(PassflowEvent.Refresh, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: false });
      this.tokenCacheService.isRefreshing = false;
      this.tokenCacheService.tokenExpiredFlag = false;
      this.tokenCacheService.startTokenCheck();
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Token refresh failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
        details:
          axios.isAxiosError(error) && error.response
            ? {
                status: error.response.status,
                data: error.response.data,
              }
            : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);

      // Check if this is an auth error (4xx) indicating session is invalid
      const is4xxError =
        axios.isAxiosError(error) && error.response?.status && error.response.status >= 400 && error.response.status < 500;

      // On an upgrade commit a 4xx is the server rejecting the PROOF, not the
      // session. Deleting the tokens here would log the user out for mistyping
      // six digits — the defect this flow exists to fix.
      if (is4xxError && !upgrade) {
        // Session is invalid - mark as expired and clean up
        this.tokenCacheService.tokenExpiredFlag = true;
        this.tokenCacheService.setTokensCache(undefined);
        this.storageManager.deleteTokens();
        this.subscribeStore.notify(PassflowEvent.SessionExpired, { reason: 'refresh_failed' });
      }

      if (error instanceof PassflowError) {
        throw error;
      } else if (is4xxError && !upgrade) {
        // Rethrown verbatim on the upgrade path instead: the status is the only
        // thing left to classify by once the server sent no error envelope, and
        // flattening it into a generic Error destroys that.
        throw new Error(`Getting unknown error message from server with code:${error.response?.status}`);
      } else {
        throw error;
      }
    }
  }

  async sendPasswordResetEmail(payload: PassflowSendPasswordResetEmailPayload): Promise<PassflowSuccessResponse> {
    try {
      return await this.authApi.sendPasswordResetEmail(payload);
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to send password reset email',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async resetPassword(newPassword: string, scopes?: string[]): Promise<PassflowAuthorizationResponse> {
    this.subscribeStore.notify(PassflowEvent.SignInStart, {});
    const urlParams = new URLSearchParams(this.platform.getCurrentUrl()?.search ?? '');
    const resetToken = urlParams.get('token') ?? undefined;
    const sscopes = scopes ?? this.scopes;

    try {
      const response = await this.authApi.resetPassword(newPassword, sscopes, resetToken);
      if (this.handlePendingSecondFactor(response)) {
        return response;
      }

      await this.processAuthResponse(response, sscopes);
      this.subscribeStore.notify(PassflowEvent.SignIn, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Password reset failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async passkeyRegister(payload: PassflowPasskeyRegisterStartPayload): Promise<PassflowAuthorizationResponse> {
    if (!this.platform.passkeys) throw new Error('Passkeys are not supported on this platform');
    this.subscribeStore.notify(PassflowEvent.RegisterStart, {});
    const deviceId = this.deviceService.getDeviceId();
    const os = getOSFromDeviceType(this.platform.getDeviceType());
    payload.scopes = payload.scopes ?? this.scopes;
    payload.create_tenant = this.createTenantForNewUser;

    try {
      const { challenge_id, publicKey } = await this.authApi.passkeyRegisterStart(payload, deviceId, os, !this.appId);
      // user handle should be base64 encoded for simplewebauthn lib we are using
      publicKey.user.id = this.platform.btoa(publicKey.user.id);
      const webauthn = await this.platform.passkeys.startRegistration(publicKey);
      if (!webauthn) throw new Error('Passkey registration was not completed');

      const responseRegisterComplete = await this.authApi.passkeyRegisterComplete(
        webauthn,
        deviceId,
        challenge_id,
        !this.appId,
      );
      if (this.handlePendingSecondFactor(responseRegisterComplete)) {
        return responseRegisterComplete;
      }

      await this.processAuthResponse(responseRegisterComplete, payload.scopes);
      this.subscribeStore.notify(PassflowEvent.Register, {
        tokens: responseRegisterComplete,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return responseRegisterComplete;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Passkey registration failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async passkeyAuthenticate(payload: PassflowPasskeyAuthenticateStartPayload): Promise<PassflowAuthorizationResponse> {
    if (!this.platform.passkeys) throw new Error('Passkeys are not supported on this platform');
    this.subscribeStore.notify(PassflowEvent.SignInStart, {});
    const deviceId = this.deviceService.getDeviceId();
    const os = getOSFromDeviceType(this.platform.getDeviceType());
    payload.scopes = payload.scopes ?? this.scopes;

    try {
      const { challenge_id, publicKey } = await this.authApi.passkeyAuthenticateStart(payload, deviceId, os, !this.appId);
      const webauthn = await this.platform.passkeys.startAuthentication(publicKey);
      if (!webauthn) throw new Error('Passkey authentication was not completed');

      const responseAuthenticateComplete = await this.authApi.passkeyAuthenticateComplete(
        webauthn,
        deviceId,
        challenge_id,
        !this.appId,
      );
      if (this.handlePendingSecondFactor(responseAuthenticateComplete)) {
        return responseAuthenticateComplete;
      }

      if ('access_token' in responseAuthenticateComplete) {
        await this.processAuthResponse(responseAuthenticateComplete, payload.scopes);
        this.subscribeStore.notify(PassflowEvent.SignIn, {
          tokens: responseAuthenticateComplete,
          parsedTokens: this.tokenCacheService.getParsedTokens(),
        });
        await this.submitSessionCheck();
      }

      return responseAuthenticateComplete;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Passkey authentication failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  createFederatedAuthUrl(payload: PassflowFederatedAuthExtendedPayload): string {
    const passflowPathWithProvider = `/auth/federated/start/${payload.provider}`;

    if (!this.appId) throw new Error('AppId is required for federated auth');
    const sscopes = payload.scopes ?? this.scopes;

    const params: Record<string, string> = {
      scopes: sscopes.join(' '),
      redirect_url: payload.redirect_url ?? this.platform.getCurrentUrl()?.origin ?? '',
      appId: this.appId,
      ...(payload.invite_token ? { invite_token: payload.invite_token } : {}),
      ...(payload.create_tenant ? { create_tenant: payload.create_tenant.toString() } : {}),
      ...(payload.device ? { device: payload.device } : {}),
    };

    const url = new URL(passflowPathWithProvider, this.url);
    const queryParams = new URLSearchParams(params);
    url.search = queryParams.toString();

    return url.toString();
  }

  async federatedAuthWithPopup(payload: PassflowFederatedAuthPayload): Promise<void> {
    this.subscribeStore.notify(PassflowEvent.SignInStart, { provider: payload.provider });
    const sscopes = payload.scopes ?? this.scopes;
    const deviceId = this.deviceService.getDeviceId();
    const passflowURL = this.createFederatedAuthUrl({ ...payload, scopes: sscopes, device: deviceId });

    try {
      const result = await this.platform.openAuthUrl(passflowURL, {
        mode: 'popup',
        expectedReturnOrigin: this.platform.getCurrentUrl()?.origin ?? '',
      });

      // A sign-in that owes its second factor comes back with the 2FA token
      // in the fragment, never the query, and with no tokens. Nothing is saved
      // and the page is not navigated: it stays to ask for the factor.
      const hashParams = new URLSearchParams(result.callbackHash.replace(/^#/, ''));
      if (this.handlePendingSecondFactor({ tfa_token: hashParams.get('tfa_token') ?? undefined })) {
        return;
      }

      const urlParams = new URLSearchParams(result.callbackSearch);
      const access_token = urlParams.get('access_token') || '';
      const refresh_token = urlParams.get('refresh_token') || '';
      const id_token = urlParams.get('id_token') || '';

      const tokensData = {
        access_token,
        refresh_token: refresh_token || undefined,
        id_token: id_token || undefined,
        scopes: sscopes,
      };

      await this.processAuthResponse(tokensData, sscopes);
      this.subscribeStore.notify(PassflowEvent.SignIn, {
        tokens: tokensData,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      this.platform.navigateTo(this.platform.getCurrentUrl()?.origin ?? '');
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Authentication failed',
        code: error instanceof PopupClosedError ? 'POPUP_CLOSED' : 'AUTH_FAILED',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
    }
  }

  federatedAuthWithRedirect(payload: PassflowFederatedAuthPayload): void {
    this.subscribeStore.notify(PassflowEvent.SignInStart, { provider: payload.provider });
    const sscopes = payload.scopes ?? this.scopes;
    const deviceId = this.deviceService.getDeviceId();
    const passflowURL = this.createFederatedAuthUrl({ ...payload, scopes: sscopes, device: deviceId });
    this.platform.navigateTo(passflowURL);
  }

  // Helper methods for authentication UI redirect
  authRedirectUrl(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): string {
    try {
      const { url, redirectUrl, scopes, appId } = options ?? {};
      const externalUrl = new URL(url ?? this.url);
      // add web to the pathname if it's not there
      externalUrl.pathname = (externalUrl.pathname.endsWith('/') ? externalUrl.pathname : externalUrl.pathname + '/') + 'web';
      const sscopes = scopes ?? this.scopes;
      const params: Record<string, string> = {
        appId: appId ?? this.appId ?? '',
        redirectto: redirectUrl ?? this.platform.getCurrentUrl()?.href ?? '',
        scopes: sscopes.join(','),
      };

      const queryParams = new URLSearchParams(params);
      externalUrl.search = queryParams.toString();
      return externalUrl.toString();
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to create auth redirect URL',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  authRedirect(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): void {
    try {
      this.platform.navigateTo(this.authRedirectUrl(options));
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to redirect to auth page',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  /**
   * Check if user is authenticated
   * CRITICAL: Cookie/BFF mode checks ID token + session state, NOT access_token
   */
  isAuthenticated(parsedTokens: ParsedTokens): boolean {
    try {
      if (this.tokenDeliveryManager.isCookieMode() || this.tokenDeliveryManager.isBFFMode()) {
        // Cookie/BFF mode: Check for ID token presence + session validity
        const hasIdToken = !!parsedTokens?.id_token || !!this.storageManager.getIdToken();
        const sessionValid = this.tokenDeliveryManager.isSessionValid();
        const sessionUnknown = this.tokenDeliveryManager.isSessionUnknown();

        // Trust session if:
        // 1. We have ID token (proves we authenticated at some point)
        // 2. Session is valid (haven't received 401) OR
        // 3. Session is unknown (haven't tried yet, optimistic)
        return hasIdToken && (sessionValid || sessionUnknown);
      }

      // JSON mode: existing logic (check access/refresh token expiry)
      if (!parsedTokens || !parsedTokens.access_token) return false;

      return (
        !isTokenExpired(parsedTokens.access_token) ||
        (parsedTokens.refresh_token !== undefined && !isTokenExpired(parsedTokens.refresh_token))
      );
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to check authentication status',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      return false;
    }
  }

  /**
   * Handle session check and callbacks
   */
  async submitSessionCheck(doRefresh = false): Promise<Tokens | undefined> {
    let tokens;
    let parsedTokens;
    try {
      tokens = await this.getTokens(doRefresh);
      parsedTokens = this.tokenCacheService.getParsedTokens();
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error || error instanceof PassflowError ? error.message : 'Session check failed',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      tokens = undefined;
    }

    if (tokens && this.sessionCallbacks.createSession) {
      await this.sessionCallbacks.createSession({ tokens, parsedTokens });
    }

    if (!tokens && this.sessionCallbacks.expiredSession) {
      await this.sessionCallbacks.expiredSession();
    }

    return tokens;
  }

  /**
   * Get tokens and refresh if needed
   * Cookie/BFF mode: Returns ID token only (access/refresh in HttpOnly cookies)
   * JSON mode: Returns all tokens from localStorage
   */
  async getTokens(doRefresh: boolean): Promise<Tokens | undefined> {
    try {
      // Cookie/BFF mode: Server manages access/refresh tokens in HttpOnly cookies
      if (this.tokenDeliveryManager.isCookieMode() || this.tokenDeliveryManager.isBFFMode()) {
        const tokens = this.storageManager.getTokens();
        // In cookie/BFF mode, we only have ID token in localStorage
        if (!tokens?.id_token) return undefined;

        // If session is invalid and refresh requested, try refresh
        if (this.tokenDeliveryManager.isSessionInvalid() && doRefresh) {
          return await this.refreshToken();
        }

        // Return tokens (ID token only, access/refresh are in cookies)
        return tokens;
      }

      // JSON mode: Existing behavior
      const tokens = this.storageManager.getTokens();
      // we have no token in storage
      if (!tokens || !tokens.access_token) return undefined;

      const access = parseToken(tokens.access_token);

      if (isTokenExpired(access)) {
        // we have expired token and we need to refresh it or throw error if it's not possible
        if (doRefresh) return await this.refreshToken();

        // we need return undefined here, because we have expired token and we no need to refresh it
        return undefined;
      } else {
        return tokens;
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
}
