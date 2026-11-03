import {
  AuthAPI,
  getOSFromDeviceType,
  isEmailVerificationStep,
  PassflowAuthorizationResponse,
  PassflowEmailCodePayload,
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
} from '../api';
import { DeviceService } from '../device';
import { notifyError } from '../error-report';
import { createPkcePair, type PkcePair } from '../pkce';
import { type CurrentUrlInfo, type PlatformAdapter, PopupClosedError, webAdapter } from '../platform';
import {
  createRefreshController,
  type RefreshController,
  type RefreshEmit,
  type RefreshEventMap,
  type RefreshTransport,
} from '../refresh/controller';
import { localCoordination, type ResolvedCoordination } from '../refresh/resolve';
import { StorageManager } from '../storage';
import { OperationErrorPayload, type PassflowEmailVerificationOperation, PassflowEvent, PassflowStore } from '../store';
import { isTokenExpired, parseToken, TokenType } from '../token';
import { TokenDeliveryManager, TokenDeliveryMode } from '../token/delivery-manager';
import { ParsedTokens, Tokens } from '../types';
import { UpgradeSessionChangedError, UpgradeTransportError } from '../upgrade/errors';
import { readSessionPin, sessionPinMatches, type UpgradeSessionPin } from '../upgrade/session';
import { isValidEmail, isValidPhoneNumber, isValidUsername } from '../utils/validation';
import { getDefaultLogger } from './logger';
import { TokenCacheService } from './token-cache-service';

/** The proof key of a PKCE sign-in that is waiting on its second factor. */
type PendingPkceSignIn = {
  verifier: string;
  scopes?: string[];
  expiresAt: number;
};

/**
 * What the call that produced an emailed code challenge knew, so `verifyEmailCode` can finish it
 * the same way: which event ends it, the scopes it asked for, and whether it left a PKCE verifier.
 */
type EmailChallenge = {
  operation: PassflowEmailVerificationOperation;
  email?: string;
  scopes: string[];
  pkce: boolean;
};

/** How this instance's refresh controller coordinates (architecture §3.3, §3.4). */
export type AuthServiceRefreshOptions = {
  coordination: ResolvedCoordination;
  /** `PassflowConfig.refreshStrikes`; the controller resolves the default. */
  strikes?: number;
};

const PENDING_PKCE_STORAGE_KEY = 'passflow_2fa_pkce';
/** As long as the pending second factor it belongs to. */
const PENDING_PKCE_TIMEOUT_MS = 5 * 60 * 1000;
/** At most this many code challenges are remembered; each resend adds one. The oldest goes first. */
const MAX_EMAIL_CHALLENGES = 10;
const VERIFIER_GONE_MESSAGE = 'The sign-in answered with a PKCE code, but its verifier is gone';

/**
 * The reset link's `?token=`: from the query, else from a hash route's query
 * (`#/password/reset?token=…`), so a hash router finds it too.
 */
const readResetToken = (url: CurrentUrlInfo | null): string | undefined => {
  if (!url) return undefined;
  const fromSearch = new URLSearchParams(url.search).get('token');
  if (fromSearch) return fromSearch;
  const query = url.hash.indexOf('?');
  return query < 0 ? undefined : (new URLSearchParams(url.hash.slice(query + 1)).get('token') ?? undefined);
};

/** The reset token's `email` claim, for display only. Never trusted, and never an error. */
const emailFromResetToken = (resetToken?: string): string | undefined => {
  if (!resetToken) return undefined;
  try {
    return parseToken(resetToken).email;
  } catch {
    return undefined;
  }
};

/**
 * Service for handling authentication related functionality
 */
export class AuthService {
  private tokenDeliveryManager: TokenDeliveryManager;
  private tokenExchangeConfig?: TokenExchangeConfig;
  private pendingPkce?: PendingPkceSignIn;
  /**
   * The emailed code challenges this instance produced, by `challenge_id`. Memory only: an id
   * this instance does not know (reload, another tab, a recreated instance) finishes as a sign-in.
   */
  private emailChallenges = new Map<string, EmailChallenge>();

  /**
   * The one place this instance sends `/auth/refresh` (PFL-792). Every refresh path asks it: the
   * explicit `refreshToken()`, the upgrade commit, `getTokens(true)`/`session()` and, once
   * `Passflow` attaches it, `TokenCacheService.getTokensWithRefresh()`.
   */
  readonly refresh: RefreshController;

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
    private readPkceEnabled?: () => Promise<boolean>,
    refreshOptions: AuthServiceRefreshOptions = { coordination: localCoordination() },
  ) {
    this.tokenExchangeConfig = tokenExchangeConfig;
    this.tokenDeliveryManager = new TokenDeliveryManager(storageManager);

    // If token exchange is enabled, set BFF mode immediately
    if (tokenExchangeConfig?.enabled) {
      this.tokenDeliveryManager.setMode(TokenDeliveryMode.BFF);
    }

    // The controller reads the identity from the cache or storage now. It subscribes to nothing
    // in the store: every new session calls `sessionStarted()` directly (amendment A1).
    this.refresh = createRefreshController({
      emit: this.createRefreshEmit(),
      storage: storageManager,
      cache: tokenCacheService,
      transport: this.createRefreshTransport(),
      coordination: refreshOptions.coordination,
      platform,
      ...(refreshOptions.strikes !== undefined ? { strikes: refreshOptions.strikes } : {}),
      logger: getDefaultLogger(),
    });

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
   * Applies a sign-in's tokens and starts a new session in the refresh controller.
   *
   * Every sign-in reaches the tokens through here: password, passwordless, passkey, federated,
   * the 2FA code and recovery-code completion, PKCE completion, `joinInvitation` and tokens from a
   * redirect (`applyTokens`). So this is where the controller learns of a new session (amendment
   * A1): a tab that signed out, or whose session ended, refreshes again on the new one.
   */
  private async processAuthResponse(response: PassflowAuthorizationResponse, scopes: string[]): Promise<void> {
    await this.applyAuthResponse(response, scopes);
    this.refresh.sessionStarted();
  }

  /**
   * Stores an authentication response: token storage, session state, CSRF token. In BFF mode it
   * forwards the tokens to the BFF server first. Starts no session: a cookie-mode refresh applies
   * its answer through here too.
   */
  private async applyAuthResponse(response: PassflowAuthorizationResponse, scopes: string[]): Promise<void> {
    if (response.code && !response.access_token) {
      throw new Error('A PKCE authorization code was not exchanged, so there are no tokens to apply');
    }

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
   * its verify and recovery calls can carry the token. On a PKCE sign-in the
   * server keeps the login's challenge, so the second factor's answer is a code:
   * the verifier stays here for `completePkceSignIn`, off the public event.
   */
  private handlePendingSecondFactor(
    response: Pick<PassflowAuthorizationResponse, 'requires_2fa' | 'challenge_id' | 'tfa_token'>,
    email?: string,
    pkce?: Pick<PkcePair, 'verifier'>,
    scopes?: string[],
  ): boolean {
    if (response.requires_2fa !== true && !response.tfa_token) {
      return false;
    }
    if (pkce) {
      this.rememberPkceSignIn(pkce.verifier, scopes);
    } else {
      this.forgetPkceSignIn();
    }
    this.subscribeStore.notify(PassflowEvent.TwoFactorRequired, {
      email: email || '',
      challengeId: response.challenge_id || '',
      tfaToken: response.tfa_token || '',
    });
    return true;
  }

  /**
   * Reports whether an answer is an email verification step, and when it is, prepares its completion.
   *
   * That answer is not a session: on `true` the caller returns it as it is, without
   * `processAuthResponse`, a `SignIn`/`Register` event, a session check or an error event. With a
   * code (`challenge_id`) on a PKCE app the verifier is kept for the code `/auth/validate` answers
   * with. A link step drops any verifier: that sign-in finishes on another page.
   */
  private handleEmailVerificationStep(
    response: PassflowAuthorizationResponse,
    operation: PassflowEmailVerificationOperation,
    email: string | undefined,
    pkce: Pick<PkcePair, 'verifier'> | undefined,
    scopes: string[],
  ): boolean {
    if (!isEmailVerificationStep(response)) {
      return false;
    }
    const challengeId = response.challenge_id || undefined;
    if (challengeId && pkce) {
      this.rememberPkceSignIn(pkce.verifier, scopes);
    } else {
      this.forgetPkceSignIn();
    }
    if (challengeId) {
      this.rememberEmailChallenge(challengeId, { operation, email, scopes, pkce: pkce !== undefined });
    }
    this.subscribeStore.notify(PassflowEvent.EmailVerificationRequired, { email, challengeId, operation });
    return true;
  }

  /** Adds a challenge at the newest end, dropping the oldest past `MAX_EMAIL_CHALLENGES`. */
  private rememberEmailChallenge(id: string, challenge: EmailChallenge): void {
    this.emailChallenges.delete(id);
    this.emailChallenges.set(id, challenge);
    for (const oldest of this.emailChallenges.keys()) {
      if (this.emailChallenges.size <= MAX_EMAIL_CHALLENGES) break;
      this.emailChallenges.delete(oldest);
    }
  }

  /**
   * Keeps the verifier in memory, which is where it is read from first. The copy
   * in sessionStorage is only for a redirect or reload during the second factor,
   * which would otherwise lose the sign-in.
   */
  private rememberPkceSignIn(verifier: string, scopes?: string[]): void {
    this.pendingPkce = { verifier, scopes, expiresAt: Date.now() + PENDING_PKCE_TIMEOUT_MS };
    if (typeof sessionStorage === 'undefined') {
      return;
    }
    try {
      sessionStorage.setItem(PENDING_PKCE_STORAGE_KEY, JSON.stringify(this.pendingPkce));
    } catch {
      // Disabled or full: the sign-in still completes unless the page goes away.
    }
  }

  private readPendingPkce(): PendingPkceSignIn | undefined {
    if (!this.pendingPkce && typeof sessionStorage !== 'undefined') {
      try {
        const stored = sessionStorage.getItem(PENDING_PKCE_STORAGE_KEY);
        this.pendingPkce = stored ? (JSON.parse(stored) as PendingPkceSignIn) : undefined;
      } catch {
        this.pendingPkce = undefined;
      }
    }
    if (this.pendingPkce && Date.now() >= this.pendingPkce.expiresAt) {
      this.forgetPkceSignIn();
    }
    return this.pendingPkce;
  }

  /** Whether a PKCE sign-in is waiting for the code its second factor answers with. */
  hasPendingPkceSignIn(): boolean {
    return this.readPendingPkce() !== undefined;
  }

  /** Drops the verifier of a pending sign-in. `TwoFactorService` calls this with its own state. */
  forgetPkceSignIn(): void {
    this.pendingPkce = undefined;
    if (typeof sessionStorage === 'undefined') {
      return;
    }
    try {
      sessionStorage.removeItem(PENDING_PKCE_STORAGE_KEY);
    } catch {
      // Nothing to do: it expires with the second factor.
    }
  }

  /**
   * The proof key for a sign-in on a PKCE app, undefined on any other app.
   *
   * It is sent whether or not the sign-in has a parent: the parent is added to
   * the request outside this SDK, so it is not visible here, and `pkce.Challenge`
   * on the server wants it under a device parent and ignores it under an OIDC one.
   * When the setting cannot be read the sign-in goes out without a challenge, and
   * a PKCE app refuses it with its own error.
   */
  private async startPkce(): Promise<PkcePair | undefined> {
    let enabled = false;
    try {
      enabled = (await this.readPkceEnabled?.()) ?? false;
    } catch (error) {
      getDefaultLogger().warn('Passflow: could not read the app settings, so this sign-in sends no PKCE challenge', error);
      return undefined;
    }
    return enabled ? createPkcePair() : undefined;
  }

  /**
   * Swaps a code in a sign-in's answer for what the code stands for; any other
   * answer passes through. That can still be a 2FA token: the server re-runs its
   * gate at the exchange unless the code records a passed second factor.
   */
  private async exchangeCode(
    response: PassflowAuthorizationResponse,
    pkce: PkcePair | undefined,
  ): Promise<PassflowAuthorizationResponse> {
    if (!response.code || !pkce) {
      return response;
    }
    return await this.authApi.pkceExchange(response.code, pkce.verifier);
  }

  /**
   * Finishes a PKCE sign-in whose code came from its second factor: redeems the
   * code with the first factor's verifier and applies the tokens. `TwoFactorService`
   * is the caller, and clears the pending state once this has succeeded.
   */
  async completePkceSignIn(code: string): Promise<PassflowAuthorizationResponse> {
    const pending = this.readPendingPkce();
    if (!pending) {
      throw new Error(VERIFIER_GONE_MESSAGE);
    }
    const tokens = await this.authApi.pkceExchange(code, pending.verifier);
    await this.processAuthResponse(tokens, pending.scopes ?? this.scopes);
    return tokens;
  }

  /**
   * Applies tokens that were issued outside this service, honouring the delivery
   * mode: this is the one place they reach the BFF and browser storage, so no
   * caller saves them itself. An answer that carries no tokens is left alone.
   */
  async applyTokens(tokens: Tokens): Promise<void> {
    const response = tokens as PassflowAuthorizationResponse;
    if (!response.access_token && !response.id_token && !response.token_delivery) {
      return;
    }
    await this.processAuthResponse(response, response.scopes ?? this.readPendingPkce()?.scopes ?? this.scopes);
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
        const errorPayload: OperationErrorPayload = {
          operation: 'sign-in',
          message: 'Invalid email format',
          originalError: error,
          code: 'VALIDATION_ERROR',
        };
        notifyError(this.subscribeStore, errorPayload);
        throw error;
      }
    }

    if ('username' in payload && payload.username) {
      if (!isValidUsername(payload.username)) {
        const error = new Error(
          'Invalid username format. Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens',
        );
        const errorPayload: OperationErrorPayload = {
          operation: 'sign-in',
          message:
            'Invalid username format. Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens',
          originalError: error,
          code: 'VALIDATION_ERROR',
        };
        notifyError(this.subscribeStore, errorPayload);
        throw error;
      }
    }

    if ('phone' in payload && payload.phone) {
      if (!isValidPhoneNumber(payload.phone)) {
        const error = new Error('Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)');
        const errorPayload: OperationErrorPayload = {
          operation: 'sign-in',
          message: 'Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)',
          originalError: error,
          code: 'VALIDATION_ERROR',
        };
        notifyError(this.subscribeStore, errorPayload);
        throw error;
      }
    }

    this.subscribeStore.notify(PassflowEvent.SignInStart, { email: payload.email });
    const deviceId = this.deviceService.getDeviceId();
    const os = getOSFromDeviceType(this.platform.getDeviceType());
    payload.scopes = payload.scopes ?? this.scopes;

    try {
      const pkce = await this.startPkce();
      const answer = await this.authApi.signIn(pkce ? { ...payload, code_challenge: pkce.challenge } : payload, deviceId, os);
      if (this.handleEmailVerificationStep(answer, 'sign-in', payload.email, pkce, payload.scopes)) {
        return answer;
      }
      if (this.handlePendingSecondFactor(answer, payload.email, pkce, payload.scopes)) {
        return answer;
      }

      const response = await this.exchangeCode(answer, pkce);
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
      const errorPayload: OperationErrorPayload = {
        operation: 'sign-in',
        message: error instanceof Error ? error.message : 'Sign in failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      notifyError(this.subscribeStore, errorPayload);
      throw error;
    }
  }

  async signUp(payload: PassflowSignUpPayload): Promise<PassflowAuthorizationResponse> {
    // Validate user input before API call
    if (payload.user.email && !isValidEmail(payload.user.email)) {
      const error = new Error('Invalid email format');
      const errorPayload: OperationErrorPayload = {
        operation: 'sign-up',
        message: 'Invalid email format',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      notifyError(this.subscribeStore, errorPayload);
      throw error;
    }

    if (payload.user.phone_number && !isValidPhoneNumber(payload.user.phone_number)) {
      const error = new Error('Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)');
      const errorPayload: OperationErrorPayload = {
        operation: 'sign-up',
        message: 'Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      notifyError(this.subscribeStore, errorPayload);
      throw error;
    }

    this.subscribeStore.notify(PassflowEvent.RegisterStart, { email: payload.user.email });
    payload.scopes = payload.scopes ?? this.scopes;
    payload.create_tenant = this.createTenantForNewUser;

    try {
      const pkce = await this.startPkce();
      const answer = await this.authApi.signUp(pkce ? { ...payload, code_challenge: pkce.challenge } : payload);
      if (this.handleEmailVerificationStep(answer, 'sign-up', payload.user.email, pkce, payload.scopes)) {
        return answer;
      }
      if (this.handlePendingSecondFactor(answer, payload.user.email, pkce, payload.scopes)) {
        return answer;
      }

      const response = await this.exchangeCode(answer, pkce);
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
      const errorPayload: OperationErrorPayload = {
        operation: 'sign-up',
        message: error instanceof Error ? error.message : 'Sign up failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      notifyError(this.subscribeStore, errorPayload);
      throw error;
    }
  }

  async passwordlessSignIn(payload: PassflowPasswordlessSignInPayload): Promise<PassflowPasswordlessResponse> {
    // Validate input before API call
    if (payload.email && !isValidEmail(payload.email)) {
      const error = new Error('Invalid email format');
      const errorPayload: OperationErrorPayload = {
        operation: 'passwordless.start',
        message: 'Invalid email format',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      notifyError(this.subscribeStore, errorPayload);
      throw error;
    }

    if (payload.phone && !isValidPhoneNumber(payload.phone)) {
      const error = new Error('Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)');
      const errorPayload: OperationErrorPayload = {
        operation: 'passwordless.start',
        message: 'Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      notifyError(this.subscribeStore, errorPayload);
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
      const errorPayload: OperationErrorPayload = {
        operation: 'passwordless.start',
        message: error instanceof Error ? error.message : 'Failed to send passwordless sign-in link',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      notifyError(this.subscribeStore, errorPayload);
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
      const errorPayload: OperationErrorPayload = {
        operation: 'passwordless.complete',
        message: error instanceof Error ? error.message : 'Passwordless sign in failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      notifyError(this.subscribeStore, errorPayload);
      throw error;
    }
  }

  /**
   * Finishes a sign-up, sign-in or password change that answered with an emailed code
   * (`email_verification_required` with a `challenge_id`): posts the code to `/auth/validate`, then
   * continues like `signIn`. Emits `Register` for a sign-up's challenge and `SignIn` otherwise
   * (an unknown id included), `TwoFactorRequired` when a second factor is owed, and one `Error`
   * on failure. Emits no Start event: the code step's `EmailVerificationRequired` ended that one.
   */
  async verifyEmailCode(payload: PassflowEmailCodePayload): Promise<PassflowAuthorizationResponse> {
    const challenge = this.emailChallenges.get(payload.challenge_id);
    const email = challenge?.email;

    try {
      // A challenge that left no verifier ignores one from another sign-in. One that left a
      // verifier needs it before the code is spent: without it a sign-up would create the
      // account and get no session. An unknown id takes whatever is pending.
      const pending = challenge?.pkce === false ? undefined : this.readPendingPkce();
      if (challenge?.pkce && !pending) {
        throw new Error(VERIFIER_GONE_MESSAGE);
      }

      const answer = await this.authApi.validateEmailCode(payload);
      // A 200 spends the row, whatever comes next.
      this.emailChallenges.delete(payload.challenge_id);
      const scopes = pending?.scopes ?? challenge?.scopes ?? this.scopes;

      // Not expected, but a second code step is handled like the first.
      if (this.handleEmailVerificationStep(answer, challenge?.operation ?? 'sign-in', email, pending, scopes)) {
        return answer;
      }
      // A second factor is owed: the verifier is remembered again, so it lasts as long as the factor.
      if (this.handlePendingSecondFactor(answer, email, pending, scopes)) {
        return answer;
      }

      let exchanged: PassflowAuthorizationResponse = answer;
      if (answer.code) {
        if (!pending) {
          throw new Error(VERIFIER_GONE_MESSAGE);
        }
        exchanged = await this.authApi.pkceExchange(answer.code, pending.verifier);
        if (this.handlePendingSecondFactor(exchanged, email)) {
          return exchanged;
        }
      }

      // A reset row's redirect is on the code's answer: the exchange returns only tokens.
      const response = answer.redirect_url ? { ...exchanged, redirect_url: answer.redirect_url } : exchanged;
      await this.processAuthResponse(response, scopes);
      this.forgetPkceSignIn();
      this.subscribeStore.notify(challenge?.operation === 'sign-up' ? PassflowEvent.Register : PassflowEvent.SignIn, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      const errorPayload: OperationErrorPayload = {
        operation: 'email-verification.complete',
        message: error instanceof Error ? error.message : 'Email verification failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      notifyError(this.subscribeStore, errorPayload);
      throw error;
    }
  }

  /**
   * Signs this tab out under the refresh lock (PFL-792 §2.8): stops this tab's refresh callers and
   * retry timer, waits at most 5 s for the lock (a request already in flight lands first), posts
   * `signed-out` to the other tabs, calls the logout API with the NEWEST stored refresh token (best
   * effort), then deletes the stored tokens, id token and CSRF token and clears the token cache.
   *
   * Emits no `SignOut`: `Passflow.logOut()` emits exactly one, after this resolves.
   *
   * @returns the `sub` of the session that ended, when known
   */
  async logOut(): Promise<string | undefined> {
    const userId = this.refresh.identity();
    await this.refresh.signOut(async (newest) => {
      await this.callLogoutApi(newest);
      this.forgetPkceSignIn();
      this.emailChallenges.clear();
      this.clearLocalSession();
    });
    return userId;
  }

  /**
   * `Passflow.reset()` (PFL-792 amendment A2): the same local sign-out, synchronously, with no
   * API call and no lock. Emits no `SignOut`; the caller emits one.
   *
   * @returns the `sub` of the session that ended, when known
   */
  resetSession(): string | undefined {
    const userId = this.refresh.identity();
    this.refresh.signOutNow(() => {
      this.emailChallenges.clear();
      this.clearLocalSession();
    });
    return userId;
  }

  /** The logout API call. Server-side cleanup is best effort: every failure is ignored. */
  private async callLogoutApi(newestRefreshToken: string | undefined): Promise<void> {
    // BFF mode: call BFF logout endpoint to clear httpOnly cookies
    if (this.tokenDeliveryManager.isBFFMode() && this.tokenExchangeConfig?.logoutUrl) {
      try {
        await fetch(this.tokenExchangeConfig.logoutUrl, {
          method: 'POST',
          credentials: 'include', // Include httpOnly cookies
        });
      } catch (_error) {
        // Network error during logout - ignore and continue with local cleanup
      }
      return;
    }
    // Regular mode: cookie mode sends no token (the server reads the HttpOnly cookie); JSON mode
    // sends the newest stored refresh token, read under the lock.
    const refreshToken = newestRefreshToken ?? this.storageManager.getToken(TokenType.refresh_token);
    const deviceId = this.storageManager.getDeviceId();
    try {
      const response = await this.authApi.logOut(deviceId, refreshToken, !this.appId);
      if (response.status !== 'ok') {
        throw new Error('Logout failed');
      }
    } catch (_error) {
      // Logout API call failed - ignore and continue with local cleanup
    }
  }

  /** Deletes every local trace of the session (both delivery modes) and clears the token cache. */
  private clearLocalSession(): void {
    this.storageManager.deleteTokens();
    this.storageManager.clearIdToken();
    this.storageManager.clearCsrfToken();
    this.tokenDeliveryManager.reset();
    this.tokenCacheService.setTokensCache(undefined);
    this.tokenCacheService.stopTokenCheck?.();
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
    try {
      const token = this.storageManager.getToken(TokenType.access_token);
      if (!token) {
        return undefined;
      }
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

  /** The delivery mode the refresh transport sends in. BFF without a refresh URL has no endpoint: JSON, as before. */
  private refreshMode(): 'json' | 'cookie' | 'bff' {
    if (this.tokenDeliveryManager.isBFFMode() && this.tokenExchangeConfig?.refreshUrl) return 'bff';
    if (this.tokenDeliveryManager.isCookieMode()) return 'cookie';
    return 'json';
  }

  /**
   * The controller's events, onto the store. Only `notify` is used (plus the error dedupe), so a
   * store double with `notify` alone works.
   */
  private createRefreshEmit(): RefreshEmit {
    return <E extends keyof RefreshEventMap>(event: E, payload: RefreshEventMap[E]): void => {
      const store = this.subscribeStore;
      switch (event) {
        case 'refresh': {
          const { tokens, source } = payload as RefreshEventMap['refresh'];
          store.notify(PassflowEvent.Refresh, { tokens, parsedTokens: this.tokenCacheService.getParsedTokens(), source });
          return;
        }
        case 'signin': {
          const { tokens, origin } = payload as RefreshEventMap['signin'];
          store.notify(PassflowEvent.SignIn, { tokens, parsedTokens: this.tokenCacheService.getParsedTokens(), origin });
          return;
        }
        case 'error':
          notifyError(store, payload as RefreshEventMap['error']);
          return;
        case 'refresh:start':
          store.notify(PassflowEvent.RefreshStart, {});
          return;
        case 'token-cache-expired':
          store.notify(PassflowEvent.TokenCacheExpired, payload as RefreshEventMap['token-cache-expired']);
          return;
        case 'refresh:failing':
          store.notify(PassflowEvent.RefreshFailing, payload as RefreshEventMap['refresh:failing']);
          return;
        case 'refresh:recovered':
          store.notify(PassflowEvent.RefreshRecovered, payload as RefreshEventMap['refresh:recovered']);
          return;
        case 'session:expired':
          store.notify(PassflowEvent.SessionExpired, payload as RefreshEventMap['session:expired']);
          return;
        case 'signout':
          store.notify(PassflowEvent.SignOut, payload as RefreshEventMap['signout']);
          return;
        default:
          getDefaultLogger().warn(`[passflow] Unknown refresh event: ${String(event)}`);
      }
    };
  }

  /**
   * One refresh request in the current delivery mode, with no events and no saving (architecture
   * §3.2): the controller decides what an answer or a failure means.
   *
   * - JSON: `AuthAPI.refreshToken(stored refresh token, stored scopes, stored access token[, upgrade])`.
   * - Cookie: `AuthAPI.refreshToken('', scopes[, undefined, upgrade])`; the server reads the HttpOnly cookie.
   * - BFF: `POST tokenExchange.refreshUrl`. A non-OK answer becomes a `PassflowError` (status, and
   *   the body's `error.id` or `error.http.<status>`), so it is classified like any other answer.
   */
  private createRefreshTransport(): RefreshTransport {
    return {
      mode: () => this.refreshMode(),
      send: async ({ tokens, upgrade }) => {
        const mode = this.refreshMode();
        if (mode === 'bff') return await this.sendBffRefresh();
        if (mode === 'cookie') {
          return upgrade
            ? await this.authApi.refreshToken('', this.scopes, undefined, upgrade)
            : await this.authApi.refreshToken('', this.scopes);
        }
        // The `upgrade` argument is passed only when there is one, rather than as an explicit
        // `undefined`: the ordinary refresh call stays byte-identical to what it was before step-up.
        const refresh = tokens?.refresh_token ?? '';
        const scopes = tokens?.scopes ?? this.scopes;
        const access = tokens?.access_token;
        return upgrade
          ? await this.authApi.refreshToken(refresh, scopes, access, upgrade)
          : await this.authApi.refreshToken(refresh, scopes, access);
      },
      applyOpaque: async (response) => {
        this.tokenDeliveryManager.setSessionValid();
        if (this.tokenDeliveryManager.isBFFMode()) {
          // The BFF keeps the access and refresh tokens; only the id token is local.
          if (response.id_token) this.storageManager.setIdToken(response.id_token);
          if (response.csrf_token) this.storageManager.setCsrfToken(response.csrf_token);
          return;
        }
        // Cookie mode: the id token and CSRF token, in the delivery mode the answer names.
        await this.applyAuthResponse(response, this.scopes);
      },
      invalidate: () => {
        // The end of a cookie/BFF session (last strike, successor timeout): §2.11.
        this.tokenDeliveryManager.setSessionInvalid();
        this.storageManager.clearIdToken();
        this.storageManager.clearCsrfToken();
      },
      assertPin: (pin) => this.assertSessionPin(pin),
      opaqueMarker: () => {
        const id = this.storageManager.getIdToken();
        const csrf = this.storageManager.getCsrfToken();
        return id === undefined && csrf === undefined ? undefined : `${id ?? ''}\n${csrf ?? ''}`;
      },
    };
  }

  /** The BFF refresh endpoint. A non-OK answer becomes a `PassflowError`; a network failure rejects as is. */
  private async sendBffRefresh(): Promise<PassflowAuthorizationResponse> {
    const url = this.tokenExchangeConfig?.refreshUrl ?? '';
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'include', // Include httpOnly cookies
    });
    if (!response.ok) {
      let id: string | undefined;
      let message: string | undefined;
      try {
        const body = (await response.json()) as { error?: { id?: unknown; message?: unknown } } | undefined;
        if (typeof body?.error?.id === 'string') id = body.error.id;
        if (typeof body?.error?.message === 'string') message = body.error.message;
      } catch {
        // No JSON body: the status decides.
      }
      throw new PassflowError({
        id: id ?? `error.http.${response.status}`,
        message: message ?? 'BFF token refresh failed',
        status: response.status,
        location: url,
        time: new Date().toISOString(),
      });
    }
    return (await response.json()) as PassflowAuthorizationResponse;
  }

  /**
   * Refreshes the session, optionally committing an assurance upgrade.
   *
   * Both go through the refresh controller, the one place this instance sends `/auth/refresh`: it
   * coordinates with other tabs, saves with a compare-and-set, classifies failures and emits the
   * events (PFL-792). A plain refresh is "fresh": it is satisfied only by tokens from a request
   * sent at or after the call. A failure keeps the tokens unless it really ends the session.
   *
   * The upgrade commit is the one path that is never classified: any failure rejects with the
   * error unchanged and keeps the tokens, because a 4xx there is the server rejecting the PROOF,
   * not the session (logging the user out for mistyping six digits is the defect this flow exists
   * to fix). The upgrade transport classifies those failures itself. The session pin is checked
   * when the answer arrives, before anything is applied: see `assertSessionPin`.
   */
  async refreshToken(upgrade?: UpgradeRefreshField, pin?: UpgradeSessionPin): Promise<PassflowAuthorizationResponse> {
    // BFF mode cannot carry an upgrade, and the refusal has to come BEFORE any event or network
    // call: the BFF refresh endpoint is the customer's own, posted to with an empty body, so there
    // is nowhere to put `{upgrade:{...}}` without a customer-backend change. Refusing early is what
    // lets the UI show "unavailable" instead of asking for a code that can never be submitted.
    if (upgrade && this.tokenDeliveryManager.isBFFMode()) {
      throw new UpgradeTransportError({
        kind: 'unavailable',
        message: 'Step-up verification cannot be committed through a BFF refresh endpoint',
      });
    }

    if (upgrade) return await this.refresh.commitUpgrade(upgrade, pin);

    // JSON mode with nothing stored: nothing to send (one Error, as before). An ended session is
    // the controller's to answer (`error.refresh.session_ended`), and cookie/BFF modes have no
    // readable refresh token at all: both go straight to the controller.
    if (this.refreshMode() === 'json' && !this.refresh.ended) {
      const stored = this.storageManager.getTokens();
      if (!stored?.refresh_token) {
        const error = new Error(stored ? 'No refresh token found' : 'No tokens found');
        notifyError(this.subscribeStore, {
          operation: 'refresh',
          source: 'refresh-token',
          message: error.message,
          originalError: error,
        });
        throw error;
      }
    }
    return await this.refresh.refresh({ trigger: 'refresh-token', fresh: true });
  }

  async sendPasswordResetEmail(payload: PassflowSendPasswordResetEmailPayload): Promise<PassflowSuccessResponse> {
    try {
      return await this.authApi.sendPasswordResetEmail(payload);
    } catch (error) {
      const errorPayload: OperationErrorPayload = {
        operation: 'password-reset.send',
        message: error instanceof Error ? error.message : 'Failed to send password reset email',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      notifyError(this.subscribeStore, errorPayload);
      throw error;
    }
  }

  async resetPassword(newPassword: string, scopes?: string[], token?: string): Promise<PassflowAuthorizationResponse> {
    this.subscribeStore.notify(PassflowEvent.SignInStart, {});
    // An explicit token wins; then the query, as before; then a hash route's query.
    const resetToken = token ?? readResetToken(this.platform.getCurrentUrl());
    const sscopes = scopes ?? this.scopes;

    try {
      const pkce = await this.startPkce();
      const answer = pkce
        ? await this.authApi.resetPassword(newPassword, sscopes, resetToken, pkce.challenge)
        : await this.authApi.resetPassword(newPassword, sscopes, resetToken);
      if (this.handleEmailVerificationStep(answer, 'reset-password', emailFromResetToken(resetToken), pkce, sscopes)) {
        return answer;
      }
      if (this.handlePendingSecondFactor(answer, undefined, pkce, sscopes)) {
        return answer;
      }

      const exchanged = await this.exchangeCode(answer, pkce);
      if (this.handlePendingSecondFactor(exchanged)) {
        return exchanged;
      }

      // The reset link's redirect is on the code's answer: the exchange returns only tokens.
      const response = answer.redirect_url ? { ...exchanged, redirect_url: answer.redirect_url } : exchanged;
      await this.processAuthResponse(response, sscopes);
      this.subscribeStore.notify(PassflowEvent.SignIn, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      const errorPayload: OperationErrorPayload = {
        operation: 'password-reset.complete',
        message: error instanceof Error ? error.message : 'Password reset failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      notifyError(this.subscribeStore, errorPayload);
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
      const pkce = await this.startPkce();
      const { challenge_id, publicKey } = await this.authApi.passkeyRegisterStart(
        pkce ? { ...payload, code_challenge: pkce.challenge } : payload,
        deviceId,
        os,
        !this.appId,
      );
      // user handle should be base64 encoded for simplewebauthn lib we are using
      publicKey.user.id = this.platform.btoa(publicKey.user.id);
      const webauthn = await this.platform.passkeys.startRegistration(publicKey);
      if (!webauthn) throw new Error('Passkey registration was not completed');

      const answer = await this.authApi.passkeyRegisterComplete(webauthn, deviceId, challenge_id, !this.appId);
      if (this.handlePendingSecondFactor(answer, undefined, pkce, payload.scopes)) {
        return answer;
      }

      const responseRegisterComplete = await this.exchangeCode(answer, pkce);
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
      const errorPayload: OperationErrorPayload = {
        operation: 'passkey.register',
        message: error instanceof Error ? error.message : 'Passkey registration failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      notifyError(this.subscribeStore, errorPayload);
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
      const pkce = await this.startPkce();
      const { challenge_id, publicKey } = await this.authApi.passkeyAuthenticateStart(
        pkce ? { ...payload, code_challenge: pkce.challenge } : payload,
        deviceId,
        os,
        !this.appId,
      );
      const webauthn = await this.platform.passkeys.startAuthentication(publicKey);
      if (!webauthn) throw new Error('Passkey authentication was not completed');

      const answer = await this.authApi.passkeyAuthenticateComplete(webauthn, deviceId, challenge_id, !this.appId);
      if (this.handlePendingSecondFactor(answer, undefined, pkce, payload.scopes)) {
        return answer;
      }

      const responseAuthenticateComplete = await this.exchangeCode(answer, pkce);
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
      const errorPayload: OperationErrorPayload = {
        operation: 'passkey.authenticate',
        message: error instanceof Error ? error.message : 'Passkey authentication failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      notifyError(this.subscribeStore, errorPayload);
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
      const errorPayload: OperationErrorPayload = {
        operation: 'federated.popup',
        message: error instanceof Error ? error.message : 'Authentication failed',
        code: error instanceof PopupClosedError ? 'POPUP_CLOSED' : 'AUTH_FAILED',
        originalError: error,
      };
      notifyError(this.subscribeStore, errorPayload);
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
      const errorPayload: OperationErrorPayload = {
        operation: 'auth-redirect.url',
        message: error instanceof Error ? error.message : 'Failed to create auth redirect URL',
        originalError: error,
      };
      notifyError(this.subscribeStore, errorPayload);
      throw error;
    }
  }

  authRedirect(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): void {
    try {
      this.platform.navigateTo(this.authRedirectUrl(options));
    } catch (error) {
      const errorPayload: OperationErrorPayload = {
        operation: 'auth-redirect',
        message: error instanceof Error ? error.message : 'Failed to redirect to auth page',
        originalError: error,
      };
      notifyError(this.subscribeStore, errorPayload);
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
      const errorPayload: OperationErrorPayload = {
        operation: 'auth.is-authenticated',
        message: error instanceof Error ? error.message : 'Failed to check authentication status',
        originalError: error,
      };
      notifyError(this.subscribeStore, errorPayload);
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
      const errorPayload: OperationErrorPayload = {
        operation: 'session.check',
        message: error instanceof Error || error instanceof PassflowError ? error.message : 'Session check failed',
        originalError: error,
      };
      notifyError(this.subscribeStore, errorPayload);
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
   * `getTokens(true)` / `session({ doRefresh: true })` (architecture §2.8): starts or joins a
   * refresh, then resolves with the cached tokens whatever the outcome: the kept tokens after a
   * transient, blocked or auth-with-strikes-left failure, `undefined` once the session ended. The
   * failure itself was reported by the controller, so it is not reported again here.
   */
  private async refreshForSession(): Promise<Tokens | undefined> {
    try {
      await this.refresh.refresh({ trigger: 'session' });
    } catch {
      // Reported by the controller (Error{refresh}); the cache says what is left.
    }
    return this.tokenCacheService.getTokens();
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
          return await this.refreshForSession();
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
        // we have an expired token: refresh it when asked (kept tokens if that fails)
        if (doRefresh) return await this.refreshForSession();

        // we need return undefined here, because we have expired token and we no need to refresh it
        return undefined;
      } else {
        return tokens;
      }
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
}
