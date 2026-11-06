import type { AxiosInstance } from 'axios';
import {
  AppAPI,
  type AppSettings,
  AuthAPI,
  InvitationAPI,
  type InvitationsPaginatedList,
  type InviteLinkResponse,
  type PassflowAuthorizationResponse,
  type PassflowConfig,
  type PassflowEmailCodePayload,
  PassflowError,
  PassflowFederatedAuthPayload,
  type PassflowPasskeyAuthenticateStartPayload,
  type PassflowPasskeyRegisterStartPayload,
  type PassflowPasskeySettings,
  type PassflowPasswordlessResponse,
  type PassflowPasswordlessSignInCompletePayload,
  type PassflowPasswordlessSignInPayload,
  type PassflowPasswordPolicySettings,
  type PassflowSendPasswordResetEmailPayload,
  type PassflowSettingsAll,
  type PassflowSignInPayload,
  type PassflowSignUpPayload,
  type PassflowSuccessResponse,
  type PassflowTenantResponse,
  type PassflowValidationResponse,
  type PasswordlessApprovalInfo,
  type PasswordlessWaitResult,
  type RequestInviteLinkPayload,
  resolveUpgradeDomain,
  SettingAPI,
  TenantAPI,
  TwoFactorApiClient,
  type TwoFactorCompletionOptions,
  type TwoFactorConfirmResponse,
  type TwoFactorDisableResponse,
  type TwoFactorEnrollment,
  type TwoFactorRecoveryResponse,
  type TwoFactorRegenerateResponse,
  type TwoFactorSetupLinkResponse,
  type TwoFactorSetupResponse,
  type TwoFactorStatusResponse,
  type TwoFactorTrustedDevice,
  type TwoFactorVerifyResponse,
  UpgradeAPI,
  type UpgradeDomain,
  UserAPI,
} from './api';

import type { AxiosClient, AxiosUpgradeHandler } from './api/axios-client';
import { DEFAULT_SCOPES, PASSFLOW_CLOUD_URL, SDK_VERSION } from './constants';
import { DeviceService } from './device';
import { notifyError } from './error-report';
import type { CurrentUrlInfo, PlatformAdapter } from './platform';
import { webAdapter } from './platform';
import { resolveCoordination } from './refresh/resolve';
import { AuthService, InvitationService, TenantService, TokenCacheService, TwoFactorService, UserService } from './services';
import { StorageManager } from './storage';
import {
  type OperationErrorPayload,
  PassflowEvent,
  type PassflowOperation,
  PassflowStore,
  type PassflowSubscriber,
} from './store';
import { parseToken, TokenType } from './token';
import { TokenDeliveryMode } from './token/delivery-manager';
import { verifyUrlTokens } from './token/verify';
import type { ParsedTokens, SessionParams, Tokens } from './types';
import {
  type AssuranceBar,
  type CreateClientConfig,
  createUpgradeClient,
  createUpgradeFacade,
  type FetchLike,
  type ResponseInterceptorHost,
  readAcrValues,
  type UpgradeFacade,
} from './upgrade';
import { isValidJWTFormat, sanitizeErrorMessage } from './utils/validation';

export class Passflow {
  /**
   * SDK version string.
   * Useful for debugging and reporting version-specific issues.
   * @example
   * ```typescript
   * console.log('Using Passflow SDK version:', Passflow.version);
   * ```
   */
  static readonly version: string = SDK_VERSION;

  // API clients
  private authApi: AuthAPI;
  private appApi: AppAPI;
  private userApi: UserAPI;
  private settingApi: SettingAPI;
  private tenantApi: TenantAPI;
  private invitationApi: InvitationAPI;
  private twoFactorApi: TwoFactorApiClient;
  private upgradeApi: UpgradeAPI;

  // Configuration
  private scopes: string[];
  private createTenantForNewUser: boolean;
  private doRefreshTokens = false;
  private deferFederatedLanding: boolean;

  // Services
  private deviceService: DeviceService;
  private storageManager: StorageManager;
  private subscribeStore: PassflowStore;
  private authService: AuthService;
  private userService: UserService;
  private tenantService: TenantService;
  private invitationService: InvitationService;
  private tokenCacheService: TokenCacheService;
  private twoFactorService: TwoFactorService;

  // Public services
  public tenant: TenantService;
  public twoFactor: TwoFactorService;

  /**
   * Step-up (assurance upgrade) wiring. Always present, inert until
   * `enable({ prompt })` is called — constructing a `Passflow` must never patch
   * a global or install a prompt.
   */
  readonly upgrade: UpgradeFacade;

  /**
   * Passflow's own API as an interception scope ("domain 1"), resolved ONCE
   * here from `PassflowConfig.url` so no adapter or wrapper ever derives it.
   * `null` when no `url` was configured, which is empty — never a throw, and
   * never silent: the first parseable challenge then names `url` as the fix.
   */
  private readonly upgradeDomain: UpgradeDomain | null;

  // Session callbacks
  private createSessionCallback?: ({ tokens, parsedTokens }: { tokens?: Tokens; parsedTokens?: ParsedTokens }) => Promise<void>;
  private expiredSessionCallback?: () => Promise<void>;

  // The app's PKCE setting, read once per appId
  private pkceEnabledRead?: Promise<boolean>;

  // State
  error?: Error;
  private platform: PlatformAdapter;
  get origin(): string {
    return this.platform.getCurrentUrl()?.origin ?? '';
  }
  url: string;
  appId?: string;

  constructor(config: PassflowConfig) {
    const { url, appId, scopes } = config;
    this.url = url || PASSFLOW_CLOUD_URL;
    this.appId = appId;
    this.platform = config.platform ?? webAdapter;
    this.deferFederatedLanding = config.deferFederatedLanding ?? false;

    // Initialize single StorageManager instance
    this.storageManager = new StorageManager({
      prefix: config.keyStoragePrefix ?? '',
      storage: this.platform.storage,
    });

    // Initialize single DeviceService instance with shared StorageManager
    this.deviceService = new DeviceService(this.storageManager);

    // Initialize API clients with shared instances
    this.authApi = new AuthAPI(config, this.storageManager, this.deviceService);
    this.appApi = new AppAPI(config, this.storageManager, this.deviceService);
    this.userApi = new UserAPI(config, this.storageManager, this.deviceService);
    this.settingApi = new SettingAPI(config, this.storageManager, this.deviceService);
    this.tenantApi = new TenantAPI(config, this.storageManager, this.deviceService);
    this.invitationApi = new InvitationAPI(config, this.storageManager, this.deviceService);
    this.twoFactorApi = new TwoFactorApiClient(config, this.storageManager, this.deviceService);
    this.upgradeApi = new UpgradeAPI(config, this.storageManager, this.deviceService);
    this.upgradeDomain = resolveUpgradeDomain(config.url);

    // Initialize PassflowStore
    this.subscribeStore = new PassflowStore();

    this.tokenCacheService = new TokenCacheService(this.storageManager, this.authApi, this.subscribeStore, this.platform);

    this.scopes = scopes ?? DEFAULT_SCOPES;
    this.createTenantForNewUser = config.createTenantForNewUser ?? false;

    // How this instance coordinates token refresh with the other tabs (PFL-792). The refresh
    // controller is created by AuthService, which owns the delivery mode its transport needs.
    const coordination = resolveCoordination(config.refreshCoordination, this.platform, config.keyStoragePrefix, {
      tokenKeys: () => this.storageManager.tokenKeys(),
    });

    // Initialize domain services with dependencies
    this.authService = new AuthService(
      this.authApi,
      this.deviceService,
      this.storageManager,
      this.subscribeStore,
      this.tokenCacheService,
      this.scopes,
      this.createTenantForNewUser,
      this.url,
      {
        createSession: this.createSessionCallback,
        expiredSession: this.expiredSessionCallback,
      },
      this.appId ?? '',
      config.tokenExchange,
      this.platform,
      () => this.readPkceEnabled(),
      {
        coordination,
        ...(config.refreshStrikes !== undefined ? { strikes: config.refreshStrikes } : {}),
      },
    );

    // getTokensWithRefresh() refreshes through the same controller.
    this.tokenCacheService.attachRefreshController(this.authService.refresh);
    // The pre-request refresh of every API client this instance owns asks the same controller.
    for (const client of this.axiosClients()) {
      client.setRefreshHandler((request) => this.authService.refresh.ensureFresh(request));
    }

    this.userService = new UserService(this.userApi, this.deviceService, this.platform);

    this.tenantService = new TenantService(this.tenantApi, this.scopes);
    this.tenant = this.tenantService;

    this.invitationService = new InvitationService(this.invitationApi);

    this.twoFactorService = new TwoFactorService(this.twoFactorApi, this.subscribeStore, this.authService);
    this.twoFactor = this.twoFactorService;

    this.upgrade = createUpgradeFacade({
      // The prepare round. The commit round is `/auth/refresh`, which must go
      // through AuthService: it is the only path that STORES the rotated tokens,
      // so posting directly would elevate the session on the server and leave
      // the client holding stale ones.
      startUpgrade: (payload) => this.upgradeApi.startUpgrade(payload),
      commitRefresh: async (upgrade, pin) => {
        await this.authService.refreshToken(upgrade, pin);
      },
      // The identity the flight is pinned to, read once when it starts. The
      // check itself lives inside `refreshToken`, immediately before the
      // rotated tokens are applied — see `AuthService.assertSessionPin`.
      readSessionPin: () => this.authService.readSessionPin(),
      canCommit: () =>
        this.authService['tokenDeliveryManager'].isBFFMode()
          ? { ok: false, reason: 'Step-up verification cannot be committed through a BFF refresh endpoint' }
          : { ok: true },
      markSessionInvalid: () => this.authService['tokenDeliveryManager'].setSessionInvalid(),
      platform: this.platform,
      passflowDomain: this.upgradeDomain,
      ...(config.upgrade?.factors ? { factors: config.upgrade.factors } : {}),
      ...(config.upgrade?.relyingPartyId ? { relyingPartyId: () => config.upgrade?.relyingPartyId } : {}),
      readObtainedBar: () => this.readAssuranceBar(),
      // §5.5's credential swap. Called twice by the core — before the elevation
      // and after it — so returning the CURRENT token both times is what makes
      // `{from: stale, to: fresh}` come out right, and exact-match on `from` is
      // what proves the outgoing header was ours.
      authorizationSwap: () => {
        const token = this.storageManager.getToken(TokenType.access_token);
        return token ? { from: `Bearer ${token}`, to: `Bearer ${token}` } : undefined;
      },
      attachInternalSeam: (factory) => this.attachUpgradeSeam(factory),
      onSessionChange: (listener) => this.subscribeToSessionChange(listener),
    });

    // Check for tokens in query params if configured
    if (config.parseQueryParams) {
      this.checkAndSetTokens();
    }

    this.setTokensToCacheFromLocalStorage();
  }

  /**
   * Whether the current app wants PKCE. A sign-in asks before a passkey ceremony,
   * where a round-trip eats into the browser's user-gesture window, so the answer
   * is kept for the appId. A failed read is not kept: the next sign-in asks again.
   */
  private readPkceEnabled(): Promise<boolean> {
    if (!this.appId) {
      return Promise.resolve(false);
    }
    if (!this.pkceEnabledRead) {
      const read: Promise<boolean> = this.appApi.getAppSettings().then((settings) => settings.pkce_enabled);
      this.pkceEnabledRead = read;
      read.catch(() => {
        if (this.pkceEnabledRead === read) {
          this.pkceEnabledRead = undefined;
        }
      });
    }
    return this.pkceEnabledRead;
  }

  /**
   * Update the appId and propagate it to all API clients.
   * This ensures that all future API requests use the new appId in their headers.
   *
   * @param appId - The new application ID to set
   *
   * @example
   * ```typescript
   * // Update appId after discovery
   * passflow.setAppId('discovered-app-id-123');
   * ```
   */
  setAppId(appId: string): void {
    this.appId = appId;
    this.pkceEnabledRead = undefined;

    // Update all API clients
    this.authApi.setAppId(appId);
    this.appApi.setAppId(appId);
    this.userApi.setAppId(appId);
    this.settingApi.setAppId(appId);
    this.tenantApi.setAppId(appId);
    this.invitationApi.setAppId(appId);
    this.twoFactorApi.setAppId(appId);
    this.upgradeApi.setAppId(appId);

    // Update authService appId if needed
    if (this.authService) {
      // AuthService stores appId internally but doesn't have a setter
      // The API clients will handle the headers, so this is sufficient
    }
  }

  /**
   * Wraps a `fetch`, returning a new function with step-up handling attached.
   *
   * Installs nothing and touches no global — this is the SSR- and
   * React-Native-safe surface. Two verbs exist because the semantics genuinely
   * differ: an axios interceptor mutates, a fetch wrapper returns, and one name
   * would hide which happened.
   *
   * A challenge from Passflow's own API is handled with no further
   * configuration; a challenge from the developer's own backend needs that
   * backend declared via `upgrade.enable({ backend })`.
   *
   * @example
   * ```typescript
   * const authedFetch = passflow.withAuth(fetch);
   * const res = await authedFetch('https://api.example.com/transfer', { method: 'POST' });
   * if (!res.ok && isUpgradeCancelled(res)) {
   *   // the user declined the step-up — not an authorization failure
   * }
   * ```
   */
  withAuth(next?: FetchLike): FetchLike {
    return this.upgrade.withAuth(next);
  }

  /**
   * Attaches step-up handling to an axios instance the caller already owns,
   * **mutating** it, and returns a `detach()` disposer.
   *
   * The parameter is typed structurally — duck-typed on
   * `interceptors.response.use` — so this package's axios version is not a
   * constraint on the caller's. It returns the disposer rather than the
   * instance on purpose: it mutates, so returning the instance would read as if
   * it had built something.
   *
   * @example
   * ```typescript
   * const api = axios.create({ baseURL: 'https://api.example.com' });
   * const detach = passflow.attachAuth(api);
   * ```
   */
  attachAuth(instance: ResponseInterceptorHost): () => void {
    return this.upgrade.attachAuth(instance);
  }

  /**
   * Builds a ready axios instance with step-up handling already wired, for a
   * caller with no HTTP client of their own.
   *
   * Pure passthrough of axios' own create options, so `baseURL`, `headers`,
   * `timeout` and `adapter` stay the caller's. A `baseURL` is NOT read as a
   * declared backend — that would derive an interception scope through a side
   * door; declare it with `upgrade.enable({ backend })`.
   *
   * @example
   * ```typescript
   * const api = passflow.createClient({ baseURL: 'https://api.example.com' });
   * ```
   */
  createClient(config?: CreateClientConfig): AxiosInstance {
    return createUpgradeClient(config, (instance) => this.upgrade.attachAuth(instance));
  }

  /**
   * The assurance bar the session currently holds, read from the `acr` claim of
   * the stored access token.
   *
   * The server scores `acr` and is the only authority; this is the client-side
   * read of what it last said, and it is what lets an `insufficient` outcome
   * report a real `obtained` bar instead of the bar the ceremony was ranked for.
   */
  private readAssuranceBar(): AssuranceBar | undefined {
    const token = this.storageManager.getToken(TokenType.access_token);
    if (!token) {
      return undefined;
    }
    try {
      const claims = parseToken(token) as { acr?: unknown; auth_time?: unknown };
      const acrValues = typeof claims.acr === 'string' ? claims.acr : undefined;
      if (!acrValues) {
        return undefined;
      }
      const level = readAcrValues(acrValues).level;
      return level === undefined ? { acrValues } : { acrValues, level };
    } catch {
      // An unparseable token tells us nothing about the bar, and guessing one
      // would be worse than reporting the ranked approximation.
      return undefined;
    }
  }

  /** Every axios client this instance owns, which is every surface a Passflow 401 can arrive on. */
  private axiosClients(): AxiosClient[] {
    return [
      this.authApi['axiosClient'],
      this.appApi['axiosClient'],
      this.userApi['axiosClient'],
      this.settingApi['axiosClient'],
      this.tenantApi['axiosClient'],
      this.invitationApi['axiosClient'],
      this.twoFactorApi['axiosClient'],
      this.upgradeApi['axiosClient'],
    ];
  }

  /**
   * Installs (or clears) §4.4's internal seam on every one of the SDK's own
   * clients.
   *
   * Each client gets a handler bound to its OWN `replay`, so a replayed request
   * goes back out through the instance that issued it. The seam is consulted
   * inside the existing error interceptor, which is where it has to live: axios
   * runs response interceptors FIFO and that handler converts the `AxiosError`
   * into a `PassflowError` with no headers and no config, so anything
   * registered afterwards is structurally too late.
   */
  private attachUpgradeSeam(
    factory: ((reissue: (config: unknown) => Promise<unknown>) => (error: unknown) => Promise<unknown>) | undefined,
  ): void {
    for (const client of this.axiosClients()) {
      if (!factory) {
        client.setUpgradeInterceptor(undefined);
        continue;
      }
      const handler = factory((config) => client.replay(config as Parameters<AxiosClient['replay']>[0]));
      client.setUpgradeInterceptor(handler as unknown as AxiosUpgradeHandler);
    }
  }

  /**
   * Notifies on a session change, which the facade answers by discarding its
   * controller.
   *
   * `SignIn` and `SignOut` both count: a challenge is server-bound to the
   * session's `sid`, so an elevation abandoned across either boundary must never
   * elevate the NEW session.
   */
  private subscribeToSessionChange(listener: () => void): () => void {
    const subscriber: PassflowSubscriber = {
      onAuthChange: () => listener(),
    };
    this.subscribeStore.subscribe(subscriber, [PassflowEvent.SignIn, PassflowEvent.SignOut]);
    return () => this.subscribeStore.unsubscribe(subscriber);
  }

  // Session management
  /**
   * Configure session callbacks and check current session status.
   *
   * **WARNING**: Calling this method multiple times will overwrite previously registered callbacks.
   * Only the most recent `createSession` and `expiredSession` callbacks will be active.
   *
   * @param params - Session configuration parameters
   * @param params.createSession - Callback invoked when a valid session exists or is created
   * @param params.expiredSession - Callback invoked when no valid session exists
   * @param params.doRefresh - Whether to automatically refresh expired tokens (default: false)
   * @returns Promise that resolves when session check is complete
   *
   * @example
   * ```typescript
   * await passflow.session({
   *   createSession: async ({ tokens, parsedTokens }) => {
   *     console.log('User is authenticated', parsedTokens?.access_token?.sub);
   *     // Initialize user session in your app
   *   },
   *   expiredSession: async () => {
   *     console.log('User session expired');
   *     // Redirect to login or show login modal
   *   },
   *   doRefresh: true // Automatically refresh tokens if expired
   * });
   * ```
   */
  session: ({ createSession, expiredSession, doRefresh }: SessionParams) => Promise<void> = async ({
    createSession,
    expiredSession,
    doRefresh = false,
  }) => {
    this.createSessionCallback = createSession;
    this.expiredSessionCallback = expiredSession;
    this.doRefreshTokens = doRefresh;

    await this.submitSessionCheck();
  };

  private async submitSessionCheck() {
    let tokens;
    let parsedTokens;
    try {
      tokens = await this.authService.getTokens(this.doRefreshTokens);
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

    if (tokens && this.createSessionCallback) {
      await this.createSessionCallback({ tokens, parsedTokens });
    }

    if (!tokens && this.expiredSessionCallback) {
      await this.expiredSessionCallback();
    }
  }

  // Event subscription
  /**
   * Subscribe to Passflow authentication events.
   *
   * @param subscriber - Subscriber function that receives event type and payload
   * @param events - Optional array of specific events to listen for. If omitted, subscribes to all events.
   *
   * @example
   * ```typescript
   * // Subscribe to all events
   * passflow.subscribe((event, payload) => {
   *   console.log('Event:', event, payload);
   * });
   *
   * // Subscribe to specific events only
   * passflow.subscribe(
   *   (event, payload) => {
   *     if (event === PassflowEvent.SignIn) {
   *       console.log('User signed in', payload.tokens);
   *     }
   *   },
   *   [PassflowEvent.SignIn, PassflowEvent.SignOut]
   * );
   * ```
   */
  subscribe(subscriber: PassflowSubscriber, events?: PassflowEvent[]) {
    this.subscribeStore.subscribe(subscriber, events);

    // Initialize token cache service and token event listener
    this.tokenCacheService.initialize();
  }

  /**
   * Unsubscribe from Passflow authentication events.
   *
   * @param subscriber - The subscriber function to remove
   * @param events - Optional array of specific events to unsubscribe from. If omitted, unsubscribes from all events.
   *
   * @example
   * ```typescript
   * const subscriber = (event, payload) => console.log(event, payload);
   *
   * // Subscribe
   * passflow.subscribe(subscriber);
   *
   * // Later, unsubscribe
   * passflow.unsubscribe(subscriber);
   * ```
   */
  unsubscribe(subscriber: PassflowSubscriber, events?: PassflowEvent[]) {
    this.subscribeStore.unsubscribe(subscriber, events);
  }

  // Token handling
  /**
   * Handle OAuth redirect callback and take tokens from the URL query or fragment.
   * This method should be called on the redirect page after authentication.
   *
   * The tokens are removed from the URL at once, then verified in the background against the
   * configured server's published keys and this app id (required). `SignIn` with
   * `source: 'tokens-in-url'` (tokens saved), or `Error` with operation `tokens.from-url` (nothing
   * saved), reports the outcome, so subscribe first.
   *
   * @example
   * ```typescript
   * // On your redirect page (e.g., /auth/callback)
   * passflow.subscribe(
   *   { onAuthChange: (event, payload) => console.log(event, payload) },
   *   [PassflowEvent.SignIn, PassflowEvent.Error],
   * );
   * passflow.handleTokensRedirect();
   * ```
   *
   * A PKCE federated landing (`?code=`) returns `undefined` and finishes in the background: `SignIn`
   * or `TwoFactorRequired` is the signal. With `deferFederatedLanding` it is left to
   * `completeFederatedLanding()`.
   */
  handleTokensRedirect(): void {
    this.checkAndSetTokens();
  }

  /**
   * Takes a PKCE federated landing (`?code=&user_state=`) on this page, for an instance built with
   * `deferFederatedLanding`. The code is exchanged in the background; `SignIn` with
   * `source: 'federated-landing'`, `TwoFactorRequired`, or `Error` with operation `federated.redirect`
   * reports the outcome, so subscribe first.
   *
   * @returns true when this tab started that sign-in and the exchange began. On false, neither the
   * URL nor the stored proof key has changed, so an instance that has its app id can still take it.
   */
  completeFederatedLanding(): boolean {
    return this.takeFederatedLanding();
  }

  private checkAndSetTokens(): void {
    // Cache the URL once to avoid redundant calls (especially for async/expensive adapters)
    const currentUrl = this.platform.getCurrentUrl();

    // Check query params first, then fall back to hash
    // React SDK may put tokens in hash (more secure), while some OAuth flows use query params
    let urlParams = new URLSearchParams(currentUrl?.search ?? '');

    // If no access_token in query params, check hash
    if (!urlParams.get('access_token') && currentUrl?.hash) {
      // Hash format: #access_token=xxx&refresh_token=yyy
      const hashParams = new URLSearchParams(currentUrl.hash.substring(1));
      if (hashParams.get('access_token')) {
        urlParams = hashParams;
      }
    }

    // A sign-in that owes its second factor lands with `#tfa_token=` and no
    // tokens (a federated GET callback on a non-PKCE app).
    if (!urlParams.get('access_token') && this.adoptTwoFactorTokenFromUrl(currentUrl)) {
      this.error = undefined;
      return undefined;
    }

    const access_token = urlParams.get('access_token');
    const refresh_token = urlParams.get('refresh_token');
    const id_token = urlParams.get('id_token');
    const scopes: string[] = urlParams.get('scopes')?.split(',') ?? this.scopes;

    if (access_token) {
      // Validate JWT format for access_token
      if (!isValidJWTFormat(access_token)) {
        const errorPayload: OperationErrorPayload = {
          operation: 'tokens.from-url',
          message: 'Invalid access token format received',
          code: 'INVALID_TOKEN_FORMAT',
        };
        notifyError(this.subscribeStore, errorPayload);
        this.cleanupUrlParams(currentUrl);
        return undefined;
      }

      // Validate optional refresh_token if present
      if (refresh_token && !isValidJWTFormat(refresh_token)) {
        const errorPayload: OperationErrorPayload = {
          operation: 'tokens.from-url',
          message: 'Invalid refresh token format received',
          code: 'INVALID_TOKEN_FORMAT',
        };
        notifyError(this.subscribeStore, errorPayload);
        this.cleanupUrlParams(currentUrl);
        return undefined;
      }

      // Validate optional id_token if present
      if (id_token && !isValidJWTFormat(id_token)) {
        const errorPayload: OperationErrorPayload = {
          operation: 'tokens.from-url',
          message: 'Invalid ID token format received',
          code: 'INVALID_TOKEN_FORMAT',
        };
        notifyError(this.subscribeStore, errorPayload);
        this.cleanupUrlParams(currentUrl);
        return undefined;
      }

      const tokens: Tokens = {
        access_token,
        refresh_token: refresh_token ?? undefined,
        id_token: id_token ?? undefined,
        scopes,
      };

      this.cleanupUrlParams(currentUrl);
      this.error = undefined;
      // A failure to verify or to save the tokens is one `tokens.from-url` Error; what runs after
      // SignIn (subscribers, the session check) reports its own failures.
      verifyUrlTokens(this.url, this.appId, tokens)
        .then(() => {
          // URL tokens mean we're in JSON mode, not cookie/BFF mode
          // Clear any stored delivery mode to ensure consistent behavior
          this.storageManager.clearDeliveryMode();
          this.storageManager.saveTokens(tokens);
          this.tokenCacheService.setTokensCache(tokens);
          this.authService.refresh.sessionStarted();
        })
        .then(
          () => {
            this.subscribeStore.notify(PassflowEvent.SignIn, {
              tokens,
              parsedTokens: this.getParsedTokens(),
              source: 'tokens-in-url',
            });
            return this.submitSessionCheck();
          },
          (error: unknown) =>
            notifyError(this.subscribeStore, {
              operation: 'tokens.from-url',
              message: error instanceof Error ? error.message : 'Tokens in the URL could not be verified',
              code: 'TOKEN_NOT_VERIFIED',
              originalError: error,
            }),
        );
      return undefined;
    } else {
      this.cleanupUrlParams(currentUrl);
      if (!this.deferFederatedLanding) {
        this.takeFederatedLanding();
      }
      this.error = this.checkErrorsFromURL();
    }
    return undefined;
  }

  /**
   * Removes only `code` and `user_state`, and only once the code is taken, so `appid` and
   * `redirectto` stay for the login page. A code this tab did not ask for leaves the URL as it is.
   */
  private takeFederatedLanding(): boolean {
    const currentUrl = this.platform.getCurrentUrl();
    if (!currentUrl) return false;

    const urlParams = new URLSearchParams(currentUrl.search);
    const code = urlParams.get('code');
    const hasTokens = urlParams.get('access_token') || new URLSearchParams(currentUrl.hash?.substring(1)).get('access_token');
    if (hasTokens || !code || !urlParams.get('user_state') || !this.authService.handleFederatedCode(code)) {
      return false;
    }

    urlParams.delete('code');
    urlParams.delete('user_state');
    const rest = urlParams.toString();
    this.platform.replaceUrl(currentUrl.pathname + (rest ? `?${rest}` : '') + currentUrl.hash);
    return true;
  }

  /**
   * Adopts a `#tfa_token=` fragment: the 2FA token goes to the TwoFactorService
   * through `TwoFactorRequired`, exactly as a password sign-in's does, and the
   * fragment is stripped from the URL. Nothing is saved as a session.
   *
   * @returns true when the URL carried a 2FA token
   */
  private adoptTwoFactorTokenFromUrl(currentUrl: CurrentUrlInfo | null): boolean {
    if (!currentUrl?.hash) return false;
    const hashParams = new URLSearchParams(currentUrl.hash.substring(1));
    const tfaToken = hashParams.get('tfa_token');
    if (!tfaToken) return false;

    hashParams.delete('tfa_token');
    const rest = hashParams.toString();
    this.platform.replaceUrl(currentUrl.pathname + currentUrl.search + (rest ? `#${rest}` : ''));

    if (!isValidJWTFormat(tfaToken)) {
      const errorPayload: OperationErrorPayload = {
        operation: 'tokens.from-url',
        message: 'Invalid 2FA token format received',
        code: 'INVALID_TOKEN_FORMAT',
      };
      notifyError(this.subscribeStore, errorPayload);
      return true;
    }

    this.subscribeStore.notify(PassflowEvent.TwoFactorRequired, { email: '', challengeId: '', tfaToken });
    return true;
  }

  private checkErrorsFromURL(): Error | undefined {
    const urlParams = new URLSearchParams(this.platform.getCurrentUrl()?.search ?? '');
    const error = urlParams.get('error');
    if (error) {
      // Sanitize error message to prevent XSS
      const sanitized = sanitizeErrorMessage(error);
      return new Error(sanitized);
    }
    return undefined;
  }

  /**
   * When a token appears in the query or the fragment, removes every token from the query and drops
   * a token-carrying fragment, in one history replace. Other query params stay.
   */
  private cleanupUrlParams(url: CurrentUrlInfo | null): void {
    if (!url) return; // no URL context (SSR or unsupported environment)

    const names = ['access_token', 'refresh_token', 'id_token'];
    const query = new URLSearchParams(url.search);
    const hash = new URLSearchParams(url.hash?.substring(1));
    const hashHasTokens = names.some((name) => hash.get(name));
    if (!hashHasTokens && !names.some((name) => query.get(name))) return;

    for (const name of [...names, 'client_challenge']) query.delete(name);
    const rest = query.toString();
    this.platform.replaceUrl(url.pathname + (rest ? `?${rest}` : '') + (hashHasTokens ? '' : (url.hash ?? '')));
  }

  private setTokensToCacheFromLocalStorage(): void {
    let tokens = this.storageManager.getTokens();

    // If tokens don't have access_token, check for inconsistent state
    // This can happen if delivery_mode is set to BFF but tokens were actually saved in JSON mode
    if (!tokens?.access_token) {
      const deliveryMode = this.storageManager.getDeliveryMode();
      if (deliveryMode) {
        // Delivery mode is set (cookie/BFF mode)
        // Check if this is legitimate cookie mode or stale state

        if (tokens?.id_token && this.storageManager.hasCookieModeIdToken()) {
          // Legitimate cookie/BFF mode: we have id_token from cookie mode storage
          // Access token is in HttpOnly cookies, not localStorage - this is valid
          this.tokenCacheService.setTokensCache(tokens);
          return;
        }

        // Check if there are JSON mode tokens that should be used instead
        if (this.storageManager.hasJsonModeTokens()) {
          // Stale state: delivery_mode is set but JSON tokens exist
          // Clear delivery mode and use JSON tokens
          this.storageManager.clearDeliveryMode();
          tokens = this.storageManager.getTokens();
        } else {
          // No valid tokens in either mode - clean up completely
          this.storageManager.deleteTokens();
          return;
        }
      }
    }

    if (tokens) {
      this.tokenCacheService.setTokensCache(tokens);
    }
  }

  /**
   * Get cached tokens from memory without triggering a refresh.
   *
   * @returns Cached tokens or undefined if not cached
   *
   * @example
   * ```typescript
   * const tokens = passflow.getCachedTokens();
   * if (tokens) {
   *   console.log('Access token:', tokens.access_token);
   * }
   * ```
   */
  getCachedTokens() {
    return this.tokenCacheService.getTokens();
  }

  /**
   * Get cached tokens from memory and automatically refresh if expired.
   *
   * @returns Promise resolving to tokens or undefined
   *
   * @example
   * ```typescript
   * const tokens = await passflow.getTokensWithRefresh();
   * // Tokens are guaranteed to be valid or undefined
   * ```
   */
  getTokensWithRefresh() {
    return this.tokenCacheService.getTokensWithRefresh();
  }

  /**
   * Get parsed JWT tokens with decoded claims.
   *
   * @returns Parsed token objects with decoded payloads
   *
   * @example
   * ```typescript
   * const parsed = passflow.getParsedTokens();
   * if (parsed?.access_token) {
   *   console.log('User ID:', parsed.access_token.sub);
   *   console.log('Expires at:', new Date(parsed.access_token.exp * 1000));
   * }
   * ```
   */
  getParsedTokens() {
    return this.tokenCacheService.getParsedTokens();
  }

  /**
   * Check if the cached tokens are expired.
   *
   * @returns True if tokens are expired, false otherwise
   *
   * @example
   * ```typescript
   * if (passflow.areTokensExpired()) {
   *   await passflow.refreshToken();
   * }
   * ```
   */
  areTokensExpired() {
    return this.tokenCacheService.isExpired();
  }

  // Auth delegation methods
  /**
   * Check if the user is currently authenticated with valid tokens.
   *
   * @returns True if user has valid, non-expired tokens
   *
   * @example
   * ```typescript
   * if (passflow.isAuthenticated()) {
   *   console.log('User is logged in');
   * } else {
   *   console.log('User needs to sign in');
   * }
   * ```
   */
  isAuthenticated(): boolean {
    // Cookie/BFF: no access token is readable; the id token and the session state decide.
    const mode = this.getDeliveryMode();
    if (mode === TokenDeliveryMode.Cookie || mode === TokenDeliveryMode.BFF) {
      return this.authService.isAuthenticated(this.tokenCacheService.getParsedTokens() ?? {});
    }
    const tokens = this.storageManager.getTokens();
    if (!tokens || !tokens.access_token) return false;

    // Use cached parsed tokens instead of re-parsing
    const parsedTokens = this.tokenCacheService.getParsedTokens();
    if (!parsedTokens) return false;

    return this.authService.isAuthenticated(parsedTokens);
  }

  /**
   * Sign in a user with email/username and password.
   *
   * @param payload - Sign-in credentials and options
   * @param payload.email - User's email or username
   * @param payload.password - User's password
   * @param payload.scopes - Optional scopes to request (defaults to SDK scopes)
   * @returns Promise with authorization response containing tokens
   * May answer an email verification step instead of tokens: check it with
   * `isEmailVerificationStep(response)`. With a `challenge_id`, finish with `verifyEmailCode`.
   * @throws {PassflowError} If authentication fails
   *
   * @example
   * ```typescript
   * try {
   *   const response = await passflow.signIn({
   *     email: 'user@example.com',
   *     password: 'secure-password'
   *   });
   *   console.log('Signed in successfully', response.access_token);
   * } catch (error) {
   *   console.error('Sign in failed', error.message);
   * }
   * ```
   */
  async signIn(payload: PassflowSignInPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.signIn(payload);

    return response;
  }

  /**
   * Register a new user account with email and password.
   *
   * @param payload - Registration details
   * @param payload.email - User's email address
   * @param payload.password - User's password
   * @param payload.username - Optional username
   * @param payload.scopes - Optional scopes to request
   * @returns Promise with authorization response containing tokens
   * May answer an email verification step instead of tokens: check it with
   * `isEmailVerificationStep(response)`. With a `challenge_id`, finish with `verifyEmailCode`.
   * @throws {PassflowError} If registration fails
   *
   * @example
   * ```typescript
   * try {
   *   const response = await passflow.signUp({
   *     email: 'newuser@example.com',
   *     password: 'secure-password',
   *     username: 'newuser'
   *   });
   *   console.log('Account created', response.access_token);
   * } catch (error) {
   *   console.error('Sign up failed', error.message);
   * }
   * ```
   */
  async signUp(payload: PassflowSignUpPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.signUp(payload);

    return response;
  }

  /**
   * Initiate passwordless authentication by sending a magic link or OTP.
   *
   * @param payload - Passwordless sign-in configuration
   * @param payload.email - User's email address
   * @param payload.method - Delivery method ('email' or 'sms')
   * @returns Promise with response indicating if the code was sent
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * // Send magic link via email
   * const response = await passflow.passwordlessSignIn({
   *   email: 'user@example.com',
   *   method: 'email'
   * });
   * console.log('Magic link sent:', response.success);
   * ```
   */
  passwordlessSignIn(payload: PassflowPasswordlessSignInPayload): Promise<PassflowPasswordlessResponse> {
    return this.authService.passwordlessSignIn(payload);
  }

  /**
   * Complete passwordless authentication by verifying the OTP or token.
   *
   * @param payload - Verification payload
   * @param payload.email - User's email address
   * @param payload.code - Verification code from email/SMS
   * @param payload.scopes - Optional scopes to request
   * @returns Promise with validation response containing tokens
   * @throws {PassflowError} If verification fails
   *
   * @example
   * ```typescript
   * try {
   *   const response = await passflow.passwordlessSignInComplete({
   *     email: 'user@example.com',
   *     code: '123456'
   *   });
   *   console.log('Passwordless sign-in complete', response.access_token);
   * } catch (error) {
   *   console.error('Invalid code', error.message);
   * }
   * ```
   */
  async passwordlessSignInComplete(payload: PassflowPasswordlessSignInCompletePayload): Promise<PassflowValidationResponse> {
    const response = await this.authService.passwordlessSignInComplete(payload);

    return response;
  }

  /**
   * Waits for a magic-link sign-in this tab started to be approved on another device, then
   * finishes it here. Polls every 3 s until the challenge expires; network errors, 429 and 5xx keep
   * polling. Emits `SignIn` or `TwoFactorRequired` as any other sign-in does.
   *
   * Aborting rejects with `signal.reason` and keeps the sign-in, so a later call can wait again.
   * Once the approval has been read, the token exchange finishes regardless of the signal.
   *
   * @param challengeId - The `challenge_id` from `passwordlessSignIn`
   * @param options - Optional `signal` to stop waiting
   * @returns `signed-in` with the tokens, or `second-factor-required`, `denied`, `expired`, `completed`
   * @throws When this tab no longer holds the sign-in, on a refused status poll, or on a failed exchange
   *
   * @example
   * ```typescript
   * const { challenge_id } = await passflow.passwordlessSignIn(payload);
   * const pending = passflow.getPendingPasswordlessSignIn(challenge_id);
   * if (pending) {
   *   showCode(pending.matchCode);
   *   const result = await passflow.waitForPasswordlessSignIn(challenge_id);
   * }
   * ```
   */
  waitForPasswordlessSignIn(challengeId: string, options?: { signal?: AbortSignal }): Promise<PasswordlessWaitResult> {
    return this.authService.waitForPasswordlessSignIn(challengeId, options);
  }

  /**
   * The code to show while waiting for approval on another device.
   *
   * @param challengeId - The `challenge_id` from `passwordlessSignIn`
   * @returns The match code and expiry (epoch milliseconds), or `undefined` unless this tab started
   * that sign-in and it can be approved from another device
   */
  getPendingPasswordlessSignIn(challengeId: string): { matchCode: string; expiresAt: number } | undefined {
    return this.authService.getPendingPasswordlessSignIn(challengeId);
  }

  /**
   * Reads what the device that opened a magic link shows before approving: app, requesting browser
   * and OS, location, time and attempts left. It holds no identity and changes nothing on the server.
   *
   * @param challengeId - The `challenge_id` from the link
   * @returns The approval context
   * @throws {PassflowError} If the challenge is unknown or cannot be approved
   */
  getPasswordlessApproval(challengeId: string): Promise<PasswordlessApprovalInfo> {
    return this.authService.getPasswordlessApproval(challengeId);
  }

  /**
   * Approves or denies a waiting sign-in from the device that opened the magic link. The tab that
   * started the sign-in finishes it; this device gets no tokens.
   *
   * @param challengeId - The `challenge_id` from the link
   * @param otp - The one-time code from the link
   * @param approve - `true` to approve, `false` to deny
   * @param matchCode - The code the user read from the waiting tab. Needed to approve.
   * @throws {PassflowError} If the code is wrong, the sign-in is expired or already decided
   */
  decidePasswordlessApproval(challengeId: string, otp: string, approve: boolean, matchCode?: string): Promise<void> {
    return this.authService.decidePasswordlessApproval(challengeId, otp, approve, matchCode);
  }

  /**
   * Finishes a sign-up, sign-in or password change that answered with `email_verification_required`
   * and a `challenge_id`, using the code the user received by email. Answers like `signIn`: a new
   * token pair, or a `tfa_token` when a second factor is owed (`isTwoFactorVerificationRequired()`
   * is then true).
   *
   * Emits `Register` for a challenge this instance got from `signUp`, and `SignIn` otherwise. The
   * challenges are remembered in memory only, so a code typed in another tab or after the
   * `Passflow` instance was recreated emits `SignIn`, even for a sign-up.
   *
   * @param payload.challenge_id - The `challenge_id` from the email verification step
   * @param payload.otp - The code from the email
   * @throws {PassflowError} wrong, expired or spent code (`error.otp.*`), unknown challenge (`error.not.found`)
   *
   * @example
   * ```typescript
   * const step = await passflow.signUp({ user: { email, password } });
   * if (isEmailVerificationStep(step) && step.challenge_id) {
   *   const response = await passflow.verifyEmailCode({ challenge_id: step.challenge_id, otp: '123456' });
   * }
   * ```
   */
  async verifyEmailCode(payload: PassflowEmailCodePayload): Promise<PassflowAuthorizationResponse> {
    return await this.authService.verifyEmailCode(payload);
  }

  /**
   * Centralized error handler for all public methods.
   * Creates proper ErrorPayload, distinguishes PassflowError from generic Error,
   * notifies error event, and re-throws the error.
   *
   * Reports at most once per error object: when a service already reported it (a 2FA wrapper,
   * a sign-in), the service's more specific report stands and nothing is added here.
   *
   * @param error - The error to handle
   * @param operation - The operation that failed (`ErrorPayload.operation`)
   * @param context - Context description for the fallback message
   * @throws The original error after handling
   */
  /**
   * Asks the server whether this app may redirect to `url`.
   *
   * Navigate to the address it resolves to, not the one passed in. Treat any rejection as a refusal.
   *
   * @param url - The address to check
   * @returns The address to navigate to
   * @throws {PassflowError} `error.app.redirect.url.not.registered` when refused, or a request error
   */
  async checkRedirectUrl(url: string): Promise<string> {
    try {
      return await this.authService.checkRedirectUrl(url);
    } catch (error) {
      this.handleError(error, 'redirect.check', 'Redirect check');
    }
  }

  private handleError(error: unknown, operation: PassflowOperation, context: string): never {
    const errorPayload: OperationErrorPayload = {
      operation,
      message: error instanceof Error ? error.message : `${context} failed`,
      originalError: error,
      code: error instanceof PassflowError ? error.id : undefined,
    };
    notifyError(this.subscribeStore, errorPayload);
    throw error;
  }

  /**
   * Sign out the current user and clear all tokens.
   *
   * @returns Promise that resolves when sign-out is complete
   * @throws {PassflowError} If sign-out request fails
   *
   * @example
   * ```typescript
   * try {
   *   await passflow.logOut();
   *   console.log('User signed out successfully');
   *   // Redirect to login page
   * } catch (error) {
   *   console.error('Sign out failed', error.message);
   * }
   * ```
   */
  async logOut(): Promise<void> {
    try {
      // Under the refresh lock: logs out the newest token, deletes storage, clears the cache.
      const userId = await this.authService.logOut();
      this.twoFactorService.clearPartialAuthState();
      // Exactly one SignOut, after the cache is cleared; also when the session had already ended.
      this.notifySignedOut(userId);
      await this.submitSessionCheck();
    } catch (error) {
      this.handleError(error, 'log-out', 'Log out');
    }
  }

  /**
   * Initiate federated authentication (OAuth) with a popup window.
   *
   * @param payload - Federated authentication configuration
   * @param payload.provider - OAuth provider (e.g., 'google', 'github', 'microsoft')
   * @param payload.scopes - Optional scopes to request
   *
   * @example
   * ```typescript
   * // Sign in with Google using a popup
   * passflow.federatedAuthWithPopup({
   *   provider: 'google'
   * });
   *
   * // Listen for the result via subscribe
   * passflow.subscribe((event, payload) => {
   *   if (event === PassflowEvent.SignIn) {
   *     console.log('OAuth sign-in successful', payload.tokens);
   *   }
   * });
   * ```
   */
  federatedAuthWithPopup(payload: PassflowFederatedAuthPayload): void {
    this.authService.federatedAuthWithPopup(payload);
  }

  /**
   * Initiate federated authentication (OAuth) with a full-page redirect.
   *
   * @param payload - Federated authentication configuration
   * @param payload.provider - OAuth provider (e.g., 'google', 'github', 'microsoft')
   * @param payload.scopes - Optional scopes to request
   * @param payload.redirectUrl - URL to redirect to after authentication
   *
   * @example
   * ```typescript
   * // Sign in with GitHub using redirect
   * passflow.federatedAuthWithRedirect({
   *   provider: 'github',
   *   redirectUrl: window.location.origin + '/auth/callback'
   * });
   * ```
   */
  federatedAuthWithRedirect(payload: PassflowFederatedAuthPayload): void {
    this.authService.federatedAuthWithRedirect(payload);
  }

  /**
   * Reset the SDK state by clearing all tokens and optionally throwing an error.
   *
   * @param error - Optional error message to throw after reset
   * @throws {Error} If error message is provided
   *
   * @example
   * ```typescript
   * // Clear tokens without error
   * passflow.reset();
   *
   * // Clear tokens and throw error
   * try {
   *   passflow.reset('Session expired');
   * } catch (error) {
   *   console.error('Reset error:', error.message);
   * }
   * ```
   */
  reset(error?: string) {
    // Synchronous: no API call, no lock. Stops this tab's refresh, tells the other tabs, deletes
    // storage and clears the cache before the one SignOut.
    this.notifySignedOut(this.authService.resetSession());
    if (error) {
      this.error = new Error(error);
      const errorPayload: OperationErrorPayload = {
        operation: 'reset',
        message: error,
        code: 'RESET_ERROR',
      };
      notifyError(this.subscribeStore, errorPayload);
      throw this.error;
    }
  }

  /** The one `SignOut` of `logOut()`/`reset()` in this tab (PFL-792 §2.4). */
  private notifySignedOut(userId: string | undefined): void {
    this.subscribeStore.notify(
      PassflowEvent.SignOut,
      userId === undefined ? { origin: 'this-tab' } : { origin: 'this-tab', userId },
    );
  }

  /**
   * Releases what this instance holds for token refresh: leaves the refresh lock queue, cancels
   * every refresh timer and the token check, removes its storage and foreground listeners, closes
   * its BroadcastChannel, and rejects pending refresh callers with `PassflowRefreshError`
   * (`error.refresh.disposed`). Afterwards the instance must not be used.
   *
   * The SDK never calls it by itself, not on `beforeunload` (it fires before a cancellable
   * "Leave site?" prompt and before a page enters the back/forward cache) nor on `pagehide`:
   * document teardown already releases the page's locks and channels. Call it when an SPA tears
   * the instance down, and in tests.
   *
   * @example
   * ```typescript
   * passflow.dispose();
   * ```
   */
  dispose(): void {
    this.authService.refresh.dispose();
    this.tokenCacheService.destroy();
  }

  /**
   * Refresh the access token using the refresh token.
   *
   * @returns Promise with new authorization response containing refreshed tokens
   * @throws {Error} JSON mode with no stored refresh token (`No tokens found` / `No refresh token found`)
   * @throws {PassflowRefreshError} `error.refresh.session_ended` and the other ends, once the session ended
   * @throws {PassflowError} If refresh request fails
   *
   * @example
   * ```typescript
   * try {
   *   const response = await passflow.refreshToken();
   *   console.log('Token refreshed', response.access_token);
   * } catch (error) {
   *   console.error('Failed to refresh token', error.message);
   *   // Redirect to login
   * }
   * ```
   */
  async refreshToken(): Promise<PassflowAuthorizationResponse> {
    // The no-token rejections ('No tokens found' / 'No refresh token found') are JSON mode's and
    // live in AuthService: cookie and BFF modes have no readable refresh token, and an ended
    // session rejects with `error.refresh.session_ended`.
    // The refresh path reports its own failure, once (Error{refresh}); nothing is added here.
    return await this.authService.refreshToken();
  }

  /**
   * Send a password reset email to the user.
   *
   * @param payload - Password reset request
   * @param payload.email - User's email address
   * @returns Promise with success response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * try {
   *   await passflow.sendPasswordResetEmail({
   *     email: 'user@example.com'
   *   });
   *   console.log('Password reset email sent');
   * } catch (error) {
   *   console.error('Failed to send reset email', error.message);
   * }
   * ```
   */
  sendPasswordResetEmail(payload: PassflowSendPasswordResetEmailPayload): Promise<PassflowSuccessResponse> {
    return this.authService.sendPasswordResetEmail(payload);
  }

  /**
   * Reset password using a reset token (typically from URL after clicking email link).
   *
   * @param newPassword - The new password to set
   * @param scopes - Optional scopes to request after reset
   * @param resetToken - The reset link's token. Without it the token is read from `?token=` in
   *   `location.search`, then from a hash route's query (`#/reset?token=…`). Pass it when your
   *   router keeps the link's query somewhere else (memory router).
   * @returns Promise with authorization response containing new tokens
   * May answer an email verification step instead of tokens: check it with
   * `isEmailVerificationStep(response)`. With a `challenge_id`, finish with `verifyEmailCode`.
   * @throws {PassflowError} If reset fails
   *
   * @example
   * ```typescript
   * // On password reset page (e.g., /reset-password?token=xyz)
   * try {
   *   const response = await passflow.resetPassword('new-secure-password');
   *   console.log('Password reset successful', response.access_token);
   * } catch (error) {
   *   console.error('Password reset failed', error.message);
   * }
   * ```
   */
  async resetPassword(newPassword: string, scopes?: string[], resetToken?: string): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.resetPassword(newPassword, scopes, resetToken);

    return response;
  }

  // App settings
  /**
   * Get application settings and configuration.
   *
   * @returns Promise with app settings including branding, features, and config
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const settings = await passflow.getAppSettings();
   * console.log('App name:', settings.name);
   * console.log('Passwordless enabled:', settings.passwordless_enabled);
   * ```
   */
  async getAppSettings(): Promise<AppSettings> {
    try {
      return await this.appApi.getAppSettings();
    } catch (error) {
      this.handleError(error, 'settings.app', 'Get app settings');
    }
  }

  /**
   * Get all Passflow settings including password policy, passkey settings, etc.
   *
   * @returns Promise with all settings
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const settings = await passflow.getSettingsAll();
   * console.log('Password policy:', settings.password_policy);
   * console.log('Passkey settings:', settings.passkey);
   * ```
   */
  async getSettingsAll(): Promise<PassflowSettingsAll> {
    try {
      return await this.settingApi.getSettingsAll();
    } catch (error) {
      this.handleError(error, 'settings.all', 'Get all settings');
    }
  }

  /**
   * Get password policy settings (min length, complexity requirements, etc.).
   *
   * @returns Promise with password policy configuration
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const policy = await passflow.getPasswordPolicySettings();
   * console.log('Min length:', policy.min_length);
   * console.log('Require uppercase:', policy.require_uppercase);
   * ```
   */
  async getPasswordPolicySettings(): Promise<PassflowPasswordPolicySettings> {
    try {
      return await this.settingApi.getPasswordPolicySettings();
    } catch (error) {
      this.handleError(error, 'settings.password-policy', 'Get password policy settings');
    }
  }

  /**
   * Get passkey (WebAuthn) configuration settings.
   *
   * @returns Promise with passkey settings
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const passkeySettings = await passflow.getPasskeySettings();
   * console.log('Passkeys enabled:', passkeySettings.enabled);
   * console.log('User verification:', passkeySettings.user_verification);
   * ```
   */
  async getPasskeySettings(): Promise<PassflowPasskeySettings> {
    try {
      return await this.settingApi.getPasskeySettings();
    } catch (error) {
      this.handleError(error, 'settings.passkey', 'Get passkey settings');
    }
  }

  // Passkey methods
  /**
   * Register a new user with a passkey (WebAuthn).
   *
   * @param payload - Passkey registration configuration
   * @param payload.email - User's email address
   * @param payload.username - Optional username
   * @param payload.scopes - Optional scopes to request
   * @returns Promise with authorization response containing tokens
   * @throws {PassflowError} If passkey registration fails
   *
   * @example
   * ```typescript
   * try {
   *   const response = await passflow.passkeyRegister({
   *     email: 'user@example.com',
   *     username: 'myusername'
   *   });
   *   console.log('Passkey registered', response.access_token);
   * } catch (error) {
   *   console.error('Passkey registration failed', error.message);
   * }
   * ```
   */
  async passkeyRegister(payload: PassflowPasskeyRegisterStartPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.passkeyRegister(payload);

    return response;
  }

  /**
   * Authenticate a user with a passkey (WebAuthn).
   *
   * @param payload - Passkey authentication configuration
   * @param payload.email - Optional user email to pre-fill
   * @param payload.scopes - Optional scopes to request
   * @returns Promise with authorization response containing tokens
   * @throws {PassflowError} If passkey authentication fails
   *
   * @example
   * ```typescript
   * try {
   *   // Let user select from available passkeys
   *   const response = await passflow.passkeyAuthenticate({});
   *   console.log('Passkey sign-in successful', response.access_token);
   * } catch (error) {
   *   console.error('Passkey authentication failed', error.message);
   * }
   * ```
   */
  async passkeyAuthenticate(payload: PassflowPasskeyAuthenticateStartPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.passkeyAuthenticate(payload);

    return response;
  }

  // Token management
  /**
   * Manually set tokens (useful after custom authentication flows).
   * This will save tokens to storage, update cache, and trigger SignIn event.
   *
   * @param tokensData - Tokens object to set
   * @param tokensData.access_token - JWT access token
   * @param tokensData.refresh_token - Optional refresh token
   * @param tokensData.id_token - Optional ID token
   * @param tokensData.scopes - Token scopes
   *
   * @example
   * ```typescript
   * // Set tokens from a custom auth flow
   * passflow.setTokens({
   *   access_token: 'eyJhbGci...',
   *   refresh_token: 'eyJhbGci...',
   *   id_token: 'eyJhbGci...',
   *   scopes: ['id', 'offline', 'email']
   * });
   * ```
   */
  setTokens(tokensData: Tokens): void {
    // Cookie and BFF modes keep only the id token locally, under the key the next load reads;
    // saving the JSON keys there would be dropped as stale state on the next page load.
    const mode = this.getDeliveryMode();
    const opaque = mode === TokenDeliveryMode.Cookie || mode === TokenDeliveryMode.BFF;
    this.storageManager.saveTokens(tokensData, opaque ? mode : undefined);
    this.tokenCacheService.setTokensCache(tokensData);
    // A new session: the refresh controller starts over on these tokens.
    this.authService.refresh.sessionStarted();
    this.subscribeStore.notify(PassflowEvent.SignIn, {
      tokens: tokensData,
      parsedTokens: this.tokenCacheService.getParsedTokens(),
    });
  }

  /**
   * Get current tokens from storage, optionally refreshing if expired.
   *
   * @param doRefresh - If true, automatically refresh expired tokens (default: false)
   * @returns Promise with tokens or undefined if not authenticated
   *
   * @example
   * ```typescript
   * // Get tokens without refresh
   * const tokens = await passflow.getTokens();
   *
   * // Get tokens and auto-refresh if expired
   * const freshTokens = await passflow.getTokens(true);
   * ```
   */
  async getTokens(doRefresh = false): Promise<Tokens | undefined> {
    return await this.authService.getTokens(doRefresh);
  }

  /**
   * Get a specific token from storage by type.
   *
   * @param tokenType - Type of token to retrieve ('access_token', 'refresh_token', 'id_token')
   * @returns Token string or undefined if not found
   *
   * @example
   * ```typescript
   * const accessToken = passflow.getToken('access_token');
   * if (accessToken) {
   *   // Use token for API calls
   *   fetch('/api/data', {
   *     headers: { Authorization: `Bearer ${accessToken}` }
   *   });
   * }
   * ```
   */
  getToken(tokenType: TokenType): string | undefined {
    return this.storageManager.getToken(tokenType);
  }

  // User passkey methods delegated to UserService
  /**
   * Get list of passkeys registered for the current user.
   *
   * @returns Promise with array of user's passkeys
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const passkeys = await passflow.getUserPasskeys();
   * passkeys.forEach(passkey => {
   *   console.log('Passkey:', passkey.name, passkey.id);
   * });
   * ```
   */
  async getUserPasskeys() {
    try {
      return await this.userService.getUserPasskeys();
    } catch (error) {
      this.handleError(error, 'passkey.list', 'Get user passkeys');
    }
  }

  /**
   * Rename a user's passkey to a friendly name.
   *
   * @param name - New friendly name for the passkey
   * @param passkeyId - ID of the passkey to rename
   * @returns Promise with success response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * await passflow.renameUserPasskey('My MacBook Pro', 'passkey-123');
   * console.log('Passkey renamed successfully');
   * ```
   */
  async renameUserPasskey(name: string, passkeyId: string): Promise<PassflowSuccessResponse> {
    try {
      return await this.userService.renameUserPasskey(name, passkeyId);
    } catch (error) {
      this.handleError(error, 'passkey.rename', 'Rename user passkey');
    }
  }

  /**
   * Delete a passkey from the user's account.
   *
   * @param passkeyId - ID of the passkey to delete
   * @returns Promise with success response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * await passflow.deleteUserPasskey('passkey-123');
   * console.log('Passkey deleted successfully');
   * ```
   */
  async deleteUserPasskey(passkeyId: string): Promise<PassflowSuccessResponse> {
    try {
      return await this.userService.deleteUserPasskey(passkeyId);
    } catch (error) {
      this.handleError(error, 'passkey.delete', 'Delete user passkey');
    }
  }

  /**
   * Add a new passkey to the current user's account (requires active session).
   *
   * @param options - Optional passkey configuration
   * @param options.relyingPartyId - Optional RP ID for the passkey
   * @param options.passkeyUsername - Optional username to associate with passkey
   * @param options.passkeyDisplayName - Optional display name for the passkey
   * @returns Promise that resolves when passkey is added
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * // Add passkey with default settings
   * await passflow.addUserPasskey();
   *
   * // Add passkey with custom display name
   * await passflow.addUserPasskey({
   *   passkeyDisplayName: 'My iPhone'
   * });
   * ```
   */
  async addUserPasskey(options?: {
    relyingPartyId?: string;
    passkeyUsername?: string;
    passkeyDisplayName?: string;
  }): Promise<void> {
    try {
      return await this.userService.addUserPasskey(options);
    } catch (error) {
      this.handleError(error, 'passkey.add', 'Add user passkey');
    }
  }

  // Tenant methods delegated to TenantService
  /**
   * Join a tenant invitation
   * @param token The invitation token
   * @param scopes Optional scopes to request
   * @returns Promise with invite response
   */
  async joinInvitation(token: string, scopes?: string[]): Promise<PassflowAuthorizationResponse> {
    try {
      const response = await this.tenant.joinInvitation(token, scopes);
      response.scopes = scopes ?? this.scopes;
      await this.authService.applyTokens(response);
      return response;
    } catch (error) {
      this.handleError(error, 'invitation.join', 'Join invitation');
    }
  }

  /**
   * Create a new tenant
   * @param name The name of the tenant
   * @param refreshToken Whether to refresh the token after creating the tenant
   * @returns Promise with tenant response
   */
  async createTenant(name: string, refreshToken?: boolean): Promise<PassflowTenantResponse> {
    try {
      const response = await this.tenant.createTenant(name);
      if (refreshToken) {
        await this.refreshToken();
      }
      return response;
    } catch (error) {
      this.handleError(error, 'tenant.create', 'Create tenant');
    }
  }

  // Invitation methods delegated to InvitationService
  /**
   * Request an invitation link for a user to join a tenant.
   *
   * @param payload - Invitation request configuration
   * @param payload.email - Email address to send invitation to
   * @param payload.tenantID - Tenant ID for the invitation
   * @param payload.send_to_email - Whether to send email automatically (default: true)
   * @returns Promise with invitation link response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const invitation = await passflow.requestInviteLink({
   *   email: 'newuser@example.com',
   *   tenantID: 'tenant-123',
   *   send_to_email: true
   * });
   * console.log('Invitation link:', invitation.link);
   * ```
   */
  async requestInviteLink(payload: RequestInviteLinkPayload): Promise<InviteLinkResponse> {
    try {
      // default is true
      if (payload.send_to_email === undefined) {
        payload.send_to_email = true;
      }
      return await this.invitationService.requestInviteLink(payload);
    } catch (error) {
      this.handleError(error, 'invitation.request-link', 'Request invite link');
    }
  }

  /**
   * Gets a list of active invitations
   * @param options Optional parameters for filtering and pagination
   * @returns Promise with paginated list of invitations
   */
  async getInvitations(options: {
    tenantID: string;
    groupID?: string;
    skip?: number | string;
    limit?: number | string;
  }): Promise<InvitationsPaginatedList> {
    try {
      return await this.invitationService.getInvitations(options);
    } catch (error) {
      this.handleError(error, 'invitation.list', 'Get invitations');
    }
  }

  /**
   * Delete an invitation by its token.
   *
   * @param token - Invitation token to delete
   * @returns Promise with success response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * await passflow.deleteInvitation('invitation-token-123');
   * console.log('Invitation deleted');
   * ```
   */
  async deleteInvitation(token: string): Promise<PassflowSuccessResponse> {
    try {
      return await this.invitationService.deleteInvitation(token);
    } catch (error) {
      this.handleError(error, 'invitation.delete', 'Delete invitation');
    }
  }

  /**
   * Resend an invitation email.
   *
   * @param token - Invitation token to resend
   * @returns Promise with success response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * await passflow.resendInvitation('invitation-token-123');
   * console.log('Invitation email resent');
   * ```
   */
  async resendInvitation(token: string): Promise<PassflowSuccessResponse> {
    try {
      return await this.invitationService.resendInvitation(token);
    } catch (error) {
      this.handleError(error, 'invitation.resend', 'Resend invitation');
    }
  }

  /**
   * Get invitation details and link by invitation ID.
   *
   * @param invitationID - Invitation ID to retrieve
   * @returns Promise with invitation link response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const invitation = await passflow.getInvitationLink('invitation-123');
   * console.log('Invitation link:', invitation.link);
   * ```
   */
  async getInvitationLink(invitationID: string): Promise<InviteLinkResponse> {
    try {
      return await this.invitationService.getInvitationLink(invitationID);
    } catch (error) {
      this.handleError(error, 'invitation.get-link', 'Get invitation link');
    }
  }

  // Auth redirect helpers
  /**
   * Generate an authentication redirect URL for hosted login.
   *
   * @param options - Redirect URL configuration
   * @param options.url - Optional custom Passflow server URL
   * @param options.redirectUrl - URL to redirect to after authentication
   * @param options.scopes - Optional scopes to request
   * @param options.appId - Optional app ID to use
   * @returns Authentication redirect URL
   *
   * @example
   * ```typescript
   * const authUrl = passflow.authRedirectUrl({
   *   redirectUrl: window.location.origin + '/auth/callback',
   *   scopes: ['id', 'email', 'offline']
   * });
   * console.log('Auth URL:', authUrl);
   * // Use this URL for custom navigation logic
   * ```
   */
  authRedirectUrl(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): string {
    return this.authService.authRedirectUrl(options);
  }

  /**
   * Redirect to the Passflow hosted login page.
   *
   * @param options - Redirect configuration
   * @param options.url - Optional custom Passflow server URL
   * @param options.redirectUrl - URL to redirect to after authentication
   * @param options.scopes - Optional scopes to request
   * @param options.appId - Optional app ID to use
   *
   * @example
   * ```typescript
   * // Redirect to hosted login page
   * passflow.authRedirect({
   *   redirectUrl: window.location.origin + '/auth/callback'
   * });
   * ```
   */
  authRedirect(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): void {
    this.authService.authRedirect(options);
  }

  /**
   * Get the current token delivery mode.
   * Returns the mode determined by the server (json_body, cookie, or mobile).
   *
   * @returns The current token delivery mode
   *
   * @example
   * ```typescript
   * import { TokenDeliveryMode } from '@passflow/core';
   *
   * const mode = passflow.getDeliveryMode();
   * if (mode === TokenDeliveryMode.Cookie) {
   *   console.log('Using cookie-based authentication');
   * } else {
   *   console.log('Using JSON body authentication');
   * }
   * ```
   */
  getDeliveryMode(): import('./token/delivery-manager').TokenDeliveryMode {
    return this.authService['tokenDeliveryManager'].getMode();
  }

  /**
   * Restore and validate session for cookie mode on page load.
   * Only applicable when using cookie-based token delivery.
   * Validates that HttpOnly cookies are still valid with the server.
   *
   * This method is automatically called on SDK initialization for cookie mode,
   * but can be called manually to re-validate the session.
   *
   * @returns Promise resolving to true if session is valid, false otherwise
   *
   * @example
   * ```typescript
   * // Check if session is valid (useful after page reload)
   * const isValid = await passflow.restoreSession();
   * if (isValid) {
   *   console.log('Session restored successfully');
   * } else {
   *   console.log('Session expired, please sign in again');
   * }
   * ```
   */
  async restoreSession(): Promise<boolean> {
    return await this.authService.restoreSession();
  }

  // Two-Factor Authentication methods

  /**
   * Get the current 2FA enrollment status for the authenticated user.
   *
   * @returns Promise with 2FA status including enabled state and policy
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const status = await passflow.getTwoFactorStatus();
   * console.log('2FA enabled:', status.enabled);
   * console.log('Recovery codes remaining:', status.recovery_codes_remaining);
   * ```
   */
  async getTwoFactorStatus(): Promise<TwoFactorStatusResponse> {
    try {
      return await this.twoFactorService.getStatus();
    } catch (error) {
      this.handleError(error, '2fa.status', 'Get 2FA status');
    }
  }

  /**
   * Begin the 2FA setup process for the authenticated user.
   * Returns a secret and QR code to scan with an authenticator app.
   *
   * @returns Promise with setup response containing secret and QR code
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const setup = await passflow.beginTwoFactorSetup();
   * console.log('Scan this QR code:', setup.qr_code);
   * console.log('Or enter this secret:', setup.secret);
   * ```
   */
  async beginTwoFactorSetup(): Promise<TwoFactorSetupResponse> {
    try {
      return await this.twoFactorService.beginSetup();
    } catch (error) {
      this.handleError(error, '2fa.setup.begin', 'Begin 2FA setup');
    }
  }

  /**
   * Confirm 2FA setup by verifying a TOTP code from the authenticator app.
   * Returns recovery codes that MUST be saved by the user.
   *
   * @param code - 6-digit TOTP code from authenticator app
   * @returns Promise with confirmation response including recovery codes
   * @throws {PassflowError} If verification fails
   *
   * @example
   * ```typescript
   * const result = await passflow.confirmTwoFactorSetup('123456');
   * console.log('SAVE THESE RECOVERY CODES:', result.recovery_codes);
   * // Display recovery codes to user for safekeeping
   * ```
   */
  async confirmTwoFactorSetup(code: string): Promise<TwoFactorConfirmResponse> {
    try {
      return await this.twoFactorService.confirmSetup(code);
    } catch (error) {
      this.handleError(error, '2fa.setup.confirm', 'Confirm 2FA setup');
    }
  }

  /**
   * What the sign-in waiting on its second factor can do next. The server decides; read this
   * before asking for a code, and call `requestChallenge` only on `verify`.
   *
   * @returns `verify`: ask for a code. `email_link`: `sendTwoFactorSetupLink`, then the user signs
   * in again after enrolling. `direct`: `beginTwoFactorEnrollment`, `confirmTwoFactorEnrollment`,
   * then `verifyTwoFactor`. `unavailable`: tell the user to contact the administrator.
   * @throws {PassflowError} A 401 means the sign-in is over: sign in again.
   */
  async getTwoFactorEnrollment(): Promise<TwoFactorEnrollment> {
    try {
      return await this.twoFactorService.getEnrollment();
    } catch (error) {
      this.handleError(error, '2fa.enrollment.read', 'Read 2FA enrollment');
    }
  }

  /**
   * Email the user a link to set up 2FA, on a sign-in whose enrollment is `email_link`.
   * The budget is 3 requests in 5 minutes, shared with `requestChallenge`, so limit resends.
   *
   * @throws {PassflowError} 503 `error.2fa.setup_link.send_failed` when the email could not be sent
   */
  async sendTwoFactorSetupLink(): Promise<TwoFactorSetupLinkResponse> {
    try {
      return await this.twoFactorService.sendSetupLink();
    } catch (error) {
      this.handleError(error, '2fa.enrollment.setup-link', 'Send 2FA setup link');
    }
  }

  /**
   * Begin 2FA setup on the pending sign-in, when its enrollment is `direct`.
   * Returns a secret and QR code to scan with an authenticator app.
   *
   * @throws {PassflowError} 403 `error.2fa.enrollment.not_allowed` in any other state
   */
  async beginTwoFactorEnrollment(): Promise<TwoFactorSetupResponse> {
    try {
      return await this.twoFactorService.beginEnrollment();
    } catch (error) {
      this.handleError(error, '2fa.setup.begin', 'Begin 2FA enrollment');
    }
  }

  /**
   * Confirm 2FA setup on the pending sign-in. The sign-in stays pending: show the recovery codes,
   * then `verifyTwoFactor` with the same code finishes it.
   *
   * @param code - TOTP code from the authenticator app
   * @returns Promise with the recovery codes the user must save
   * @throws {PassflowError} 401 `error.api.request.2fa_code.invalid` on a wrong code
   */
  async confirmTwoFactorEnrollment(code: string): Promise<TwoFactorConfirmResponse> {
    try {
      return await this.twoFactorService.confirmEnrollment(code);
    } catch (error) {
      this.handleError(error, '2fa.setup.confirm', 'Confirm 2FA enrollment');
    }
  }

  /**
   * Verify a TOTP code during login when 2FA is required.
   * Completes the authentication process and saves tokens.
   *
   * @param code - 6-digit TOTP code from authenticator app
   * @param options - `trustDevice: true` asks the server to trust this device,
   *   so later sign-ins from it skip the second factor where the app allows it
   * @returns Promise with verification response containing tokens
   * @throws {PassflowError} If verification fails
   *
   * @example
   * ```typescript
   * // After signIn returns requires_2fa: true
   * if (passflow.isTwoFactorVerificationRequired()) {
   *   const response = await passflow.verifyTwoFactor('123456', { trustDevice: true });
   *   console.log('Authentication complete', response.access_token);
   * }
   * ```
   */
  async verifyTwoFactor(code: string, options?: TwoFactorCompletionOptions): Promise<TwoFactorVerifyResponse> {
    try {
      // The service has applied the tokens in the app's delivery mode.
      const response = await this.twoFactorService.verify(code, options);

      this.subscribeStore.notify(PassflowEvent.SignIn, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      this.handleError(error, '2fa.verify', 'Verify 2FA');
    }
  }

  /**
   * Use a recovery code for authentication when TOTP is unavailable.
   * Completes the authentication process and saves tokens.
   *
   * @param code - Recovery code from the list provided during setup
   * @param options - `trustDevice: true` asks the server to trust this device
   * @returns Promise with recovery response containing tokens and remaining codes count
   * @throws {PassflowError} If recovery code is invalid
   *
   * @example
   * ```typescript
   * // After signIn returns requires_2fa: true
   * const result = await passflow.useTwoFactorRecoveryCode('ABCD-1234');
   * console.log('Authenticated with recovery code');
   * console.log(`${result.remaining_recovery_codes} recovery codes remaining`);
   * ```
   */
  async useTwoFactorRecoveryCode(code: string, options?: TwoFactorCompletionOptions): Promise<TwoFactorRecoveryResponse> {
    try {
      // The service has applied the tokens in the app's delivery mode.
      const response = await this.twoFactorService.useRecoveryCode(code, options);

      this.subscribeStore.notify(PassflowEvent.SignIn, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      this.handleError(error, '2fa.recovery.use', 'Use 2FA recovery code');
    }
  }

  /**
   * Disable 2FA for the authenticated user.
   * Requires verification with a current TOTP code.
   *
   * @param code - Current 6-digit TOTP code for verification
   * @returns Promise with success response
   * @throws {PassflowError} If verification fails
   *
   * @example
   * ```typescript
   * await passflow.disableTwoFactor('123456');
   * console.log('2FA disabled successfully');
   * ```
   */
  async disableTwoFactor(code: string): Promise<TwoFactorDisableResponse> {
    try {
      return await this.twoFactorService.disable(code);
    } catch (error) {
      this.handleError(error, '2fa.disable', 'Disable 2FA');
    }
  }

  /**
   * Regenerate recovery codes for the authenticated user.
   * Old recovery codes will be invalidated. Requires verification with a current TOTP code.
   *
   * @param code - Current 6-digit TOTP code for verification
   * @returns Promise with response containing new recovery codes
   * @throws {PassflowError} If verification fails
   *
   * @example
   * ```typescript
   * const result = await passflow.regenerateTwoFactorRecoveryCodes('123456');
   * console.log('New recovery codes:', result.recovery_codes);
   * // Display new recovery codes to user for safekeeping
   * ```
   */
  async regenerateTwoFactorRecoveryCodes(code: string): Promise<TwoFactorRegenerateResponse> {
    try {
      return await this.twoFactorService.regenerateRecoveryCodes(code);
    } catch (error) {
      this.handleError(error, '2fa.recovery.regenerate', 'Regenerate 2FA recovery codes');
    }
  }

  /**
   * List the devices the signed-in user trusted to skip the second factor on
   * this app. The device making the request has `current: true`.
   *
   * @returns Promise with the trusted devices
   * @throws {PassflowError} If the request fails
   *
   * @example
   * ```typescript
   * const devices = await passflow.getTrustedDevices();
   * devices.forEach((d) => console.log(d.user_agent, d.current ? '(this device)' : ''));
   * ```
   */
  async getTrustedDevices(): Promise<TwoFactorTrustedDevice[]> {
    try {
      return await this.twoFactorService.getTrustedDevices();
    } catch (error) {
      this.handleError(error, '2fa.trusted-devices.list', 'Get trusted devices');
    }
  }

  /**
   * Revoke one of the signed-in user's trusted devices. Its next sign-in
   * asks for the second factor again.
   *
   * @param id - The trusted device's `id` from `getTrustedDevices()`
   * @throws {PassflowError} If the request fails, including a 404 for an unknown id
   *
   * @example
   * ```typescript
   * await passflow.revokeTrustedDevice(device.id);
   * ```
   */
  async revokeTrustedDevice(id: string): Promise<void> {
    try {
      await this.twoFactorService.revokeTrustedDevice(id);
    } catch (error) {
      this.handleError(error, '2fa.trusted-devices.revoke', 'Revoke trusted device');
    }
  }

  /**
   * Check if 2FA verification is currently required (local state check).
   * Returns true if user has signed in but needs to complete 2FA verification.
   *
   * @returns True if 2FA verification is pending, false otherwise
   *
   * @example
   * ```typescript
   * if (passflow.isTwoFactorVerificationRequired()) {
   *   // Show 2FA code input UI
   *   console.log('Please enter your 2FA code');
   * }
   * ```
   */
  isTwoFactorVerificationRequired(): boolean {
    return this.twoFactorService.isVerificationRequired();
  }

  /**
   * Get configured TOTP digit count for the current app
   * @returns Number of digits (6 or 8) configured for TOTP codes
   *
   * @example
   * ```typescript
   * const digits = passflow.getTotpDigits();
   * console.log(`TOTP codes should be ${digits} digits`);
   * ```
   */
  getTotpDigits(): 6 | 8 {
    return this.twoFactorService.getTotpDigits();
  }

  // Magic Link 2FA Setup Methods

  /**
   * Validate a magic link token for 2FA setup.
   * Used when a user clicks on an admin-generated magic link to set up 2FA.
   *
   * The magic link creates a scoped session that can ONLY be used for 2FA setup,
   * not for regular authentication.
   *
   * @param token - Magic link token from URL parameter
   * @returns Promise with validation response containing scoped session or error
   *
   * @example
   * ```typescript
   * // On the magic link landing page (e.g., /2fa-setup/:token)
   * const urlToken = extractTokenFromUrl();
   * const result = await passflow.validateTwoFactorSetupMagicLink(urlToken);
   *
   * if (result.success) {
   *   console.log('Magic link validated');
   *   console.log('User ID:', result.userId);
   *   console.log('Session expires in:', result.expiresIn, 'seconds');
   *   // Show 2FA setup form
   * } else {
   *   console.error('Validation failed:', result.error?.message);
   *   // Show error UI
   * }
   * ```
   */
  async validateTwoFactorSetupMagicLink(
    token: string,
  ): Promise<import('./api/model').TwoFactorSetupMagicLinkValidationResponse> {
    return await this.twoFactorService.validateTwoFactorSetupMagicLink(token);
  }

  /**
   * Get the current magic link session (if any).
   * Used by React SDK components to access session data.
   *
   * @returns Active magic link session or null if none/expired
   *
   * @example
   * ```typescript
   * const session = passflow.getMagicLinkSession();
   * if (session) {
   *   console.log('Active session for user:', session.userId);
   *   console.log('Expires at:', new Date(session.expiresAt));
   * }
   * ```
   */
  getMagicLinkSession(): import('./api/model').TwoFactorSetupMagicLinkSession | null {
    return this.twoFactorService.getMagicLinkSession();
  }

  /**
   * Check if a magic link session is currently active.
   *
   * @returns True if magic link session is active and not expired
   *
   * @example
   * ```typescript
   * if (passflow.hasMagicLinkSession()) {
   *   // User can proceed with 2FA setup
   * } else {
   *   // Redirect to error page or request new link
   * }
   * ```
   */
  hasMagicLinkSession(): boolean {
    return this.twoFactorService.hasMagicLinkSession();
  }

  /**
   * Clear the magic link session.
   * Called after successful 2FA setup or on error.
   *
   * @example
   * ```typescript
   * // After 2FA setup is complete
   * passflow.clearMagicLinkSession();
   * // Redirect to sign-in
   * ```
   */
  clearMagicLinkSession(): void {
    this.twoFactorService.clearMagicLinkSession();
  }
}
