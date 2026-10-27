import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import {
  APP_ID_HEADER_KEY,
  AUTHORIZATION_HEADER_KEY,
  DEVICE_ID_HEADER_KEY,
  DEVICE_TYPE_HEADER_KEY,
  PASSFLOW_CLOUD_URL,
  TOKEN_EXPIRY_BUFFER_SECONDS,
} from '../constants';

import { DeviceService } from '../device';
import type { PlatformAdapter } from '../platform';
import { webAdapter } from '../platform';
import { StorageManager } from '../storage';
import { TokenService, isTokenExpired, parseToken } from '../token';
import { TokenDeliveryManager } from '../token/delivery-manager';
import type { UpgradeChallenge } from '../upgrade/challenge';
import { parseUpgradeChallenge } from '../upgrade/challenge';
import { hasUpgradeTransactionMarker } from '../upgrade/markers';

import {
  PassflowAuthorizationResponse,
  PassflowConfig,
  PassflowEndpointPaths,
  PassflowError,
  PassflowResponseError,
  RequestMethod,
  RequestOptions,
  type UpgradeDomain,
  resolveUpgradeDomain,
} from './model';

export enum HttpStatuses {
  badRequest = 400,
  unauthorized = 401,
  tooManyRequests = 429,
  internalServerError = 500,
  success = 200,
  created = 201,
}

// Rate limiting retry configuration
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY_MS = 1000;

/**
 * Reports whether a response is an RFC 9470 step-up challenge rather than a
 * plain authentication failure. Adapts the axios response shape onto the
 * transport-agnostic parser in `../upgrade/challenge`.
 */
const axiosHeaderReader =
  (response: AxiosResponse) =>
  (name: string): string | undefined => {
    const value = response.headers?.[name] ?? response.headers?.[name.toLowerCase()];
    return Array.isArray(value) ? value.join(', ') : (value as string | undefined);
  };

const readUpgradeChallengeFrom = (response: AxiosResponse): UpgradeChallenge | undefined =>
  parseUpgradeChallenge(response.status, axiosHeaderReader(response), response.data);

const isUpgradeChallengeResponse = (response: AxiosResponse): boolean => readUpgradeChallengeFrom(response) !== undefined;

/**
 * Handles a challenge the Passflow instance itself received, resolving with a
 * replayed response once the session has been elevated.
 *
 * Consulted INSIDE the existing error interceptor rather than registered as a
 * later one: axios runs response interceptors FIFO and the handler below
 * converts the `AxiosError` into a `PassflowError`, which has no headers and no
 * config, so anything registered afterwards is structurally too late.
 */
export type AxiosUpgradeHandler = (error: AxiosError, challenge: UpgradeChallenge) => Promise<AxiosResponse>;

export class AxiosClient {
  private instance: AxiosInstance;
  protected storageManager: StorageManager;
  protected deviceService: DeviceService;
  protected tokenDeliveryManager: TokenDeliveryManager;
  private refreshPromise: Promise<AxiosResponse<PassflowAuthorizationResponse>> | null = null;
  private isRefreshing = false;
  private _platform: PlatformAdapter;

  tokenService: TokenService;

  get origin(): string {
    return this._platform.getCurrentUrl()?.origin ?? '';
  }
  url: string;
  appId?: string;

  protected defaultHeaders: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };

  private readonly nonAccessTokenEndpoints = ['/auth/', '/settings', '/settings/'];
  /**
   * Endpoints under `/auth/` that DO need credentials.
   *
   * `'upgrade'` is here because `/auth/upgrade/start` is access-token-gated.
   * Without it the path matches `isNonAuthEndpoint()` and the request
   * interceptor returns before either the cookie-mode branch or the JSON-mode
   * token branch runs: no `Authorization`, no `withCredentials`, no CSRF token,
   * and a prepare round that 401s in every delivery mode.
   */
  private readonly protectedEndpoints = ['logout', 'refresh', 'upgrade'];

  /** Set when a consumer wires the upgrade feature. Absent by default. */
  private upgradeHandler?: AxiosUpgradeHandler;

  /**
   * Passflow's own API as an interception scope, resolved ONCE here from
   * `PassflowConfig.url` so no wrapper or adapter ever derives it. `null` when
   * no `url` was configured — see `resolveUpgradeDomain`.
   */
  readonly upgradeDomain: UpgradeDomain | null;

  constructor(config: PassflowConfig, storageManager?: StorageManager, deviceService?: DeviceService) {
    const { url, appId, keyStoragePrefix } = config;
    this._platform = config.platform ?? webAdapter;

    this.url = url || PASSFLOW_CLOUD_URL;
    this.upgradeDomain = resolveUpgradeDomain(url);

    // Use provided instances or create new ones (backward compatibility)
    this.storageManager =
      storageManager ??
      new StorageManager({
        prefix: keyStoragePrefix ?? '',
      });
    this.deviceService = deviceService ?? new DeviceService(this.storageManager);
    this.tokenService = new TokenService(this.storageManager);
    this.tokenDeliveryManager = new TokenDeliveryManager(this.storageManager);

    if (appId) {
      this.appId = appId;

      this.defaultHeaders = {
        ...this.defaultHeaders,
        [APP_ID_HEADER_KEY]: appId,
      };
    }

    // Add device headers
    const deviceId = this.deviceService.getDeviceId();
    this.defaultHeaders = {
      ...this.defaultHeaders,
      [DEVICE_ID_HEADER_KEY]: deviceId,
      [DEVICE_TYPE_HEADER_KEY]: this._platform.getDeviceType(),
    };

    // Detect cookie capability
    this.detectCookieSupport();

    this.instance = axios.create({
      baseURL: this.url,
      headers: { ...this.defaultHeaders },
    });

    this.instance.interceptors.request.use(async (axiosConfig: InternalAxiosRequestConfig) => {
      // Request to non-access token endpoints
      if (this.isNonAuthEndpoint(axiosConfig.url)) {
        return axiosConfig;
      }

      // Cookie mode handling
      if (this.tokenDeliveryManager.isCookieMode()) {
        // Browser automatically sends HttpOnly cookies
        // Do NOT add Authorization header
        axiosConfig.withCredentials = true;

        // Add CSRF token if available
        const csrfToken = this.storageManager.getCsrfToken();
        if (csrfToken) {
          axiosConfig.headers['X-CSRF-Token'] = csrfToken;
        }

        return axiosConfig;
      }

      // JSON mode: existing token handling
      // Request to refresh token endpoint
      if (axiosConfig.url?.includes('refresh')) {
        if (this.isRefreshing) {
          // Abort duplicate refresh requests
          const controller = new AbortController();
          controller.abort();
          axiosConfig.signal = controller.signal;
          return axiosConfig;
        }
        return axiosConfig;
      }

      // Request to access token endpoints
      const tokens = this.storageManager.getTokens();

      if (tokens?.access_token) {
        const access = parseToken(tokens.access_token);

        // Check if token is expired with buffer
        if (isTokenExpired(access, TOKEN_EXPIRY_BUFFER_SECONDS) && tokens.refresh_token) {
          try {
            // Single-flight pattern: reuse in-flight refresh
            if (this.refreshPromise) {
              const response = await this.refreshPromise;
              // After refresh completes, get new token
              if (response?.data?.access_token) {
                axiosConfig.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${response.data.access_token}`;
              }
              return axiosConfig;
            }

            // Start new refresh using single-flight pattern
            this.refreshPromise = this.refreshTokens();

            try {
              const response = await this.refreshPromise;
              // After refresh completes, get new token
              if (response?.data?.access_token) {
                axiosConfig.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${response.data.access_token}`;
              }
              return axiosConfig;
            } finally {
              this.refreshPromise = null;
            }
          } catch (error) {
            // On failure, clear refresh state immediately so future requests can retry
            this.refreshPromise = null;
            this.isRefreshing = false;
            // Clear tokens on auth failure
            this.storageManager.deleteTokens();
            return Promise.reject(error);
          }
        }

        axiosConfig.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${tokens.access_token}`;

        return axiosConfig;
      }
      return axiosConfig;
    });

    this.instance.interceptors.response.use(
      (response: AxiosResponse) => response,
      async (e: AxiosError) => {
        // Mark the session invalid on a 401 — unless this particular request
        // carries positive evidence that the 401 is part of an elevation.
        //
        // Evidence, both per-request and both necessary:
        //
        //   1. the failed request is one of the upgrade transaction's two rounds
        //      (`/auth/upgrade/start`, or the committing `/auth/refresh`). Those
        //      401s mean "wrong code" or "spent challenge" and carry NO RFC 9470
        //      vocabulary at all, so the response cannot be used to recognise
        //      them. Without this limb a mistyped TOTP digit logs the user out
        //      mid-prompt, which is the defect this feature exists to fix.
        //   2. the response itself carried a parseable challenge, which covers a
        //      challenge arriving outside any elevation.
        //
        // On neither, the 401 invalidates exactly as it always has. That matters
        // as much as the suppression: keying on the ABSENCE of challenge
        // vocabulary would mean an expired or revoked session never invalidates,
        // leaving the user in a broken "authenticated" UI — the mirror image of
        // the same bug. Scoping to the one request that failed also keeps a
        // genuine expiry on an unrelated background request invalidating
        // normally while a prompt is open.
        if (e.response?.status === HttpStatuses.unauthorized && !this.isUpgradeTransactionError(e)) {
          this.tokenDeliveryManager.setSessionInvalid();
        }

        // An elevation seam, consulted here because a later-registered
        // interceptor would only ever see the `PassflowError` below.
        if (e.response && this.upgradeHandler) {
          const challenge = readUpgradeChallengeFrom(e.response);
          if (challenge) {
            try {
              return await this.upgradeHandler(e, challenge);
            } catch (upgradeError) {
              // The core DECLINED to act — `not-a-challenge`, `out-of-scope` or
              // `replay-unsupported` all settle by re-rejecting the error we
              // handed in. Returning that rejection would hand an SDK caller a
              // raw `AxiosError` where every existing consumer pattern-matches
              // on `PassflowError.id`, and it would skip the rate-limit path
              // below as well. The identity comparison is the whole test: the
              // same object back means "not mine", anything else is a genuine
              // step-up outcome and belongs to the caller untouched.
              //
              // Reachable in a configuration, not just in theory: with no `url`
              // configured, domain 1 is `null`, so Passflow's own challenges are
              // all out of scope and every one of them took this path.
              if (upgradeError !== e) {
                throw upgradeError;
              }
            }
          }
        }

        // Handle rate limiting with retry logic
        if (e.response?.status === HttpStatuses.tooManyRequests) {
          return await this.handleRateLimitError(e);
        }
        return this.handleAxiosError(e);
      },
    );
  }

  /**
   * The `setSessionInvalid()` suppression predicate, keyed on the request that
   * failed and on the response that came back — never on "this response does not
   * speak upgrade vocabulary", which is unsound in both directions.
   */
  private isUpgradeTransactionError(e: AxiosError): boolean {
    return hasUpgradeTransactionMarker(e.config) || (e.response !== undefined && isUpgradeChallengeResponse(e.response));
  }

  /**
   * Installs (or clears) the handler consulted when a response carries an
   * upgrade challenge. Passing `undefined` detaches it.
   */
  setUpgradeInterceptor(handler: AxiosUpgradeHandler | undefined): void {
    this.upgradeHandler = handler;
  }

  /**
   * Re-issues a request after an elevation. Exposed for the upgrade handler,
   * which owns the replay-once decision; the marker preventing a second
   * elevation travels on the config the caller passes in.
   */
  replay<T = unknown>(config: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.instance.request<T>(config);
  }

  private isProtectedEndpoint(url?: string): boolean {
    return this.protectedEndpoints.some((endpoint) => url?.includes(endpoint));
  }

  private isNonAuthEndpoint(url?: string): boolean {
    return this.nonAccessTokenEndpoints.some((endpoint) => url?.includes(endpoint)) && !this.isProtectedEndpoint(url);
  }

  /**
   * Detect if cookies are supported/enabled in the browser.
   * If cookie mode is already active (restored from storage) and cookies are not
   * supported, throws immediately to prevent silent misconfiguration.
   *
   * Note: If cookie mode is set later (e.g., server responds with token_delivery=cookie
   * on a non-cookie platform), this check will not catch it. The server should not
   * configure cookie mode for platforms where cookiesSupported() returns false.
   */
  private detectCookieSupport(): void {
    const supported = this._platform.cookiesSupported();

    // Enforce immediately if cookie mode was persisted from a previous session.
    if (!supported && this.tokenDeliveryManager.isCookieMode()) {
      throw new Error(
        'Passflow SDK: Cookie delivery mode is configured but cookies are not ' +
          'supported in this environment. Use a platform adapter that supports ' +
          'cookies or configure the server to use JSON token delivery.',
      );
    }
  }

  /**
   * Refresh tokens using single-flight pattern to prevent race conditions
   * Supports both cookie mode and JSON mode
   */
  private async refreshTokens(): Promise<AxiosResponse<PassflowAuthorizationResponse>> {
    if (this.tokenDeliveryManager.isCookieMode()) {
      // Cookie mode: call /auth/refresh with credentials:'include'
      // Server reads refresh token from HttpOnly cookie
      const response = await this.instance.post<PassflowAuthorizationResponse>(
        PassflowEndpointPaths.refresh,
        {}, // Empty body
        { withCredentials: true },
      );

      // Mark session as valid after successful refresh
      this.tokenDeliveryManager.setSessionValid();

      // Extract CSRF token if present
      if (response.data.csrf_token) {
        this.storageManager.setCsrfToken(response.data.csrf_token);
      }

      // Save ID token if present (other tokens are in HttpOnly cookies)
      if (response.data.id_token) {
        this.storageManager.setIdToken(response.data.id_token);
      }

      return response;
    } else {
      // JSON mode: existing refresh logic
      const tokens = this.storageManager.getTokens();
      const scopes = this.storageManager.getScopes();

      if (!tokens?.refresh_token) {
        throw new Error('No refresh token available');
      }

      this.isRefreshing = true;
      const payload = {
        refresh_token: tokens.refresh_token,
        scopes,
      };

      const response = await this.instance.post<PassflowAuthorizationResponse>(PassflowEndpointPaths.refresh, payload, {
        headers: {
          [AUTHORIZATION_HEADER_KEY]: `Bearer ${tokens.refresh_token}`,
        },
      });

      if (response.data) {
        // Update storage BEFORE processing queued requests
        this.storageManager.saveTokens(response.data);
      }

      this.isRefreshing = false;

      return response;
    }
  }

  private async handleRateLimitError(e: AxiosError): Promise<AxiosResponse> {
    const config = e.config;
    if (!config) {
      return Promise.reject(e);
    }

    // Only retry idempotent requests to avoid duplicate operations
    const method = config.method?.toUpperCase();
    const isIdempotent = ['GET', 'HEAD', 'OPTIONS'].includes(method || '');

    if (!isIdempotent) {
      // Don't retry non-idempotent requests - could cause duplicates
      return Promise.reject(e);
    }

    // Track retry attempts on the config object
    const retryCount = (config as AxiosRequestConfig & { _retryCount?: number })._retryCount || 0;

    if (retryCount >= MAX_RETRIES) {
      // Max retries exceeded, reject with original error
      return Promise.reject(e);
    }

    // Calculate delay with exponential backoff
    let delayMs = INITIAL_RETRY_DELAY_MS * Math.pow(2, retryCount);

    // Check for Retry-After header (can be in seconds or HTTP date)
    const retryAfter = e.response?.headers?.['retry-after'];
    if (retryAfter) {
      const retryAfterNum = Number.parseInt(retryAfter, 10);
      if (!Number.isNaN(retryAfterNum)) {
        // Retry-After is in seconds
        delayMs = retryAfterNum * 1000;
      } else {
        // Retry-After is an HTTP date
        const retryDate = new Date(retryAfter);
        if (!Number.isNaN(retryDate.getTime())) {
          delayMs = Math.max(0, retryDate.getTime() - Date.now());
        }
      }
    }

    // Wait for the calculated delay
    await new Promise((resolve) => setTimeout(resolve, delayMs));

    // Increment retry count and retry the request
    (config as AxiosRequestConfig & { _retryCount?: number })._retryCount = retryCount + 1;
    return this.instance.request(config);
  }

  // eslint-disable-next-line complexity
  // biome-ignore lint/suspicious/useAwait: <explanation>
  private async handleAxiosError(e: AxiosError): Promise<unknown> {
    // Handle network
    if (!e.response) {
      return Promise.reject(e);
    }

    const status = e.response.status as HttpStatuses;
    const errorData = e.response.data as Record<string, unknown>;

    // If we have a response with error data in Passflow format
    if ('error' in errorData && typeof errorData.error === 'object' && errorData.error !== null) {
      const { error } = errorData as PassflowResponseError;

      return Promise.reject(new PassflowError(error));
    }

    // For non-Passflow format errors, create a generic PassflowError
    return Promise.reject(
      new PassflowError({
        id: `error.http.${status}`,
        message: e.message || 'An error occurred',
        status: status,
        location: e.config?.url || 'unknown',
        time: new Date().toISOString(),
      }),
    );
  }

  private async send<T, D>(method: RequestMethod, path: string, options?: RequestOptions<D>): Promise<T> {
    const response = await this.instance.request<T>({
      method,
      url: path,
      ...options,
    });
    return response.data;
  }

  get<T>(path: string, config?: AxiosRequestConfig): Promise<T> {
    return this.send(RequestMethod.GET, path, config);
  }

  post<T, D>(path: string, data?: D, config?: AxiosRequestConfig): Promise<T> {
    return this.send(RequestMethod.POST, path, { data, ...config });
  }

  put<T, D>(path: string, data?: D, config?: AxiosRequestConfig): Promise<T> {
    return this.send(RequestMethod.PUT, path, { data, ...config });
  }

  patch<T, D>(path: string, data?: D, config?: AxiosRequestConfig): Promise<T> {
    return this.send(RequestMethod.PATCH, path, { data, ...config });
  }

  delete<T>(path: string, config?: AxiosRequestConfig): Promise<T> {
    return this.send(RequestMethod.DELETE, path, config);
  }

  /**
   * Update the appId and propagate it to axios headers.
   * This ensures that the APP_ID_HEADER_KEY is updated in all future requests.
   *
   * @param appId - The new application ID to set
   */
  setAppId(appId: string): void {
    this.appId = appId;

    // Update default headers
    this.defaultHeaders = {
      ...this.defaultHeaders,
      [APP_ID_HEADER_KEY]: appId,
    };

    // Update axios instance headers
    this.instance.defaults.headers.common[APP_ID_HEADER_KEY] = appId;
  }
}
