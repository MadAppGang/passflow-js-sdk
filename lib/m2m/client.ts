/**
 * M2M (Machine-to-Machine) Authentication Client
 *
 * OAuth 2.0 Client Credentials Grant implementation for server-to-server
 * authentication without user involvement.
 *
 * @example
 * ```typescript
 * const m2m = new M2MClient({
 *   url: 'https://auth.yourapp.com',
 *   clientId: 'your-client-id',
 *   clientSecret: 'your-client-secret',
 *   scopes: ['users:read', 'orders:write'],
 * });
 *
 * const token = await m2m.getToken();
 * ```
 */

import { M2MConfigError, M2MError, M2MNetworkError, M2MTokenParseError } from './errors';
import type {
  M2MClientConfig,
  M2MErrorCode,
  M2MTokenCache,
  M2MTokenClaims,
  M2MTokenRequestOptions,
  M2MTokenRequestPayload,
  M2MTokenResponse,
  RetryStrategy,
} from './types';
import { M2M_DEFAULTS } from './types';

/**
 * Default in-memory token cache
 */
class InMemoryCache implements M2MTokenCache {
  private cache: Map<string, { token: M2MTokenResponse; expiresAt: number }> = new Map();

  get(key: string): Promise<M2MTokenResponse | null> {
    const entry = this.cache.get(key);
    if (!entry) return Promise.resolve(null);

    // Check if expired
    if (Date.now() >= entry.expiresAt) {
      this.cache.delete(key);
      return Promise.resolve(null);
    }

    return Promise.resolve(entry.token);
  }

  set(key: string, token: M2MTokenResponse, ttl: number): Promise<void> {
    this.cache.set(key, {
      token,
      expiresAt: Date.now() + ttl * 1000,
    });
    return Promise.resolve();
  }

  delete(key: string): Promise<void> {
    this.cache.delete(key);
    return Promise.resolve();
  }
}

/**
 * Default retry strategy with exponential backoff
 */
const defaultRetryStrategy: RetryStrategy = {
  shouldRetry(error: { code: M2MErrorCode; status?: number }, attempt: number): boolean {
    // Don't retry after max attempts
    if (attempt >= 3) return false;

    // Retry on server errors and rate limits
    return (
      error.code === 'server_error' ||
      error.code === 'temporarily_unavailable' ||
      error.code === 'rate_limit_exceeded' ||
      (error.status !== undefined && error.status >= 500)
    );
  },
  getDelay(attempt: number): number {
    // Exponential backoff: 1s, 2s, 4s
    return Math.pow(2, attempt - 1) * 1000;
  },
};

/**
 * M2M Authentication Client
 *
 * Implements OAuth 2.0 Client Credentials Grant for machine-to-machine
 * authentication. Provides automatic token caching, refresh, and retry logic.
 */
export class M2MClient {
  private readonly config: Required<
    Pick<M2MClientConfig, 'url' | 'clientId' | 'clientSecret' | 'timeout' | 'retries' | 'retryDelay' | 'refreshThreshold'>
  > &
    Pick<
      M2MClientConfig,
      'scopes' | 'audience' | 'autoRefresh' | 'retryStrategy' | 'cache' | 'onTokenRequest' | 'onTokenResponse' | 'onError'
    >;

  private readonly cache: M2MTokenCache;
  private readonly retryStrategy: RetryStrategy;
  private readonly tokenEndpoint: string;

  /**
   * Create a new M2M client
   *
   * @param config - Client configuration
   * @throws {M2MConfigError} If required configuration is missing
   *
   * @example
   * ```typescript
   * const m2m = new M2MClient({
   *   url: 'https://auth.yourapp.com',
   *   clientId: 'your-client-id',
   *   clientSecret: 'your-client-secret',
   * });
   * ```
   */
  constructor(config: M2MClientConfig) {
    // Validate required config
    if (!config.url) {
      throw new M2MConfigError('M2M client requires a URL');
    }
    if (!config.clientId) {
      throw new M2MConfigError('M2M client requires a clientId');
    }
    if (!config.clientSecret) {
      throw new M2MConfigError('M2M client requires a clientSecret');
    }

    // Normalize URL (remove trailing slash)
    const url = config.url.replace(/\/$/, '');

    this.config = {
      url,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: config.scopes,
      audience: config.audience,
      autoRefresh: config.autoRefresh ?? false,
      refreshThreshold: config.refreshThreshold ?? M2M_DEFAULTS.REFRESH_THRESHOLD,
      timeout: config.timeout ?? M2M_DEFAULTS.TIMEOUT,
      retries: config.retries ?? M2M_DEFAULTS.RETRIES,
      retryDelay: config.retryDelay ?? M2M_DEFAULTS.RETRY_DELAY,
      retryStrategy: config.retryStrategy,
      cache: config.cache,
      onTokenRequest: config.onTokenRequest,
      onTokenResponse: config.onTokenResponse,
      onError: config.onError,
    };

    this.cache = config.cache ?? new InMemoryCache();
    this.retryStrategy = config.retryStrategy ?? defaultRetryStrategy;
    this.tokenEndpoint = `${url}${M2M_DEFAULTS.TOKEN_ENDPOINT}`;
  }

  /**
   * Get the cache key for this client
   */
  private getCacheKey(scopes?: string[], audience?: string[]): string {
    const scopeKey = scopes?.sort().join(',') || '';
    const audienceKey = audience?.sort().join(',') || '';
    return `m2m:${this.config.clientId}:${scopeKey}:${audienceKey}`;
  }

  /**
   * Request an access token from the authorization server
   *
   * @param options - Optional request overrides
   * @returns Token response
   * @throws {M2MError} On authentication failure
   *
   * @example
   * ```typescript
   * // Basic usage
   * const token = await m2m.getToken();
   *
   * // With options
   * const token = await m2m.getToken({
   *   scopes: ['users:read'],
   *   forceRefresh: true,
   * });
   * ```
   */
  async getToken(options?: M2MTokenRequestOptions): Promise<M2MTokenResponse> {
    const scopes = options?.scopes ?? this.config.scopes;
    const audience = options?.audience ?? this.config.audience;
    const cacheKey = this.getCacheKey(scopes, audience);

    // Check cache first (unless forced refresh)
    if (!options?.forceRefresh) {
      const cached = await this.cache.get(cacheKey);
      if (cached && !this.isTokenExpired(cached)) {
        return cached;
      }
    }

    // Request new token
    return this.requestToken(scopes, audience, cacheKey);
  }

  /**
   * Get a valid token, automatically refreshing if needed
   *
   * When autoRefresh is enabled, this will proactively refresh tokens
   * that are about to expire (within refreshThreshold seconds).
   *
   * @returns Valid token response
   * @throws {M2MError} On authentication failure
   *
   * @example
   * ```typescript
   * // Always returns a valid, non-expired token
   * const token = await m2m.getValidToken();
   * ```
   */
  async getValidToken(): Promise<M2MTokenResponse> {
    const scopes = this.config.scopes;
    const audience = this.config.audience;
    const cacheKey = this.getCacheKey(scopes, audience);

    // Check cache
    const cached = await this.cache.get(cacheKey);

    if (cached) {
      // If auto-refresh is enabled and token is about to expire, refresh it
      if (this.config.autoRefresh && this.isTokenExpired(cached, this.config.refreshThreshold)) {
        return this.requestToken(scopes, audience, cacheKey);
      }

      // If token is not expired, return it
      if (!this.isTokenExpired(cached)) {
        return cached;
      }
    }

    // Request new token
    return this.requestToken(scopes, audience, cacheKey);
  }

  /**
   * Request a new token from the authorization server
   */
  private async requestToken(scopes?: string[], audience?: string[], cacheKey?: string): Promise<M2MTokenResponse> {
    // Build request payload
    const payload: M2MTokenRequestPayload = {
      grant_type: 'client_credentials',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    };

    if (scopes && scopes.length > 0) {
      payload.scope = scopes.join(' ');
    }

    if (audience && audience.length > 0) {
      payload.audience = audience.join(' ');
    }

    // Notify callback
    if (this.config.onTokenRequest) {
      this.config.onTokenRequest({
        clientId: this.config.clientId,
        scopes: scopes ?? [],
        audience: audience ?? [],
        timestamp: new Date().toISOString(),
      });
    }

    // Execute request with retries
    const token = await this.executeWithRetry(() => this.doTokenRequest(payload));

    // Add issued_at timestamp
    token.issued_at = Math.floor(Date.now() / 1000);

    // Cache the token
    if (cacheKey) {
      await this.cache.set(cacheKey, token, token.expires_in);
    }

    // Notify callback
    if (this.config.onTokenResponse) {
      this.config.onTokenResponse(token);
    }

    return token;
  }

  /**
   * Execute the actual HTTP request to the token endpoint
   */
  private async doTokenRequest(payload: M2MTokenRequestPayload): Promise<M2MTokenResponse> {
    // Build form-encoded body
    const body = new URLSearchParams();
    body.append('grant_type', payload.grant_type);
    body.append('client_id', payload.client_id);
    body.append('client_secret', payload.client_secret);
    if (payload.scope) {
      body.append('scope', payload.scope);
    }
    if (payload.audience) {
      body.append('audience', payload.audience);
    }

    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(this.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': M2M_DEFAULTS.CONTENT_TYPE,
          Accept: 'application/json',
        },
        body: body.toString(),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Parse response headers
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });

      // Parse response body
      const data = await response.json();

      // Handle error response
      if (!response.ok) {
        const error = M2MError.fromOAuthError(
          {
            error: data.error || 'server_error',
            error_description: data.error_description || data.message,
            error_uri: data.error_uri,
          },
          response.status,
          headers,
        );

        if (this.config.onError) {
          this.config.onError({
            error: error.code,
            error_description: error.message,
          });
        }

        throw error;
      }

      return data as M2MTokenResponse;
    } catch (error) {
      clearTimeout(timeoutId);

      // Handle abort (timeout)
      if (error instanceof Error && error.name === 'AbortError') {
        throw new M2MNetworkError(`Request timed out after ${this.config.timeout}ms`);
      }

      // Handle network errors
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new M2MNetworkError(`Network error: ${error.message}`, error);
      }

      // Re-throw M2M errors
      if (error instanceof M2MError) {
        throw error;
      }

      // Wrap unknown errors
      throw M2MError.fromError(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Execute a request with retry logic
   */
  private async executeWithRetry<T>(fn: () => Promise<T>): Promise<T> {
    let lastError: M2MError | undefined;

    for (let attempt = 1; attempt <= this.config.retries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        if (!(error instanceof M2MError)) {
          throw error;
        }

        lastError = error;

        // Check if we should retry
        if (
          attempt < this.config.retries &&
          this.retryStrategy.shouldRetry({ code: error.code, status: error.status }, attempt)
        ) {
          const delay = this.retryStrategy.getDelay(attempt);
          await this.sleep(delay);
          continue;
        }

        throw error;
      }
    }

    throw lastError ?? new M2MError({ code: 'server_error', message: 'Request failed after retries' });
  }

  /**
   * Sleep for a given duration
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Get the currently cached token without making a request
   *
   * @returns Cached token or null if not cached
   *
   * @example
   * ```typescript
   * const token = m2m.getCachedToken();
   * if (token && !m2m.isTokenExpired(token)) {
   *   console.log('Using cached token');
   * }
   * ```
   */
  getCachedToken(): M2MTokenResponse | null {
    // Note: This is synchronous for the default in-memory cache
    // For async caches, use getToken() instead
    const cache = this.cache as InMemoryCache;
    if ('cache' in cache) {
      const cacheKey = this.getCacheKey(this.config.scopes, this.config.audience);
      const entry = (cache as unknown as { cache: Map<string, { token: M2MTokenResponse; expiresAt: number }> }).cache.get(
        cacheKey,
      );
      return entry?.token ?? null;
    }
    return null;
  }

  /**
   * Check if a token is expired or about to expire
   *
   * @param token - Token to check (uses issued_at + expires_in if available)
   * @param threshold - Seconds before actual expiry to consider expired (default: 0)
   * @returns true if expired or about to expire
   *
   * @example
   * ```typescript
   * if (m2m.isTokenExpired(token)) {
   *   console.log('Token is expired');
   * }
   *
   * // Check if expiring within 5 minutes
   * if (m2m.isTokenExpired(token, 300)) {
   *   console.log('Token expires soon');
   * }
   * ```
   */
  isTokenExpired(token?: M2MTokenResponse | null, threshold = 0): boolean {
    if (!token) return true;

    const now = Math.floor(Date.now() / 1000);
    const issuedAt = token.issued_at ?? now - token.expires_in;
    const expiresAt = issuedAt + token.expires_in;

    return now >= expiresAt - threshold;
  }

  /**
   * Parse token claims from a JWT access token
   *
   * @param token - JWT access token string
   * @returns Decoded token claims
   * @throws {M2MTokenParseError} If token format is invalid
   *
   * @example
   * ```typescript
   * const token = await m2m.getToken();
   * const claims = m2m.parseToken(token.access_token);
   * console.log('Client ID:', claims.client_id);
   * console.log('Scopes:', claims.scopes);
   * ```
   */
  parseToken(token: string): M2MTokenClaims {
    try {
      // JWT format: header.payload.signature
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new M2MTokenParseError('Invalid JWT format: expected 3 parts');
      }

      // Decode the payload (second part)
      const payload = parts[1];
      if (!payload) {
        throw new M2MTokenParseError('Invalid JWT format: missing payload');
      }
      const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
      const claims = JSON.parse(decoded);

      // Ensure scopes is an array
      if (claims.scopes && typeof claims.scopes === 'string') {
        claims.scopes = claims.scopes.split(' ');
      } else if (!claims.scopes) {
        claims.scopes = [];
      }

      return claims as M2MTokenClaims;
    } catch (error) {
      if (error instanceof M2MTokenParseError) {
        throw error;
      }
      throw new M2MTokenParseError(`Failed to parse token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Clear the token cache, forcing a new request on next getToken()
   *
   * @example
   * ```typescript
   * m2m.clearCache();
   * // Next getToken() will request a new token
   * const token = await m2m.getToken();
   * ```
   */
  clearCache(): void {
    const cacheKey = this.getCacheKey(this.config.scopes, this.config.audience);
    this.cache.delete(cacheKey);
  }

  /**
   * Revoke the current token
   *
   * Note: Requires the server to support token revocation (RFC 7009).
   * Not all Passflow deployments may support this endpoint.
   *
   * @throws {M2MError} If revocation fails
   *
   * @example
   * ```typescript
   * await m2m.revokeToken();
   * console.log('Token revoked');
   * ```
   */
  async revokeToken(): Promise<void> {
    const cached = this.getCachedToken();
    if (!cached) {
      return; // No token to revoke
    }

    const revokeEndpoint = `${this.config.url}/oauth2/revoke`;

    const body = new URLSearchParams();
    body.append('token', cached.access_token);
    body.append('client_id', this.config.clientId);
    body.append('client_secret', this.config.clientSecret);

    try {
      const response = await fetch(revokeEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': M2M_DEFAULTS.CONTENT_TYPE,
        },
        body: body.toString(),
      });

      // RFC 7009: Server should return 200 even if token was already revoked
      if (!response.ok && response.status !== 200) {
        const data = await response.json().catch(() => ({}));
        throw M2MError.fromOAuthError(
          {
            error: data.error || 'server_error',
            error_description: data.error_description || 'Token revocation failed',
          },
          response.status,
        );
      }

      // Clear cache
      this.clearCache();
    } catch (error) {
      if (error instanceof M2MError) {
        throw error;
      }
      throw M2MError.fromError(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Get the configured URL
   */
  get url(): string {
    return this.config.url;
  }

  /**
   * Get the configured client ID
   */
  get clientId(): string {
    return this.config.clientId;
  }

  /**
   * Get the configured scopes
   */
  get scopes(): string[] | undefined {
    return this.config.scopes;
  }

  /**
   * Get the configured audience
   */
  get audience(): string[] | undefined {
    return this.config.audience;
  }
}
