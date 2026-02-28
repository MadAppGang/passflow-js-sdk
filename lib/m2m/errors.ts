/**
 * M2M Authentication Error Classes
 *
 * Custom error classes for M2M authentication failures with
 * OAuth 2.0 compliant error codes and detailed information.
 */

import type { M2MErrorCode, M2MRateLimitInfo } from './types';

/**
 * M2M Authentication Error
 *
 * Thrown when M2M authentication fails. Contains OAuth 2.0 compliant
 * error codes and additional debugging information.
 *
 * @example
 * ```typescript
 * try {
 *   const token = await m2m.getToken();
 * } catch (error) {
 *   if (error instanceof M2MError) {
 *     console.error(`Error: ${error.code} - ${error.message}`);
 *     if (error.code === 'rate_limit_exceeded') {
 *       console.log(`Retry after: ${error.rateLimitInfo?.reset}`);
 *     }
 *   }
 * }
 * ```
 */
export class M2MError extends Error {
  /** OAuth 2.0 error code */
  readonly code: M2MErrorCode;

  /** HTTP status code from the response */
  readonly status: number;

  /** URI with more information about the error (if provided) */
  readonly errorUri?: string;

  /** Rate limit information (if rate limited) */
  readonly rateLimitInfo?: M2MRateLimitInfo;

  /** Response headers from the server */
  readonly headers?: Record<string, string>;

  /** Original error (if this wraps another error) */
  readonly cause?: Error;

  /** Timestamp when the error occurred */
  readonly timestamp: string;

  constructor(options: {
    code: M2MErrorCode;
    message: string;
    status?: number;
    errorUri?: string;
    rateLimitInfo?: M2MRateLimitInfo;
    headers?: Record<string, string>;
    cause?: Error;
  }) {
    super(options.message);
    this.name = 'M2MError';
    this.code = options.code;
    this.status = options.status ?? 400;
    this.errorUri = options.errorUri;
    this.rateLimitInfo = options.rateLimitInfo;
    this.headers = options.headers;
    this.cause = options.cause;
    this.timestamp = new Date().toISOString();

    // Maintains proper stack trace for where error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, M2MError);
    }
  }

  /**
   * Create an M2MError from an OAuth 2.0 error response
   */
  static fromOAuthError(
    errorResponse: {
      error: M2MErrorCode;
      error_description?: string;
      error_uri?: string;
    },
    status: number,
    headers?: Record<string, string>,
  ): M2MError {
    const rateLimitInfo = headers ? M2MError.parseRateLimitHeaders(headers) : undefined;

    return new M2MError({
      code: errorResponse.error,
      message: errorResponse.error_description ?? M2MError.getDefaultMessage(errorResponse.error),
      status,
      errorUri: errorResponse.error_uri,
      rateLimitInfo,
      headers,
    });
  }

  /**
   * Create an M2MError from a network or other error
   */
  static fromError(error: Error, code: M2MErrorCode = 'server_error'): M2MError {
    return new M2MError({
      code,
      message: error.message || 'An unexpected error occurred',
      status: 500,
      cause: error,
    });
  }

  /**
   * Parse rate limit headers from response
   */
  static parseRateLimitHeaders(headers: Record<string, string>): M2MRateLimitInfo | undefined {
    const limit = headers['x-ratelimit-limit'];
    const remaining = headers['x-ratelimit-remaining'];
    const reset = headers['x-ratelimit-reset'] || headers['retry-after'];

    if (limit && remaining && reset) {
      return {
        limit: parseInt(limit, 10),
        remaining: parseInt(remaining, 10),
        reset: parseInt(reset, 10),
      };
    }

    return undefined;
  }

  /**
   * Get default error message for an error code
   */
  static getDefaultMessage(code: M2MErrorCode): string {
    const messages: Record<M2MErrorCode, string> = {
      invalid_request: 'The request is missing a required parameter or is otherwise malformed.',
      invalid_client: 'Client authentication failed. Verify your client credentials.',
      invalid_grant: 'The provided authorization grant is invalid or expired.',
      invalid_scope: 'The requested scope is invalid, unknown, or exceeds the allowed scopes.',
      unauthorized_client: 'The client is not authorized to use this grant type.',
      unsupported_grant_type: 'The authorization grant type is not supported.',
      rate_limit_exceeded: 'Too many requests. Please retry after the rate limit window resets.',
      server_error: 'The authorization server encountered an unexpected error.',
      temporarily_unavailable: 'The authorization server is temporarily unavailable. Please try again later.',
    };

    return messages[code] || 'An unknown error occurred.';
  }

  /**
   * Check if the error is retryable
   */
  isRetryable(): boolean {
    return (
      this.code === 'server_error' ||
      this.code === 'temporarily_unavailable' ||
      this.code === 'rate_limit_exceeded' ||
      this.status >= 500
    );
  }

  /**
   * Get suggested wait time before retry (in milliseconds)
   */
  getRetryAfter(): number {
    if (this.rateLimitInfo?.reset) {
      const now = Math.floor(Date.now() / 1000);
      const waitSeconds = this.rateLimitInfo.reset - now;
      return Math.max(waitSeconds * 1000, 1000);
    }

    // Default to 1 second for server errors
    return 1000;
  }

  /**
   * Convert to JSON-serializable object
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      status: this.status,
      errorUri: this.errorUri,
      rateLimitInfo: this.rateLimitInfo,
      timestamp: this.timestamp,
    };
  }

  /**
   * Create a human-readable string representation
   */
  toString(): string {
    let str = `M2MError [${this.code}]: ${this.message}`;
    if (this.status) {
      str += ` (HTTP ${this.status})`;
    }
    return str;
  }
}

/**
 * Network error (connection failed, timeout, etc.)
 */
export class M2MNetworkError extends M2MError {
  constructor(message: string, cause?: Error) {
    super({
      code: 'temporarily_unavailable',
      message,
      status: 0,
      cause,
    });
    this.name = 'M2MNetworkError';
  }
}

/**
 * Token parsing error (invalid JWT format)
 */
export class M2MTokenParseError extends M2MError {
  constructor(message: string, cause?: Error) {
    super({
      code: 'invalid_request',
      message,
      status: 400,
      cause,
    });
    this.name = 'M2MTokenParseError';
  }
}

/**
 * Configuration error (missing or invalid config)
 */
export class M2MConfigError extends M2MError {
  constructor(message: string) {
    super({
      code: 'invalid_request',
      message,
      status: 400,
    });
    this.name = 'M2MConfigError';
  }
}
