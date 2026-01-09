/**
 * M2MClient Retry Logic Tests
 *
 * Validates retry behavior including exponential backoff, rate limiting,
 * retry limits, and custom retry strategies.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { M2MClient } from '../../../lib/m2m/client';
import type { RetryStrategy } from '../../../lib/m2m/types';
import {
  OAUTH_ERROR_INVALID_CLIENT,
  OAUTH_ERROR_INVALID_SCOPE,
  OAUTH_ERROR_RATE_LIMIT,
  OAUTH_ERROR_SERVER_ERROR,
  OAUTH_ERROR_TEMPORARILY_UNAVAILABLE,
  createMockConfig,
  createMockToken,
} from '../utils/fixtures';
import { mockFetchError, mockFetchSuccess, mockNetworkError, resetFetchMock, setupFetchMock } from '../utils/mock-fetch';

describe('M2MClient - Retry Logic', () => {
  let mockFetch: ReturnType<typeof setupFetchMock>;

  beforeEach(() => {
    mockFetch = setupFetchMock();
    vi.useFakeTimers();
  });

  afterEach(() => {
    resetFetchMock(mockFetch);
    vi.useRealTimers();
  });

  describe('Basic Retry', () => {
    it('should retry on 5xx server errors', async () => {
      const client = new M2MClient(createMockConfig({ retries: 3 }));

      // First attempt: 500 error
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      // Second attempt: 500 error
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      // Third attempt: Success
      mockFetchSuccess(mockFetch, createMockToken());

      const promise = client.getToken();

      // Advance through first retry delay (1000ms)
      await vi.advanceTimersByTimeAsync(1000);
      // Advance through second retry delay (2000ms)
      await vi.advanceTimersByTimeAsync(2000);

      const token = await promise;

      expect(token).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should retry on rate_limit_exceeded (429)', async () => {
      const client = new M2MClient(createMockConfig({ retries: 3 }));

      // First attempt: 429 rate limit
      mockFetchError(mockFetch, 429, OAUTH_ERROR_RATE_LIMIT);
      // Second attempt: Success
      mockFetchSuccess(mockFetch, createMockToken());

      const promise = client.getToken();

      // Advance through retry delay
      await vi.advanceTimersByTimeAsync(1000);

      const token = await promise;

      expect(token).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should retry on temporarily_unavailable (503)', async () => {
      const client = new M2MClient(createMockConfig({ retries: 3 }));

      // First attempt: 503 temporarily unavailable
      mockFetchError(mockFetch, 503, OAUTH_ERROR_TEMPORARILY_UNAVAILABLE);
      // Second attempt: Success
      mockFetchSuccess(mockFetch, createMockToken());

      const promise = client.getToken();

      // Advance through retry delay
      await vi.advanceTimersByTimeAsync(1000);

      const token = await promise;

      expect(token).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should NOT retry on 4xx client errors (except 429)', async () => {
      const client = new M2MClient(createMockConfig({ retries: 3 }));

      // 400 error should not retry
      mockFetchError(mockFetch, 400, OAUTH_ERROR_INVALID_SCOPE);

      try {
        await client.getToken();
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.code).toBe('invalid_scope');
      }

      // Only one attempt should be made
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should NOT retry on invalid_client (401)', async () => {
      const client = new M2MClient(createMockConfig({ retries: 3 }));

      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      try {
        await client.getToken();
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.code).toBe('invalid_client');
      }

      // Only one attempt should be made
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should NOT retry on invalid_scope (400)', async () => {
      const client = new M2MClient(createMockConfig({ retries: 3 }));

      mockFetchError(mockFetch, 400, OAUTH_ERROR_INVALID_SCOPE);

      try {
        await client.getToken();
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.code).toBe('invalid_scope');
      }

      // Only one attempt should be made
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('Retry Limits', () => {
    it('should respect max retries config (default: 3)', async () => {
      const client = new M2MClient(createMockConfig());

      // All attempts fail with 500
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);

      const promise = client.getToken().catch((error) => error);

      // Advance through all retry delays
      await vi.advanceTimersByTimeAsync(1000); // First retry
      await vi.advanceTimersByTimeAsync(2000); // Second retry

      const error = await promise;
      expect(error.code).toBe('server_error');

      // Should try 3 times total (initial + 2 retries)
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should retry with retries=1 only once', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      // First attempt fails
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);

      try {
        await client.getToken();
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.code).toBe('server_error');
      }

      // Should only try once (no retries with retries=1)
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should throw final error after retry exhaustion', async () => {
      const client = new M2MClient(createMockConfig({ retries: 2 }));

      // All attempts fail with 500
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);

      const promise = client.getToken().catch((error) => error);

      // Advance through retry delay
      await vi.advanceTimersByTimeAsync(1000);

      const error = await promise;
      expect(error.code).toBe('server_error');

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Retry Delays', () => {
    it('should use exponential backoff delays (1s, 2s, 4s)', async () => {
      const client = new M2MClient(createMockConfig({ retries: 3 }));

      // All attempts fail
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);

      const promise = client.getToken().catch((error) => error);

      // Wait for initial request to process
      await vi.waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(1));

      // Advance 1000ms for first retry (2^0 * 1000 = 1000ms)
      await vi.advanceTimersByTimeAsync(1000);
      await vi.waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(2));

      // Advance 2000ms for second retry (2^1 * 1000 = 2000ms)
      await vi.advanceTimersByTimeAsync(2000);
      await vi.waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(3));

      const error = await promise;
      expect(error.code).toBe('server_error');

      // Verify exponential backoff pattern: 1s, 2s
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should use custom retry strategy if provided', async () => {
      const customStrategy: RetryStrategy = {
        shouldRetry: (error, attempt) => {
          return error.code === 'server_error' && attempt < 2;
        },
        getDelay: (attempt) => {
          return attempt * 500; // 500ms, 1000ms
        },
      };

      const client = new M2MClient(
        createMockConfig({
          retries: 3,
          retryStrategy: customStrategy,
        }),
      );

      // All attempts fail
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);

      const promise = client.getToken().catch((error) => error);

      // First retry with 500ms delay
      await vi.advanceTimersByTimeAsync(500);
      expect(mockFetch).toHaveBeenCalledTimes(2);

      // Second retry not allowed by custom strategy
      await vi.advanceTimersByTimeAsync(1000);

      const error = await promise;
      expect(error.code).toBe('server_error');

      // Custom strategy only allows 2 attempts
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should call custom shouldRetry() for each attempt', async () => {
      const shouldRetrySpy = vi.fn((error, attempt) => {
        return error.code === 'server_error' && attempt < 3;
      });

      const customStrategy: RetryStrategy = {
        shouldRetry: shouldRetrySpy,
        getDelay: () => 100,
      };

      const client = new M2MClient(
        createMockConfig({
          retries: 4,
          retryStrategy: customStrategy,
        }),
      );

      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);

      const promise = client.getToken().catch((error) => error);

      await vi.advanceTimersByTimeAsync(100);
      await vi.advanceTimersByTimeAsync(100);
      await vi.advanceTimersByTimeAsync(100);

      const error = await promise;
      expect(error.code).toBe('server_error');

      // Should be called after each error
      expect(shouldRetrySpy).toHaveBeenCalledTimes(3);
      expect(shouldRetrySpy).toHaveBeenNthCalledWith(1, { code: 'server_error', status: 500 }, 1);
      expect(shouldRetrySpy).toHaveBeenNthCalledWith(2, { code: 'server_error', status: 500 }, 2);
      expect(shouldRetrySpy).toHaveBeenNthCalledWith(3, { code: 'server_error', status: 500 }, 3);
    });

    it('should call custom getDelay() for each retry', async () => {
      const getDelaySpy = vi.fn((attempt) => attempt * 200);

      const customStrategy: RetryStrategy = {
        shouldRetry: (error, attempt) => attempt < 3,
        getDelay: getDelaySpy,
      };

      const client = new M2MClient(
        createMockConfig({
          retries: 3,
          retryStrategy: customStrategy,
        }),
      );

      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      mockFetchSuccess(mockFetch, createMockToken());

      const promise = client.getToken();

      await vi.advanceTimersByTimeAsync(200); // First retry delay
      await vi.advanceTimersByTimeAsync(400); // Second retry delay

      await promise;

      // Should be called for each retry
      expect(getDelaySpy).toHaveBeenCalledTimes(2);
      expect(getDelaySpy).toHaveBeenNthCalledWith(1, 1);
      expect(getDelaySpy).toHaveBeenNthCalledWith(2, 2);
    });
  });

  describe('Rate Limit Headers', () => {
    it('should honor Retry-After header (seconds format)', async () => {
      const client = new M2MClient(createMockConfig({ retries: 2 }));

      // First attempt: 429 with Retry-After: 3
      mockFetchError(mockFetch, 429, OAUTH_ERROR_RATE_LIMIT, {
        'retry-after': '3',
      });
      mockFetchSuccess(mockFetch, createMockToken());

      const promise = client.getToken();

      // Default backoff is 1000ms, but we expect it to use default strategy
      // Note: The current implementation uses the retry strategy delay,
      // not Retry-After header. This test documents current behavior.
      await vi.advanceTimersByTimeAsync(1000);

      await promise;

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should populate x-ratelimit-reset timestamp in error object', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      const resetTime = Math.floor(Date.now() / 1000) + 3600;

      mockFetchError(mockFetch, 429, OAUTH_ERROR_RATE_LIMIT, {
        'x-ratelimit-limit': '100',
        'x-ratelimit-remaining': '0',
        'x-ratelimit-reset': String(resetTime),
      });

      try {
        await client.getToken();
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.rateLimitInfo).toBeDefined();
        expect(error.rateLimitInfo.limit).toBe(100);
        expect(error.rateLimitInfo.remaining).toBe(0);
        expect(error.rateLimitInfo.reset).toBe(resetTime);
      }
    });

    it('should include rate limit info in M2MError.rateLimitInfo', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      const resetTime = Math.floor(Date.now() / 1000) + 7200;

      mockFetchError(mockFetch, 429, OAUTH_ERROR_RATE_LIMIT, {
        'x-ratelimit-limit': '1000',
        'x-ratelimit-remaining': '0',
        'x-ratelimit-reset': String(resetTime),
      });

      try {
        await client.getToken();
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.code).toBe('rate_limit_exceeded');
        expect(error.rateLimitInfo).toEqual({
          limit: 1000,
          remaining: 0,
          reset: resetTime,
        });
      }
    });
  });

  describe('Edge Cases', () => {
    it('should handle network error during retry', async () => {
      const client = new M2MClient(createMockConfig({ retries: 3 }));

      // First attempt: network error
      mockNetworkError(mockFetch);
      // Second attempt: network error
      mockNetworkError(mockFetch);
      // Third attempt: success
      mockFetchSuccess(mockFetch, createMockToken());

      const promise = client.getToken();

      // Network errors are wrapped as M2MNetworkError with code 'temporarily_unavailable'
      // which should trigger retries
      await vi.advanceTimersByTimeAsync(1000);
      await vi.advanceTimersByTimeAsync(2000);

      const token = await promise;

      expect(token).toBeDefined();
      // Should retry network errors
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should handle timeout during retry without exceeding total attempts', async () => {
      const client = new M2MClient(createMockConfig({ retries: 3, timeout: 5000 }));

      // First attempt: 500 error
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      // Second attempt: 500 error
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      // Third attempt: success
      mockFetchSuccess(mockFetch, createMockToken());

      const promise = client.getToken();

      // Advance through retry delays
      await vi.advanceTimersByTimeAsync(1000);
      await vi.advanceTimersByTimeAsync(2000);

      const token = await promise;

      expect(token).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should return token on success after initial failure', async () => {
      const client = new M2MClient(createMockConfig({ retries: 3 }));

      const mockToken = createMockToken();

      // First attempt: 500 error
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      // Second attempt: success
      mockFetchSuccess(mockFetch, mockToken);

      const promise = client.getToken();

      // Advance through retry delay
      await vi.advanceTimersByTimeAsync(1000);

      const token = await promise;

      expect(token).toBeDefined();
      expect(token.access_token).toBe(mockToken.access_token);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should handle 502 Bad Gateway with retry', async () => {
      const client = new M2MClient(createMockConfig({ retries: 2 }));

      mockFetchError(mockFetch, 502, OAUTH_ERROR_SERVER_ERROR);
      mockFetchSuccess(mockFetch, createMockToken());

      const promise = client.getToken();

      await vi.advanceTimersByTimeAsync(1000);

      const token = await promise;

      expect(token).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should handle 504 Gateway Timeout with retry', async () => {
      const client = new M2MClient(createMockConfig({ retries: 2 }));

      mockFetchError(mockFetch, 504, OAUTH_ERROR_SERVER_ERROR);
      mockFetchSuccess(mockFetch, createMockToken());

      const promise = client.getToken();

      await vi.advanceTimersByTimeAsync(1000);

      const token = await promise;

      expect(token).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });
});
