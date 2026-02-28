/**
 * M2M Client Error Handling Tests
 *
 * Tests for error handling in M2MClient including OAuth error responses,
 * network errors, malformed responses, and error callbacks.
 */

import { type Mock, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { M2MClient } from '../../../lib/m2m/client';
import { M2MError, M2MNetworkError } from '../../../lib/m2m/errors';
import {
  OAUTH_ERROR_INVALID_CLIENT,
  OAUTH_ERROR_INVALID_SCOPE,
  OAUTH_ERROR_SERVER_ERROR,
  TEST_URL,
  VALID_TOKEN_RESPONSE,
  createMockConfig,
} from '../utils/fixtures';
import {
  mockFetchError,
  mockFetchSuccess,
  mockNetworkError,
  mockTimeout,
  resetFetchMock,
  setupFetchMock,
} from '../utils/mock-fetch';

describe('M2MClient - Error Handling', () => {
  let mockFetch: Mock;

  beforeEach(() => {
    mockFetch = setupFetchMock();
  });

  afterEach(() => {
    resetFetchMock(mockFetch);
    vi.clearAllMocks();
  });

  describe('OAuth Error Responses', () => {
    it('should map invalid_client error code correctly', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      await expect(client.getToken()).rejects.toMatchObject({
        name: 'M2MError',
        code: 'invalid_client',
        message: 'Client authentication failed',
        status: 401,
      });
    });

    it('should map invalid_scope error code correctly', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 400, OAUTH_ERROR_INVALID_SCOPE);

      await expect(client.getToken()).rejects.toMatchObject({
        name: 'M2MError',
        code: 'invalid_scope',
        message: 'Requested scope is invalid',
        status: 400,
      });
    });

    it('should map invalid_request error code correctly', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 400, {
        error: 'invalid_request',
        error_description: 'Missing required parameter',
      });

      await expect(client.getToken()).rejects.toMatchObject({
        name: 'M2MError',
        code: 'invalid_request',
        message: 'Missing required parameter',
        status: 400,
      });
    });

    it('should map unauthorized_client error code correctly', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 401, {
        error: 'unauthorized_client',
        error_description: 'Client not authorized for this grant type',
      });

      await expect(client.getToken()).rejects.toMatchObject({
        name: 'M2MError',
        code: 'unauthorized_client',
        message: 'Client not authorized for this grant type',
        status: 401,
      });
    });

    it('should map server_error error code correctly', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);

      await expect(client.getToken()).rejects.toMatchObject({
        name: 'M2MError',
        code: 'server_error',
        message: 'The authorization server encountered an error',
        status: 500,
      });
    });

    it('should handle unknown error codes gracefully', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 400, {
        error: 'unknown_error_code',
        error_description: 'Something went wrong',
      });

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MError);
      expect(error.code).toBe('unknown_error_code');
      expect(error.message).toBe('Something went wrong');
      expect(error.status).toBe(400);
    });
  });

  describe('Error Object Properties', () => {
    it('should contain correct code', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MError);
      expect(error.code).toBe('invalid_client');
    });

    it('should contain correct message', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 400, {
        error: 'invalid_scope',
        error_description: 'Custom error message',
      });

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MError);
      expect(error.message).toBe('Custom error message');
    });

    it('should contain HTTP status', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 403, {
        error: 'invalid_scope',
        error_description: 'Forbidden scope',
      });

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MError);
      expect(error.status).toBe(403);
    });

    it('should contain headers when present', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      const headers = {
        'x-request-id': 'test-request-123',
        'content-type': 'application/json',
      };

      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT, headers);

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MError);
      expect(error.headers).toBeDefined();
      expect(error.headers?.['x-request-id']).toBe('test-request-123');
      expect(error.headers?.['content-type']).toBe('application/json');
    });

    it('should return correct value from isRetryable() for retryable errors', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      // Test server_error (retryable)
      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);
      const serverError = await client.getToken().catch((e) => e);
      expect(serverError.isRetryable()).toBe(true);

      // Test temporarily_unavailable (retryable)
      mockFetchError(mockFetch, 503, {
        error: 'temporarily_unavailable',
        error_description: 'Service unavailable',
      });
      const unavailableError = await client.getToken().catch((e) => e);
      expect(unavailableError.isRetryable()).toBe(true);

      // Test rate_limit_exceeded (retryable)
      mockFetchError(mockFetch, 429, {
        error: 'rate_limit_exceeded',
        error_description: 'Too many requests',
      });
      const rateLimitError = await client.getToken().catch((e) => e);
      expect(rateLimitError.isRetryable()).toBe(true);
    });

    it('should return correct value from isRetryable() for non-retryable errors', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      // Test invalid_client (not retryable)
      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);
      const clientError = await client.getToken().catch((e) => e);
      expect(clientError.isRetryable()).toBe(false);

      // Test invalid_scope (not retryable)
      mockFetchError(mockFetch, 400, OAUTH_ERROR_INVALID_SCOPE);
      const scopeError = await client.getToken().catch((e) => e);
      expect(scopeError.isRetryable()).toBe(false);

      // Test invalid_request (not retryable)
      mockFetchError(mockFetch, 400, {
        error: 'invalid_request',
        error_description: 'Bad request',
      });
      const requestError = await client.getToken().catch((e) => e);
      expect(requestError.isRetryable()).toBe(false);
    });
  });

  describe('Network Errors', () => {
    it('should throw M2MNetworkError on network timeout', async () => {
      const client = new M2MClient(createMockConfig({ timeout: 100, retries: 1 }));

      mockTimeout(mockFetch);

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MNetworkError);
      expect(error.name).toBe('M2MNetworkError');
      expect(error.message).toContain('timed out');
      expect(error.status).toBe(0);
    });

    it('should throw M2MNetworkError on connection refused', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockNetworkError(mockFetch, new TypeError('Failed to fetch'));

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MNetworkError);
      expect(error.name).toBe('M2MNetworkError');
      expect(error.message).toContain('Network error');
      expect(error.status).toBe(0);
    });

    it('should throw M2MNetworkError on fetch failure', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockNetworkError(mockFetch, new TypeError('fetch failed: connection reset'));

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MNetworkError);
      expect(error.name).toBe('M2MNetworkError');
      expect(error.message).toContain('Network error');
    });
  });

  describe('Response Edge Cases', () => {
    it('should handle malformed JSON response', async () => {
      const client = new M2MClient(createMockConfig());

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers(),
        json: () => Promise.reject(new SyntaxError('Unexpected token in JSON')),
        text: () => Promise.resolve('not json'),
      });

      await expect(client.getToken()).rejects.toThrow();
    });

    it('should handle empty response body', async () => {
      const client = new M2MClient(createMockConfig());

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers(),
        json: async () => ({}),
        text: async () => '',
      });

      const token = await client.getToken();

      // Should accept empty response body as valid (server may return minimal data)
      expect(token).toBeDefined();
      expect(token).toMatchObject({});
    });

    it('should handle 200 status with error field', async () => {
      const client = new M2MClient(createMockConfig());

      mockFetchSuccess(mockFetch, {
        error: 'invalid_grant',
        error_description: 'Grant is invalid',
      });

      // With ok: true and status 200, the client treats it as success
      // This tests that the implementation doesn't check for error field in success responses
      const response = await client.getToken();

      expect(response).toBeDefined();
    });

    it('should handle missing required fields (access_token)', async () => {
      const client = new M2MClient(createMockConfig());

      mockFetchSuccess(mockFetch, {
        token_type: 'Bearer',
        expires_in: 3600,
        // Missing access_token
      });

      const response = await client.getToken();

      // Client returns the response as-is, validation happens at usage time
      expect(response).toBeDefined();
      expect(response.access_token).toBeUndefined();
    });

    it('should handle invalid token_type (not "Bearer")', async () => {
      const client = new M2MClient(createMockConfig());

      mockFetchSuccess(mockFetch, {
        access_token: 'test-token',
        token_type: 'MAC', // Not Bearer
        expires_in: 3600,
      });

      const response = await client.getToken();

      // Client accepts any token_type from server
      expect(response).toBeDefined();
      expect(response.token_type).toBe('MAC');
    });

    it('should use error description or message field', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      // Test with message field (not standard OAuth but some servers use it)
      mockFetchError(mockFetch, 400, {
        error: 'invalid_request',
        message: 'Error from message field',
      });

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MError);
      expect(error.message).toBe('Error from message field');
    });

    it('should use default error message when description is missing', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 401, {
        error: 'invalid_client',
        // No error_description
      });

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MError);
      expect(error.message).toBe('Client authentication failed. Verify your client credentials.');
    });

    it('should default to server_error when error field is missing', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 500, {
        // No error field
        error_description: 'Something went wrong',
      });

      const error = await client.getToken().catch((e) => e);

      expect(error).toBeInstanceOf(M2MError);
      expect(error.code).toBe('server_error');
      expect(error.message).toBe('Something went wrong');
    });
  });

  describe('Callbacks', () => {
    it('should invoke onError callback on error', async () => {
      const onError = vi.fn();
      const client = new M2MClient(
        createMockConfig({
          onError,
          retries: 1,
        }),
      );

      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      await client.getToken().catch(() => {
        // Ignore error
      });

      expect(onError).toHaveBeenCalledOnce();
      expect(onError).toHaveBeenCalledWith({
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      });
    });

    it('should invoke onError callback with correct error object', async () => {
      const onError = vi.fn();
      const client = new M2MClient(
        createMockConfig({
          onError,
          retries: 1,
        }),
      );

      mockFetchError(mockFetch, 400, {
        error: 'invalid_scope',
        error_description: 'Custom scope error',
      });

      await client.getToken().catch(() => {
        // Ignore error
      });

      expect(onError).toHaveBeenCalledOnce();
      expect(onError).toHaveBeenCalledWith({
        error: 'invalid_scope',
        error_description: 'Custom scope error',
      });
    });

    it('should not invoke onError callback on success', async () => {
      const onError = vi.fn();
      const client = new M2MClient(
        createMockConfig({
          onError,
          retries: 1,
        }),
      );

      mockFetchSuccess(mockFetch, VALID_TOKEN_RESPONSE);

      await client.getToken();

      expect(onError).not.toHaveBeenCalled();
    });

    it('should invoke onError callback on network errors', async () => {
      const onError = vi.fn();
      const client = new M2MClient(
        createMockConfig({
          onError,
          timeout: 100,
          retries: 1,
        }),
      );

      mockTimeout(mockFetch);

      await client.getToken().catch(() => {
        // Ignore error
      });

      // Network errors don't trigger onError callback (only OAuth errors do)
      expect(onError).not.toHaveBeenCalled();
    });

    it('should handle onError callback throwing an error', async () => {
      const onError = vi.fn(() => {
        throw new Error('Callback error');
      });

      const client = new M2MClient(
        createMockConfig({
          onError,
          retries: 1,
        }),
      );

      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      // When callback throws, the callback error propagates (implementation does not catch it)
      await expect(client.getToken()).rejects.toThrow('Callback error');

      expect(onError).toHaveBeenCalledOnce();
    });
  });

  describe('Error Object Methods', () => {
    it('should serialize error to JSON', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(
        mockFetch,
        429,
        {
          error: 'rate_limit_exceeded',
          error_description: 'Too many requests',
        },
        {
          'x-ratelimit-limit': '100',
          'x-ratelimit-remaining': '0',
          'x-ratelimit-reset': '1700000000',
        },
      );

      const error = await client.getToken().catch((e) => e);

      const json = error.toJSON();

      expect(json).toMatchObject({
        name: 'M2MError',
        code: 'rate_limit_exceeded',
        message: 'Too many requests',
        status: 429,
      });
      expect(json.timestamp).toBeDefined();
    });

    it('should convert error to string', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      const error = await client.getToken().catch((e) => e);

      const str = error.toString();

      expect(str).toContain('M2MError');
      expect(str).toContain('invalid_client');
      expect(str).toContain('Client authentication failed');
      expect(str).toContain('401');
    });

    it('should calculate retry delay from rate limit headers', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      const resetTime = Math.floor(Date.now() / 1000) + 60; // 60 seconds from now

      mockFetchError(
        mockFetch,
        429,
        {
          error: 'rate_limit_exceeded',
          error_description: 'Too many requests',
        },
        {
          'x-ratelimit-limit': '100',
          'x-ratelimit-remaining': '0',
          'x-ratelimit-reset': String(resetTime),
        },
      );

      const error = await client.getToken().catch((e) => e);

      expect(error.rateLimitInfo).toBeDefined();
      expect(error.rateLimitInfo?.reset).toBe(resetTime);

      const retryAfter = error.getRetryAfter();

      // Should suggest waiting close to 60 seconds
      expect(retryAfter).toBeGreaterThan(55000);
      expect(retryAfter).toBeLessThan(65000);
    });

    it('should return default retry delay when no rate limit info', async () => {
      const client = new M2MClient(createMockConfig({ retries: 1 }));

      mockFetchError(mockFetch, 500, OAUTH_ERROR_SERVER_ERROR);

      const error = await client.getToken().catch((e) => e);

      const retryAfter = error.getRetryAfter();

      expect(retryAfter).toBe(1000); // 1 second default
    });
  });
});
