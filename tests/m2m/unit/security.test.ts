/**
 * M2M Client Security Validation Tests
 *
 * CRITICAL: Ensures that client secrets and sensitive data are never exposed
 * through error messages, logs, callbacks, or serialization.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import { M2MClient, M2MError, M2MNetworkError } from '../../../lib/m2m';
import { OAUTH_ERROR_INVALID_CLIENT, TEST_CLIENT_ID, TEST_CLIENT_SECRET, createMockConfig } from '../utils/fixtures';
import { mockFetchError, setupFetchMock } from '../utils/mock-fetch';

describe('M2M Client Security Validation', () => {
  let mockFetch: Mock;

  beforeEach(() => {
    mockFetch = setupFetchMock();
  });

  describe('Client Secret Protection', () => {
    it('NEVER exposes client secret in M2MError.message', async () => {
      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      const client = new M2MClient(createMockConfig());

      try {
        await client.getToken();
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(M2MError);
        const m2mError = error as M2MError;

        // Secret must NOT appear in message
        expect(m2mError.message).not.toContain(TEST_CLIENT_SECRET);
      }
    });

    it('NEVER exposes client secret in M2MError.toJSON() output', async () => {
      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      const client = new M2MClient(createMockConfig());

      try {
        await client.getToken();
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(M2MError);
        const m2mError = error as M2MError;

        const json = m2mError.toJSON();
        const jsonString = JSON.stringify(json);

        // Secret must NOT appear in JSON serialization
        expect(jsonString).not.toContain(TEST_CLIENT_SECRET);
      }
    });

    it('NEVER exposes client secret in M2MError.toString() output', async () => {
      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      const client = new M2MClient(createMockConfig());

      try {
        await client.getToken();
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(M2MError);
        const m2mError = error as M2MError;

        const errorString = m2mError.toString();

        // Secret must NOT appear in string representation
        expect(errorString).not.toContain(TEST_CLIENT_SECRET);
      }
    });

    it('NEVER exposes client secret in error stack trace', async () => {
      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      const client = new M2MClient(createMockConfig());

      try {
        await client.getToken();
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(M2MError);
        const m2mError = error as M2MError;

        // Secret must NOT appear in stack trace
        expect(m2mError.stack).toBeDefined();
        expect(m2mError.stack).not.toContain(TEST_CLIENT_SECRET);
      }
    });

    it('NEVER passes client secret to onError callback', async () => {
      mockFetchError(mockFetch, 401, OAUTH_ERROR_INVALID_CLIENT);

      const onErrorSpy = vi.fn();
      const client = new M2MClient(
        createMockConfig({
          onError: onErrorSpy,
        }),
      );

      try {
        await client.getToken();
        expect.fail('Should have thrown an error');
      } catch {
        // Error expected
      }

      expect(onErrorSpy).toHaveBeenCalledOnce();
      const errorData = onErrorSpy.mock.calls[0][0];
      const errorDataString = JSON.stringify(errorData);

      // Secret must NOT appear in callback data
      expect(errorDataString).not.toContain(TEST_CLIENT_SECRET);
    });

    it('NEVER exposes client secret in network error messages', async () => {
      const networkError = new TypeError('Failed to fetch');
      mockFetch.mockRejectedValueOnce(networkError);

      const client = new M2MClient(createMockConfig());

      try {
        await client.getToken();
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(M2MError);
        const m2mError = error as M2MError;

        // Secret must NOT appear in network error
        expect(m2mError.message).not.toContain(TEST_CLIENT_SECRET);
        expect(m2mError.toString()).not.toContain(TEST_CLIENT_SECRET);
        expect(JSON.stringify(m2mError.toJSON())).not.toContain(TEST_CLIENT_SECRET);
      }
    });
  });

  describe('Callback Security', () => {
    it('onTokenRequest callback receives clientId but NOT clientSecret', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          access_token: 'mock_token',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
      });

      const onRequestSpy = vi.fn();
      const client = new M2MClient(
        createMockConfig({
          onTokenRequest: onRequestSpy,
        }),
      );

      await client.getToken();

      expect(onRequestSpy).toHaveBeenCalledOnce();
      const requestData = onRequestSpy.mock.calls[0][0];

      // clientId SHOULD be present
      expect(requestData.clientId).toBe(TEST_CLIENT_ID);

      // clientSecret must NOT be present
      expect(requestData).not.toHaveProperty('clientSecret');
      expect(JSON.stringify(requestData)).not.toContain(TEST_CLIENT_SECRET);
    });

    it('onTokenResponse callback does not expose internal implementation details', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          access_token: 'mock_token',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
      });

      const onResponseSpy = vi.fn();
      const client = new M2MClient(
        createMockConfig({
          onTokenResponse: onResponseSpy,
        }),
      );

      await client.getToken();

      expect(onResponseSpy).toHaveBeenCalledOnce();
      const responseData = onResponseSpy.mock.calls[0][0];
      const responseString = JSON.stringify(responseData);

      // Should only contain token response, not secrets
      expect(responseString).not.toContain(TEST_CLIENT_SECRET);
    });
  });

  describe('Cache Key Security', () => {
    it('cache keys do NOT contain clientSecret', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          access_token: 'mock_token',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
      });

      const customCache = {
        get: vi.fn().mockResolvedValue(null),
        set: vi.fn().mockResolvedValue(undefined),
        delete: vi.fn().mockResolvedValue(undefined),
      };

      const client = new M2MClient(
        createMockConfig({
          cache: customCache,
        }),
      );

      await client.getToken();

      // Verify cache.set was called
      expect(customCache.set).toHaveBeenCalled();

      // Get the cache key (first argument)
      const cacheKey = customCache.set.mock.calls[0][0] as string;

      // Cache key must NOT contain secret
      expect(cacheKey).not.toContain(TEST_CLIENT_SECRET);

      // Cache key should contain clientId
      expect(cacheKey).toContain(TEST_CLIENT_ID);
    });
  });

  describe('Error Message Safety', () => {
    it('error messages do NOT expose internal implementation details', async () => {
      mockFetchError(mockFetch, 500, {
        error: 'server_error',
        error_description: 'Internal server error',
      });

      const client = new M2MClient(createMockConfig());

      try {
        await client.getToken();
        expect.fail('Should have thrown an error');
      } catch (error) {
        const m2mError = error as M2MError;

        // Should not expose internal paths, secrets, etc.
        expect(m2mError.message).not.toMatch(/client_secret/i);
        expect(m2mError.message).not.toContain(TEST_CLIENT_SECRET);
      }
    });

    it('error messages are sanitized - no full request bodies', async () => {
      mockFetchError(mockFetch, 400, {
        error: 'invalid_request',
        error_description: 'Bad request',
      });

      const client = new M2MClient(createMockConfig());

      try {
        await client.getToken();
        expect.fail('Should have thrown an error');
      } catch (error) {
        const m2mError = error as M2MError;
        const errorJSON = m2mError.toJSON();

        // Error should not contain request body with secrets
        expect(JSON.stringify(errorJSON)).not.toContain('grant_type=client_credentials');
        expect(JSON.stringify(errorJSON)).not.toContain(TEST_CLIENT_SECRET);
      }
    });

    it('timeout errors do NOT expose client secret', async () => {
      const timeoutError = new Error('The operation was aborted');
      timeoutError.name = 'AbortError';
      mockFetch.mockRejectedValueOnce(timeoutError);

      const client = new M2MClient(createMockConfig({ timeout: 100 }));

      try {
        await client.getToken();
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(M2MError);
        const m2mError = error as M2MError;

        expect(m2mError.message).not.toContain(TEST_CLIENT_SECRET);
      }
    });
  });

  describe('Configuration Error Security', () => {
    it('configuration errors do NOT leak secrets in error messages', () => {
      // Create client without clientSecret to trigger config error
      try {
        new M2MClient({
          url: 'https://api.passflow.cloud',
          clientId: TEST_CLIENT_ID,
          clientSecret: '', // Empty secret should trigger error
        });
        expect.fail('Should have thrown an error');
      } catch (error) {
        const errorString = String(error);

        // Should not contain any partial secrets
        expect(errorString).not.toContain(TEST_CLIENT_SECRET);
      }
    });
  });

  describe('Comprehensive Secret Search', () => {
    it('performs comprehensive search - secret NEVER appears anywhere in error flow', async () => {
      mockFetchError(mockFetch, 401, {
        error: 'invalid_client',
        error_description: 'Client authentication failed. Check your credentials.',
      });

      const onErrorSpy = vi.fn();
      const onRequestSpy = vi.fn();

      const client = new M2MClient(
        createMockConfig({
          onError: onErrorSpy,
          onTokenRequest: onRequestSpy,
        }),
      );

      try {
        await client.getToken();
        expect.fail('Should have thrown an error');
      } catch (error) {
        const m2mError = error as M2MError;

        // Collect all possible string representations
        const allStrings = [m2mError.message, m2mError.toString(), JSON.stringify(m2mError.toJSON()), m2mError.stack || ''];

        // Check callback data
        if (onErrorSpy.mock.calls.length > 0) {
          allStrings.push(JSON.stringify(onErrorSpy.mock.calls[0][0]));
        }
        if (onRequestSpy.mock.calls.length > 0) {
          allStrings.push(JSON.stringify(onRequestSpy.mock.calls[0][0]));
        }

        // Comprehensive check: secret should NOT appear in ANY string
        for (const str of allStrings) {
          expect(str).not.toContain(TEST_CLIENT_SECRET);
        }
      }
    });
  });
});
