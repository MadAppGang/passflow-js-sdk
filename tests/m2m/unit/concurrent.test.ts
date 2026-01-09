/**
 * M2M Client - Concurrent Request Handling Tests
 *
 * Tests behavior when multiple concurrent requests are made to the M2M client,
 * including cache coordination, race conditions, and request deduplication.
 *
 * IMPORTANT: The current M2MClient implementation does NOT deduplicate concurrent
 * requests. Each getToken() call triggers its own HTTP request even if called
 * simultaneously. These tests document the ACTUAL behavior.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import { M2MClient } from '../../../lib/m2m';
import { FakeCache } from '../utils/fake-cache';
import { createExpiredToken, createMockConfig, createMockToken } from '../utils/fixtures';
import { mockFetchSuccess, resetFetchMock, setupFetchMock } from '../utils/mock-fetch';

describe('M2M Client - Concurrent Request Handling', () => {
  let mockFetch: Mock;
  let cache: FakeCache;

  beforeEach(() => {
    mockFetch = setupFetchMock();
    cache = new FakeCache();
    vi.useFakeTimers();
  });

  afterEach(() => {
    resetFetchMock(mockFetch);
    vi.useRealTimers();
  });

  describe('Concurrent getToken() - Empty Cache', () => {
    it('should handle multiple concurrent getToken() calls when cache is empty', async () => {
      const client = new M2MClient(createMockConfig({ cache }));

      // Track call order
      let callIndex = 0;

      // Mock fetch to return different tokens with delay
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            // Capture index immediately when called
            const myIndex = callIndex++;
            const token = createMockToken({ access_token: `token-${myIndex + 1}` });

            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => token,
                text: async () => JSON.stringify(token),
              });
            }, 50);
          }),
      );

      // Make 3 concurrent requests
      const promise1 = client.getToken();
      const promise2 = client.getToken();
      const promise3 = client.getToken();

      // Advance timers to complete all requests
      await vi.advanceTimersByTimeAsync(60);

      const [result1, result2, result3] = await Promise.all([promise1, promise2, promise3]);

      // ACTUAL BEHAVIOR: No deduplication - each request gets its own HTTP call
      expect(mockFetch).toHaveBeenCalledTimes(3);

      // Each call gets a different token (but order may vary due to timing)
      const receivedTokens = [result1.access_token, result2.access_token, result3.access_token].sort();
      expect(receivedTokens).toEqual(['token-1', 'token-2', 'token-3']);

      // Cache is written multiple times (race condition documented)
      expect(cache.setCallCount()).toBeGreaterThanOrEqual(3);
    });

    it('should verify all concurrent requests complete successfully', async () => {
      const client = new M2MClient(createMockConfig({ cache }));
      const token = createMockToken();

      // Mock with delay
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => token,
                text: async () => JSON.stringify(token),
              });
            }, 100);
          }),
      );

      // Make 5 concurrent requests
      const promises = Array.from({ length: 5 }, () => client.getToken());

      // Advance timers
      await vi.advanceTimersByTimeAsync(150);

      const results = await Promise.all(promises);

      // All requests complete
      expect(results).toHaveLength(5);
      expect(mockFetch).toHaveBeenCalledTimes(5);

      // All results are valid tokens
      for (const result of results) {
        expect(result).toHaveProperty('access_token');
        expect(result).toHaveProperty('token_type', 'Bearer');
        expect(result).toHaveProperty('expires_in');
      }
    });

    it('should handle concurrent requests with different delays', async () => {
      const client = new M2MClient(createMockConfig({ cache }));

      // Mock with variable delays
      let callCount = 0;
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            callCount++;
            const delay = callCount === 1 ? 100 : callCount === 2 ? 50 : 25;
            const token = createMockToken({ access_token: `token-${callCount}` });

            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => token,
                text: async () => JSON.stringify(token),
              });
            }, delay);
          }),
      );

      // Make 3 concurrent requests
      const promise1 = client.getToken(); // 100ms delay
      const promise2 = client.getToken(); // 50ms delay
      const promise3 = client.getToken(); // 25ms delay

      // Advance in stages to let requests complete at different times
      await vi.advanceTimersByTimeAsync(30);
      await vi.advanceTimersByTimeAsync(30);
      await vi.advanceTimersByTimeAsync(50);

      const [result1, result2, result3] = await Promise.all([promise1, promise2, promise3]);

      // All complete despite different delays
      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
      expect(result3).toBeDefined();

      // Order doesn't matter - all get different tokens
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });
  });

  describe('Concurrent getToken() - Expired Cache', () => {
    it('should handle concurrent getToken() calls when cached token is expired', async () => {
      const client = new M2MClient(createMockConfig({ cache }));
      const expiredToken = createExpiredToken();
      const freshToken1 = createMockToken({ access_token: 'fresh-1' });
      const freshToken2 = createMockToken({ access_token: 'fresh-2' });

      // Pre-populate cache with expired token
      cache.setTokenDirectly('m2m:test-m2m-client-id:api:read,api:write:orders-api,users-api', expiredToken, -1);

      // Mock fetch for new tokens
      let callCount = 0;
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            callCount++;
            const token = callCount === 1 ? freshToken1 : freshToken2;

            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => token,
                text: async () => JSON.stringify(token),
              });
            }, 50);
          }),
      );

      // Make concurrent requests
      const promise1 = client.getToken();
      const promise2 = client.getToken();

      await vi.advanceTimersByTimeAsync(60);

      const [result1, result2] = await Promise.all([promise1, promise2]);

      // Both requests trigger HTTP calls (no deduplication)
      expect(mockFetch).toHaveBeenCalledTimes(2);

      // Both get fresh tokens
      expect(result1.access_token).toBe('fresh-1');
      expect(result2.access_token).toBe('fresh-2');
    });

    it('should verify expired cache detection works in concurrent scenario', async () => {
      const client = new M2MClient(createMockConfig({ cache }));
      const expiredToken = createExpiredToken();

      // Pre-populate with expired token
      cache.setTokenDirectly('m2m:test-m2m-client-id:api:read,api:write:orders-api,users-api', expiredToken, -1000);

      const freshToken = createMockToken();
      mockFetchSuccess(mockFetch, freshToken);
      mockFetchSuccess(mockFetch, freshToken);
      mockFetchSuccess(mockFetch, freshToken);

      // Make 3 concurrent requests
      const promises = [client.getToken(), client.getToken(), client.getToken()];

      const results = await Promise.all(promises);

      // All trigger HTTP requests (expired token not used)
      expect(mockFetch).toHaveBeenCalledTimes(3);

      // All get fresh tokens
      for (const result of results) {
        expect(result.expires_in).toBe(3600);
        expect(result).toHaveProperty('issued_at');
      }
    });
  });

  describe('Concurrent forceRefresh', () => {
    it('should handle multiple concurrent forceRefresh calls', async () => {
      const client = new M2MClient(createMockConfig({ cache }));
      const cachedToken = createMockToken({ access_token: 'cached' });

      // Pre-populate cache
      cache.setTokenDirectly('m2m:test-m2m-client-id:api:read,api:write:orders-api,users-api', cachedToken, 3600);

      // Mock fetch for forced refresh
      let callCount = 0;
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            callCount++;
            const token = createMockToken({ access_token: `forced-${callCount}` });

            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => token,
                text: async () => JSON.stringify(token),
              });
            }, 50);
          }),
      );

      // Make 3 concurrent forceRefresh calls
      const promise1 = client.getToken({ forceRefresh: true });
      const promise2 = client.getToken({ forceRefresh: true });
      const promise3 = client.getToken({ forceRefresh: true });

      await vi.advanceTimersByTimeAsync(60);

      const [result1, result2, result3] = await Promise.all([promise1, promise2, promise3]);

      // All bypass cache and trigger HTTP requests
      expect(mockFetch).toHaveBeenCalledTimes(3);

      // Each gets a new token
      expect(result1.access_token).toBe('forced-1');
      expect(result2.access_token).toBe('forced-2');
      expect(result3.access_token).toBe('forced-3');

      // Cache is updated multiple times
      expect(cache.setCallCount()).toBeGreaterThanOrEqual(3);
    });

    it('should verify forceRefresh bypasses cache even under concurrency', async () => {
      const client = new M2MClient(createMockConfig({ cache }));
      const cachedToken = createMockToken({ access_token: 'cached' });

      cache.setTokenDirectly('m2m:test-m2m-client-id:api:read,api:write:orders-api,users-api', cachedToken, 3600);

      const freshToken = createMockToken({ access_token: 'fresh' });

      // Mock multiple responses
      for (let i = 0; i < 5; i++) {
        mockFetchSuccess(mockFetch, { ...freshToken, access_token: `fresh-${i}` });
      }

      // Mix of normal and forced requests
      const promises = [
        client.getToken(), // Uses cache
        client.getToken({ forceRefresh: true }), // Bypasses cache
        client.getToken({ forceRefresh: true }), // Bypasses cache
        client.getToken(), // Uses cache
        client.getToken({ forceRefresh: true }), // Bypasses cache
      ];

      const results = await Promise.all(promises);

      // 3 forced requests hit HTTP (2 normal requests may use cache)
      expect(mockFetch.mock.calls.length).toBeGreaterThanOrEqual(3);

      // Results are all valid
      for (const result of results) {
        expect(result).toHaveProperty('access_token');
      }
    });
  });

  describe('Concurrent getValidToken() - Auto-Refresh Window', () => {
    it('should handle concurrent getValidToken() calls during refresh threshold window', async () => {
      const refreshThreshold = 300; // 5 minutes
      const client = new M2MClient(
        createMockConfig({
          cache,
          autoRefresh: true,
          refreshThreshold,
        }),
      );

      // Create token that expires in 4 minutes (within refresh threshold)
      const expiringToken = createMockToken({ expires_in: 240, issued_at: Math.floor(Date.now() / 1000) });

      cache.setTokenDirectly('m2m:test-m2m-client-id:api:read,api:write:orders-api,users-api', expiringToken, 240);

      // Mock fetch for refresh
      let callCount = 0;
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            callCount++;
            const token = createMockToken({ access_token: `refreshed-${callCount}` });

            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => token,
                text: async () => JSON.stringify(token),
              });
            }, 50);
          }),
      );

      // Make concurrent getValidToken calls
      const promise1 = client.getValidToken();
      const promise2 = client.getValidToken();
      const promise3 = client.getValidToken();

      await vi.advanceTimersByTimeAsync(60);

      const [result1, result2, result3] = await Promise.all([promise1, promise2, promise3]);

      // All trigger refresh due to threshold (no deduplication)
      expect(mockFetch).toHaveBeenCalledTimes(3);

      // Each gets a refreshed token
      expect(result1.access_token).toBe('refreshed-1');
      expect(result2.access_token).toBe('refreshed-2');
      expect(result3.access_token).toBe('refreshed-3');
    });

    it('should verify auto-refresh logic with concurrent calls', async () => {
      const client = new M2MClient(
        createMockConfig({
          cache,
          autoRefresh: true,
          refreshThreshold: 600, // 10 minutes
        }),
      );

      // Token expires in 8 minutes (within threshold)
      const expiringToken = createMockToken({ expires_in: 480, issued_at: Math.floor(Date.now() / 1000) });

      cache.setTokenDirectly('m2m:test-m2m-client-id:api:read,api:write:orders-api,users-api', expiringToken, 480);

      const refreshedToken = createMockToken({ access_token: 'refreshed', expires_in: 3600 });
      mockFetchSuccess(mockFetch, refreshedToken);
      mockFetchSuccess(mockFetch, refreshedToken);

      // Concurrent calls
      const [result1, result2] = await Promise.all([client.getValidToken(), client.getValidToken()]);

      // Both trigger refresh
      expect(mockFetch).toHaveBeenCalledTimes(2);

      // Both get new tokens
      expect(result1.access_token).toBe('refreshed');
      expect(result2.access_token).toBe('refreshed');
    });

    it('should not refresh if token is valid and outside threshold', async () => {
      const client = new M2MClient(
        createMockConfig({
          cache,
          autoRefresh: true,
          refreshThreshold: 300, // 5 minutes
        }),
      );

      // Token expires in 20 minutes (outside threshold)
      const validToken = createMockToken({ expires_in: 1200, issued_at: Math.floor(Date.now() / 1000) });

      cache.setTokenDirectly('m2m:test-m2m-client-id:api:read,api:write:orders-api,users-api', validToken, 1200);

      // Concurrent calls
      const [result1, result2, result3] = await Promise.all([
        client.getValidToken(),
        client.getValidToken(),
        client.getValidToken(),
      ]);

      // No HTTP requests - all use cached token
      expect(mockFetch).not.toHaveBeenCalled();

      // All return the same cached token
      expect(result1.access_token).toBe(validToken.access_token);
      expect(result2.access_token).toBe(validToken.access_token);
      expect(result3.access_token).toBe(validToken.access_token);
    });
  });

  describe('Cache Coordination', () => {
    it('should write to cache after first request completes', async () => {
      const client = new M2MClient(createMockConfig({ cache }));
      const token = createMockToken();

      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => token,
                text: async () => JSON.stringify(token),
              });
            }, 50);
          }),
      );

      // Verify cache is empty
      expect(cache.size()).toBe(0);

      const promise = client.getToken();

      // Cache still empty during request
      expect(cache.size()).toBe(0);

      await vi.advanceTimersByTimeAsync(60);
      await promise;

      // Cache is written after request completes
      expect(cache.size()).toBe(1);
      expect(cache.setCallCount()).toBe(1);
    });

    it('should use cached value for subsequent calls after concurrent requests complete', async () => {
      const client = new M2MClient(createMockConfig({ cache }));
      const token1 = createMockToken({ access_token: 'token-1' });
      const token2 = createMockToken({ access_token: 'token-2' });

      // First two concurrent calls
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            const callNum = mockFetch.mock.calls.length;
            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => (callNum === 1 ? token1 : token2),
                text: async () => JSON.stringify(callNum === 1 ? token1 : token2),
              });
            }, 50);
          }),
      );

      // Make 2 concurrent requests
      const promise1 = client.getToken();
      const promise2 = client.getToken();

      await vi.advanceTimersByTimeAsync(60);
      await Promise.all([promise1, promise2]);

      // Reset call count to track subsequent calls
      const callCountAfterFirst = mockFetch.mock.calls.length;

      // Make another request - should use cache
      const result3 = await client.getToken();

      // No additional HTTP request
      expect(mockFetch.mock.calls.length).toBe(callCountAfterFirst);

      // Result is from cache (one of the cached tokens)
      expect(result3.access_token).toMatch(/token-[12]/);
    });

    it('should verify cache key generation has no race conditions', async () => {
      const client = new M2MClient(createMockConfig({ cache, scopes: ['api:read', 'api:write'] }));
      const token = createMockToken();

      mockFetchSuccess(mockFetch, token);
      mockFetchSuccess(mockFetch, token);
      mockFetchSuccess(mockFetch, token);

      // Make concurrent requests with same parameters
      await Promise.all([client.getToken(), client.getToken(), client.getToken()]);

      // All requests used the same cache key
      const keys = cache.keys();
      expect(keys.length).toBe(1);
      expect(keys[0]).toBe('m2m:test-m2m-client-id:api:read,api:write:orders-api,users-api');
    });

    it('should handle concurrent requests with different scopes/audience', async () => {
      const client = new M2MClient(createMockConfig({ cache }));

      const token1 = createMockToken({ scope: 'scope1' });
      const token2 = createMockToken({ scope: 'scope2' });
      const token3 = createMockToken({ scope: 'scope3' });

      mockFetchSuccess(mockFetch, token1);
      mockFetchSuccess(mockFetch, token2);
      mockFetchSuccess(mockFetch, token3);

      // Make concurrent requests with different scopes
      await Promise.all([
        client.getToken({ scopes: ['scope1'] }),
        client.getToken({ scopes: ['scope2'] }),
        client.getToken({ scopes: ['scope3'] }),
      ]);

      // Each scope gets its own cache entry
      const keys = cache.keys();
      expect(keys.length).toBe(3);
      expect(keys).toContain('m2m:test-m2m-client-id:scope1:orders-api,users-api');
      expect(keys).toContain('m2m:test-m2m-client-id:scope2:orders-api,users-api');
      expect(keys).toContain('m2m:test-m2m-client-id:scope3:orders-api,users-api');
    });
  });

  describe('Request Deduplication Analysis', () => {
    it('should document that concurrent requests are NOT deduplicated', async () => {
      const client = new M2MClient(createMockConfig({ cache }));
      const token = createMockToken();

      // Track number of actual HTTP calls
      let httpCallCount = 0;
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            httpCallCount++;
            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => token,
                text: async () => JSON.stringify(token),
              });
            }, 50);
          }),
      );

      // Make 5 truly concurrent requests
      const promises = Array.from({ length: 5 }, () => client.getToken());

      await vi.advanceTimersByTimeAsync(60);
      await Promise.all(promises);

      // ACTUAL BEHAVIOR: All 5 requests trigger HTTP calls (no deduplication)
      expect(httpCallCount).toBe(5);
      expect(mockFetch).toHaveBeenCalledTimes(5);

      // This documents that the current implementation does NOT implement
      // request deduplication/coalescing for concurrent getToken() calls
    });

    it('should verify each concurrent request gets independent execution', async () => {
      const client = new M2MClient(createMockConfig({ cache }));

      // Track the timing of each request
      const requestTimings: number[] = [];

      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            requestTimings.push(Date.now());
            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => createMockToken(),
                text: async () => JSON.stringify(createMockToken()),
              });
            }, 50);
          }),
      );

      // Launch concurrent requests
      const promise1 = client.getToken();
      const promise2 = client.getToken();
      const promise3 = client.getToken();

      await vi.advanceTimersByTimeAsync(60);
      await Promise.all([promise1, promise2, promise3]);

      // Each request started independently (not waiting for others)
      expect(requestTimings).toHaveLength(3);

      // All requests started at similar times (concurrent, not sequential)
      const timeDiffs = requestTimings.slice(1).map((t, i) => t - requestTimings[i]);
      for (const diff of timeDiffs) {
        expect(Math.abs(diff)).toBeLessThan(5); // Started within 5ms
      }
    });

    it('should document behavior: last writer wins in cache race', async () => {
      const client = new M2MClient(createMockConfig({ cache }));

      // Make requests return different tokens with different delays
      let callCount = 0;
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            callCount++;
            const currentCall = callCount;
            const delay = currentCall === 1 ? 100 : 50; // First request slower

            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => createMockToken({ access_token: `token-${currentCall}` }),
                text: async () => JSON.stringify(createMockToken({ access_token: `token-${currentCall}` })),
              });
            }, delay);
          }),
      );

      // Make 2 concurrent requests
      const promise1 = client.getToken(); // Slower (100ms)
      const promise2 = client.getToken(); // Faster (50ms)

      // Advance to let faster request complete first
      await vi.advanceTimersByTimeAsync(60);
      await promise2;

      // Then let slower request complete
      await vi.advanceTimersByTimeAsync(50);
      await promise1;

      // Both completed
      expect(mockFetch).toHaveBeenCalledTimes(2);

      // The cached value is from the last writer (token-1, the slower request)
      const cached = await cache.get('m2m:test-m2m-client-id:api:read,api:write:orders-api,users-api');
      expect(cached?.access_token).toBe('token-1');

      // This documents the "last writer wins" behavior in concurrent scenarios
    });
  });

  describe('Error Handling in Concurrent Requests', () => {
    it('should handle when some concurrent requests succeed and others fail', async () => {
      // Use retries: 1 so failures won't retry and succeed
      const client = new M2MClient(createMockConfig({ cache, retries: 1 }));

      let callIndex = 0;
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            const myIndex = callIndex++;
            setTimeout(() => {
              if (myIndex === 1) {
                // Second call (index 1) returns 400 (non-retryable error)
                resolve({
                  ok: false,
                  status: 400,
                  statusText: 'Bad Request',
                  headers: new Headers(),
                  json: async () => ({ error: 'invalid_request', error_description: 'Bad request' }),
                  text: async () => JSON.stringify({ error: 'invalid_request' }),
                });
              } else {
                // Other calls succeed
                resolve({
                  ok: true,
                  status: 200,
                  statusText: 'OK',
                  headers: new Headers(),
                  json: async () => createMockToken({ access_token: `token-${myIndex + 1}` }),
                  text: async () => JSON.stringify(createMockToken()),
                });
              }
            }, 50);
          }),
      );

      // Make 3 concurrent requests - immediately wrap in allSettled to handle failures
      const resultsPromise = Promise.allSettled([client.getToken(), client.getToken(), client.getToken()]);

      await vi.advanceTimersByTimeAsync(60);

      // Collect results - second should fail
      const results = await resultsPromise;

      // Verify one failed and two succeeded
      const succeeded = results.filter((r) => r.status === 'fulfilled');
      const failed = results.filter((r) => r.status === 'rejected');

      expect(succeeded).toHaveLength(2);
      expect(failed).toHaveLength(1);
    });

    it('should verify independent error handling for each concurrent request', async () => {
      const client = new M2MClient(createMockConfig({ cache, retries: 1 }));

      // All requests fail
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({
                ok: false,
                status: 401,
                statusText: 'Unauthorized',
                headers: new Headers(),
                json: async () => ({ error: 'invalid_client', error_description: 'Invalid credentials' }),
                text: async () => JSON.stringify({ error: 'invalid_client' }),
              });
            }, 50);
          }),
      );

      // Make concurrent requests - catch errors to prevent unhandled rejections
      const promise1 = client.getToken().catch((e) => e);
      const promise2 = client.getToken().catch((e) => e);
      const promise3 = client.getToken().catch((e) => e);

      await vi.advanceTimersByTimeAsync(60);

      // All fail independently
      const [error1, error2, error3] = await Promise.all([promise1, promise2, promise3]);

      expect(error1).toBeInstanceOf(Error);
      expect(error1.message).toContain('Invalid credentials');
      expect(error2).toBeInstanceOf(Error);
      expect(error2.message).toContain('Invalid credentials');
      expect(error3).toBeInstanceOf(Error);
      expect(error3.message).toContain('Invalid credentials');

      // All triggered HTTP requests
      expect(mockFetch.mock.calls.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Performance Characteristics', () => {
    it('should measure timing: concurrent requests resolve in parallel', async () => {
      const client = new M2MClient(createMockConfig({ cache }));

      const delay = 100;
      mockFetch.mockImplementation(
        async () =>
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: async () => createMockToken(),
                text: async () => JSON.stringify(createMockToken()),
              });
            }, delay);
          }),
      );

      const startTime = Date.now();

      // Make 3 concurrent requests
      const promises = [client.getToken(), client.getToken(), client.getToken()];

      await vi.advanceTimersByTimeAsync(delay + 10);
      await Promise.all(promises);

      const endTime = Date.now();
      const totalTime = endTime - startTime;

      // All complete in roughly parallel time (not 3x the delay)
      // In fake timers, this should be close to delay, not delay * 3
      expect(totalTime).toBeLessThan(delay * 2);

      // This demonstrates parallel execution despite no deduplication
    });

    it('should verify cache reduces load on subsequent calls after concurrent burst', async () => {
      const client = new M2MClient(createMockConfig({ cache }));
      const token = createMockToken();

      mockFetchSuccess(mockFetch, token);
      mockFetchSuccess(mockFetch, token);
      mockFetchSuccess(mockFetch, token);

      // First burst of concurrent requests
      await Promise.all([client.getToken(), client.getToken(), client.getToken()]);

      expect(mockFetch).toHaveBeenCalledTimes(3);

      // Second burst uses cache (no additional HTTP calls)
      await Promise.all([client.getToken(), client.getToken(), client.getToken()]);

      // Still only 3 calls from first burst
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });
  });
});
