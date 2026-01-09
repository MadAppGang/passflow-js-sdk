/**
 * M2M Client Caching Tests
 *
 * Tests for token caching behavior including basic caching, cache keys,
 * TTL edge cases, and custom cache implementations.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { M2MClient } from '../../../lib/m2m';
import { FakeCache } from '../utils/fake-cache';
import { createMockConfig, createMockToken } from '../utils/fixtures';
import { mockFetchSuccess, setupFetchMock } from '../utils/mock-fetch';

describe('M2MClient - Caching', () => {
  let mockFetch: ReturnType<typeof setupFetchMock>;

  beforeEach(() => {
    mockFetch = setupFetchMock();
    vi.clearAllMocks();
  });

  describe('Basic Caching', () => {
    it('should cache token after successful request', async () => {
      const client = new M2MClient(createMockConfig());
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      const token = await client.getToken();

      expect(token).toEqual(mockToken);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Verify token is cached
      const cachedToken = client.getCachedToken();
      expect(cachedToken).toEqual(mockToken);
    });

    it('should return cached token on subsequent calls without HTTP request', async () => {
      const client = new M2MClient(createMockConfig());
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      // First call - fetches from server
      const token1 = await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second call - should use cache
      const token2 = await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(1); // Still 1
      expect(token2).toEqual(token1);
    });

    it('should bypass cache with forceRefresh and make new request', async () => {
      const client = new M2MClient(createMockConfig());
      const mockToken1 = createMockToken({ access_token: 'token1' });
      const mockToken2 = createMockToken({ access_token: 'token2' });

      mockFetchSuccess(mockFetch, mockToken1);
      mockFetchSuccess(mockFetch, mockToken2);

      // First call
      const token1 = await client.getToken();
      expect(token1.access_token).toBe('token1');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Force refresh
      const token2 = await client.getToken({ forceRefresh: true });
      expect(token2.access_token).toBe('token2');
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should remove token from cache when clearCache() is called', async () => {
      const client = new M2MClient(createMockConfig());
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      // Get token and verify it's cached
      await client.getToken();
      expect(client.getCachedToken()).toEqual(mockToken);

      // Clear cache
      client.clearCache();

      // Verify cache is empty
      expect(client.getCachedToken()).toBeNull();
    });

    it('should return cached token via getCachedToken()', async () => {
      const client = new M2MClient(createMockConfig());
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      // Initially no cached token
      expect(client.getCachedToken()).toBeNull();

      // Get token
      await client.getToken();

      // Now should return cached token
      const cached = client.getCachedToken();
      expect(cached).toEqual(mockToken);
    });

    it('should return null from getCachedToken() when no token cached', () => {
      const client = new M2MClient(createMockConfig());

      // No token fetched yet
      const cached = client.getCachedToken();
      expect(cached).toBeNull();
    });
  });

  describe('Cache Key', () => {
    it('should include clientId in cache key', async () => {
      const cache = new FakeCache();
      const client1 = new M2MClient(createMockConfig({ clientId: 'client1', cache }));
      const client2 = new M2MClient(createMockConfig({ clientId: 'client2', cache }));

      const mockToken1 = createMockToken({ access_token: 'token1' });
      const mockToken2 = createMockToken({ access_token: 'token2' });

      mockFetchSuccess(mockFetch, mockToken1);
      mockFetchSuccess(mockFetch, mockToken2);

      await client1.getToken();
      await client2.getToken();

      // Both tokens should be cached with different keys
      expect(cache.size()).toBe(2);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should change cache key with different scopes', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ scopes: ['api:read'], cache }));

      const mockToken1 = createMockToken({ access_token: 'token1' });
      const mockToken2 = createMockToken({ access_token: 'token2' });

      mockFetchSuccess(mockFetch, mockToken1);
      mockFetchSuccess(mockFetch, mockToken2);

      // Get token with default scopes
      await client.getToken();

      // Get token with different scopes
      await client.getToken({ scopes: ['api:write'] });

      // Should have 2 different cache entries
      expect(cache.size()).toBe(2);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should change cache key with different audiences', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ audience: ['api1'], cache }));

      const mockToken1 = createMockToken({ access_token: 'token1' });
      const mockToken2 = createMockToken({ access_token: 'token2' });

      mockFetchSuccess(mockFetch, mockToken1);
      mockFetchSuccess(mockFetch, mockToken2);

      // Get token with default audience
      await client.getToken();

      // Get token with different audience
      await client.getToken({ audience: ['api2'] });

      // Should have 2 different cache entries
      expect(cache.size()).toBe(2);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should sort scopes in cache key for consistency', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);
      mockFetchSuccess(mockFetch, mockToken);

      // Request with scopes in different order
      await client.getToken({ scopes: ['write', 'read'] });
      const key1 = cache.getLastKey();

      cache.clear();
      mockFetch.mockClear();
      mockFetchSuccess(mockFetch, mockToken);

      await client.getToken({ scopes: ['read', 'write'] });
      const key2 = cache.getLastKey();

      // Keys should be identical (scopes are sorted)
      expect(key1).toBe(key2);
    });

    it('should sort audiences in cache key for consistency', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);
      mockFetchSuccess(mockFetch, mockToken);

      // Request with audiences in different order
      await client.getToken({ audience: ['api2', 'api1'] });
      const key1 = cache.getLastKey();

      cache.clear();
      mockFetch.mockClear();
      mockFetchSuccess(mockFetch, mockToken);

      await client.getToken({ audience: ['api1', 'api2'] });
      const key2 = cache.getLastKey();

      // Keys should be identical (audiences are sorted)
      expect(key1).toBe(key2);
    });
  });

  describe('TTL Edge Cases (CRITICAL)', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should match token expires_in exactly for TTL calculation', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      const mockToken = createMockToken({ expires_in: 3600 });
      mockFetchSuccess(mockFetch, mockToken);

      await client.getToken();

      // Check TTL stored in cache
      const cacheKey = cache.getLastKey();
      const ttl = cache.getTTL(cacheKey!);

      // TTL should match expires_in (with small tolerance for execution time)
      expect(ttl).toBeGreaterThanOrEqual(3599);
      expect(ttl).toBeLessThanOrEqual(3600);
    });

    it('should handle cache expiration at boundary (token just expired)', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      const mockToken = createMockToken({ expires_in: 10 }); // 10 seconds
      mockFetchSuccess(mockFetch, mockToken);
      mockFetchSuccess(mockFetch, mockToken);

      // Get token
      await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Advance time to exactly when token expires
      vi.advanceTimersByTime(10000);

      // Should request new token (cache expired)
      await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should return null after TTL expires', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      const mockToken = createMockToken({ expires_in: 5 }); // 5 seconds
      mockFetchSuccess(mockFetch, mockToken);

      await client.getToken();

      // Advance time past expiration
      vi.advanceTimersByTime(6000);

      // Cache should return null
      const cacheKey = cache.getLastKey();
      const cached = await cache.get(cacheKey!);
      expect(cached).toBeNull();
    });

    it('should handle TTL edge case: expires_in = 0 (immediate expiry)', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      const mockToken = createMockToken({ expires_in: 0 });
      mockFetchSuccess(mockFetch, mockToken);
      mockFetchSuccess(mockFetch, mockToken);

      // Get token
      await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Token expires immediately, next call should fetch new one
      await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should use Date.now() as fallback when issued_at missing from response', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      // Mock token without issued_at
      const mockToken = createMockToken({ expires_in: 3600 });
      delete mockToken.issued_at;

      mockFetchSuccess(mockFetch, mockToken);

      const before = Math.floor(Date.now() / 1000);
      const token = await client.getToken();
      const after = Math.floor(Date.now() / 1000);

      // issued_at should be added by client (around current time)
      expect(token.issued_at).toBeDefined();
      expect(token.issued_at).toBeGreaterThanOrEqual(before);
      expect(token.issued_at).toBeLessThanOrEqual(after);
    });

    it('should NOT return expired tokens from cache', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      const mockToken = createMockToken({ expires_in: 5 }); // 5 seconds
      mockFetchSuccess(mockFetch, mockToken);
      mockFetchSuccess(mockFetch, mockToken);

      // Get token
      await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Advance time past expiration
      vi.advanceTimersByTime(6000);

      // Should fetch new token (cache expired)
      await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Custom Cache', () => {
    it('should call custom cache.get() on getToken()', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      expect(cache.getCallCount()).toBe(0);

      await client.getToken();

      // Should have called cache.get() at least once
      expect(cache.getCallCount()).toBeGreaterThanOrEqual(1);
    });

    it('should call custom cache.set() with correct TTL', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      const mockToken = createMockToken({ expires_in: 7200 });
      mockFetchSuccess(mockFetch, mockToken);

      expect(cache.setCallCount()).toBe(0);

      await client.getToken();

      // Should have called cache.set() once
      expect(cache.setCallCount()).toBe(1);

      // Verify TTL was set correctly
      const cacheKey = cache.getLastKey();
      const ttl = cache.getTTL(cacheKey!);
      expect(ttl).toBeGreaterThanOrEqual(7199);
      expect(ttl).toBeLessThanOrEqual(7200);
    });

    it('should call custom cache.delete() on clearCache()', async () => {
      const cache = new FakeCache();
      const client = new M2MClient(createMockConfig({ cache }));

      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      await client.getToken();
      expect(cache.deleteCallCount()).toBe(0);

      client.clearCache();

      // Should have called cache.delete() once
      expect(cache.deleteCallCount()).toBe(1);
    });
  });
});
