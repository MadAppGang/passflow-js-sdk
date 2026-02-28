/**
 * M2MClient.getValidToken() Auto-Refresh Tests
 *
 * Tests the auto-refresh behavior of getValidToken() including:
 * - Basic token caching and validation
 * - Auto-refresh threshold behavior
 * - Edge cases around threshold boundaries
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { M2MClient } from '../../../lib/m2m';
import { FakeCache } from '../utils/fake-cache';
import { createMockConfig, createMockToken } from '../utils/fixtures';
import { mockFetchSuccess, setupFetchMock } from '../utils/mock-fetch';

describe('M2MClient.getValidToken() - Auto-Refresh', () => {
  let mockFetch: ReturnType<typeof setupFetchMock>;
  let fakeCache: FakeCache;

  beforeEach(() => {
    vi.useFakeTimers();
    mockFetch = setupFetchMock();
    fakeCache = new FakeCache();
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  describe('Basic getValidToken()', () => {
    it('returns cached token if valid and not near expiry', async () => {
      // Setup: Token expires in 3600s, threshold is 30s
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          refreshThreshold: 30,
          cache: fakeCache,
        }),
      );

      // Cache a valid token that expires in 3600 seconds
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: Math.floor(Date.now() / 1000) });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Act
      const token = await client.getValidToken();

      // Assert: Should return cached token without fetch
      expect(token).toBe(cachedToken);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('returns cached token if autoRefresh is false', async () => {
      // Setup: autoRefresh=false, token expiring soon
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: false,
          refreshThreshold: 30,
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 20 seconds (within threshold)
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time to 3590 seconds (20 seconds before expiry, within 30s threshold)
      vi.advanceTimersByTime(3590 * 1000);

      // Act
      const token = await client.getValidToken();

      // Assert: Should return cached token even though it's within threshold
      expect(token).toBe(cachedToken);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('requests new token if no cached token', async () => {
      // Setup
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          cache: fakeCache,
        }),
      );

      const newToken = createMockToken();
      mockFetchSuccess(mockFetch, newToken);

      // Act
      const token = await client.getValidToken();

      // Assert: Should fetch new token
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(token.access_token).toBe(newToken.access_token);
    });

    it('requests new token if cached token is expired', async () => {
      // Setup
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          cache: fakeCache,
        }),
      );

      // Cache an expired token
      const issuedAt = Math.floor(Date.now() / 1000) - 7200; // 2 hours ago
      const expiredToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, expiredToken, 3600);

      // Advance time to ensure it's expired
      vi.advanceTimersByTime(3700 * 1000);

      const newToken = createMockToken();
      mockFetchSuccess(mockFetch, newToken);

      // Act
      const token = await client.getValidToken();

      // Assert: Should fetch new token
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(token.access_token).toBe(newToken.access_token);
    });
  });

  describe('Auto-Refresh Threshold', () => {
    it('refreshes token within threshold when autoRefresh=true', async () => {
      // Setup: 30s threshold
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          refreshThreshold: 30,
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time to 3585 seconds (15 seconds before expiry, within 30s threshold)
      vi.advanceTimersByTime(3585 * 1000);

      const newToken = createMockToken();
      mockFetchSuccess(mockFetch, newToken);

      // Act
      const token = await client.getValidToken();

      // Assert: Should refresh token
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(token.access_token).toBe(newToken.access_token);
    });

    it('does NOT refresh within threshold when autoRefresh=false', async () => {
      // Setup: autoRefresh=false
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: false,
          refreshThreshold: 30,
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time to 3585 seconds (15 seconds before expiry, within 30s threshold)
      vi.advanceTimersByTime(3585 * 1000);

      // Act
      const token = await client.getValidToken();

      // Assert: Should NOT refresh, return cached token
      expect(mockFetch).not.toHaveBeenCalled();
      expect(token).toBe(cachedToken);
    });

    it('respects default refreshThreshold (30 seconds)', async () => {
      // Setup: Use default threshold (30s)
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          // refreshThreshold not specified, should default to 30
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time to 3580 seconds (20 seconds before expiry, within 30s default threshold)
      vi.advanceTimersByTime(3580 * 1000);

      const newToken = createMockToken();
      mockFetchSuccess(mockFetch, newToken);

      // Act
      const token = await client.getValidToken();

      // Assert: Should refresh token with default threshold
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(token.access_token).toBe(newToken.access_token);
    });

    it('respects custom refreshThreshold value', async () => {
      // Setup: Custom 120s threshold
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          refreshThreshold: 120, // 2 minutes
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time to 3510 seconds (90 seconds before expiry, within 120s threshold)
      vi.advanceTimersByTime(3510 * 1000);

      const newToken = createMockToken();
      mockFetchSuccess(mockFetch, newToken);

      // Act
      const token = await client.getValidToken();

      // Assert: Should refresh token with custom threshold
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(token.access_token).toBe(newToken.access_token);
    });
  });

  describe('Edge Cases', () => {
    it('handles token exactly at threshold boundary', async () => {
      // Setup: 30s threshold
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          refreshThreshold: 30,
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time to exactly 3570 seconds (exactly 30 seconds before expiry)
      vi.advanceTimersByTime(3570 * 1000);

      const newToken = createMockToken();
      mockFetchSuccess(mockFetch, newToken);

      // Act
      const token = await client.getValidToken();

      // Assert: Should refresh token (at boundary, isTokenExpired returns true)
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(token.access_token).toBe(newToken.access_token);
    });

    it('refreshes token just inside threshold (should refresh)', async () => {
      // Setup: 30s threshold
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          refreshThreshold: 30,
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time to 3571 seconds (29 seconds before expiry, just inside 30s threshold)
      vi.advanceTimersByTime(3571 * 1000);

      const newToken = createMockToken();
      mockFetchSuccess(mockFetch, newToken);

      // Act
      const token = await client.getValidToken();

      // Assert: Should refresh token
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(token.access_token).toBe(newToken.access_token);
    });

    it('does NOT refresh token just outside threshold (should NOT refresh)', async () => {
      // Setup: 30s threshold
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          refreshThreshold: 30,
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time to 3569 seconds (31 seconds before expiry, just outside 30s threshold)
      vi.advanceTimersByTime(3569 * 1000);

      // Act
      const token = await client.getValidToken();

      // Assert: Should NOT refresh, return cached token
      expect(mockFetch).not.toHaveBeenCalled();
      expect(token).toBe(cachedToken);
    });

    it('handles autoRefresh with refreshThreshold=0', async () => {
      // Setup: 0s threshold (only refresh when actually expired)
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          refreshThreshold: 0,
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time to 3599 seconds (1 second before expiry)
      vi.advanceTimersByTime(3599 * 1000);

      // Act
      const token = await client.getValidToken();

      // Assert: Should NOT refresh (threshold is 0, token not yet expired)
      expect(mockFetch).not.toHaveBeenCalled();
      expect(token).toBe(cachedToken);

      // Now advance to exactly expiry time
      vi.advanceTimersByTime(1 * 1000);

      const newToken = createMockToken();
      mockFetchSuccess(mockFetch, newToken);

      // Act again
      const refreshedToken = await client.getValidToken();

      // Assert: Should refresh now (token is expired)
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(refreshedToken.access_token).toBe(newToken.access_token);
    });

    it('does NOT refresh with autoRefresh=false even if threshold is 0', async () => {
      // Setup: autoRefresh=false, threshold=0
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: false,
          refreshThreshold: 0,
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time to 3599 seconds (1 second before expiry)
      vi.advanceTimersByTime(3599 * 1000);

      // Act
      const token = await client.getValidToken();

      // Assert: Should return cached token
      expect(mockFetch).not.toHaveBeenCalled();
      expect(token).toBe(cachedToken);
    });

    it('fetches new token when cached token expired even with autoRefresh=false', async () => {
      // Setup: autoRefresh=false
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: false,
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Advance time beyond expiry (3601 seconds)
      vi.advanceTimersByTime(3601 * 1000);

      const newToken = createMockToken();
      mockFetchSuccess(mockFetch, newToken);

      // Act
      const token = await client.getValidToken();

      // Assert: Should fetch new token (expired)
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(token.access_token).toBe(newToken.access_token);
    });
  });

  describe('Time Manipulation Edge Cases', () => {
    it('handles token issued in the past correctly', async () => {
      // Setup
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          refreshThreshold: 30,
          cache: fakeCache,
        }),
      );

      // Cache a token issued 1800 seconds ago with 3600s expiry (1800s remaining)
      const issuedAt = Math.floor(Date.now() / 1000) - 1800;
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Act
      const token = await client.getValidToken();

      // Assert: Should return cached token (still 1800s remaining, well outside 30s threshold)
      expect(mockFetch).not.toHaveBeenCalled();
      expect(token).toBe(cachedToken);

      // Now advance to within threshold (1781 seconds, leaving 19s remaining)
      vi.advanceTimersByTime(1781 * 1000);

      const newToken = createMockToken();
      mockFetchSuccess(mockFetch, newToken);

      // Act again
      const refreshedToken = await client.getValidToken();

      // Assert: Should refresh now (within 30s threshold)
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(refreshedToken.access_token).toBe(newToken.access_token);
    });

    it('handles multiple calls without refreshing unnecessarily', async () => {
      // Setup
      const client = new M2MClient(
        createMockConfig({
          autoRefresh: true,
          refreshThreshold: 30,
          cache: fakeCache,
        }),
      );

      // Cache a token that expires in 3600 seconds
      const issuedAt = Math.floor(Date.now() / 1000);
      const cachedToken = createMockToken({ expires_in: 3600, issued_at: issuedAt });
      const cacheKey = `m2m:${client.clientId}:api:read,api:write:orders-api,users-api`;
      fakeCache.setTokenDirectly(cacheKey, cachedToken, 3600);

      // Act: Call getValidToken() multiple times
      const token1 = await client.getValidToken();
      const token2 = await client.getValidToken();
      const token3 = await client.getValidToken();

      // Assert: All should return cached token, no fetches
      expect(token1).toBe(cachedToken);
      expect(token2).toBe(cachedToken);
      expect(token3).toBe(cachedToken);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });
});
