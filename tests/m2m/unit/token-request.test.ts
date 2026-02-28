/**
 * Unit tests for M2MClient.getToken() method
 */

import { type Mock, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { M2MClient } from '../../../lib/m2m/client';
import { FakeCache } from '../utils/fake-cache';
import {
  TEST_AUDIENCE,
  TEST_CLIENT_ID,
  TEST_CLIENT_SECRET,
  TEST_SCOPES,
  TEST_URL,
  createMockConfig,
  createMockToken,
} from '../utils/fixtures';
import { getLastFetchBody, getLastFetchHeaders, mockFetchSuccess, resetFetchMock, setupFetchMock } from '../utils/mock-fetch';

describe('M2MClient.getToken()', () => {
  let mockFetch: Mock;
  let client: M2MClient;
  let cache: FakeCache;

  beforeEach(() => {
    mockFetch = setupFetchMock();
    cache = new FakeCache();
  });

  afterEach(() => {
    resetFetchMock(mockFetch);
    cache.clear();
  });

  describe('Basic Token Request', () => {
    it('should return M2MTokenResponse on successful request', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(createMockConfig({ cache }));
      const token = await client.getToken();

      expect(token).toMatchObject({
        access_token: expect.any(String),
        token_type: 'Bearer',
        expires_in: expect.any(Number),
      });
    });

    it('should send request to correct endpoint (/oauth2/token)', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(createMockConfig({ cache }));
      await client.getToken();

      expect(mockFetch).toHaveBeenCalledWith(
        `${TEST_URL}/oauth2/token`,
        expect.objectContaining({
          method: 'POST',
        }),
      );
    });

    it('should use POST method', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(createMockConfig({ cache }));
      await client.getToken();

      const [, options] = mockFetch.mock.calls[0] as [string, RequestInit];
      expect(options.method).toBe('POST');
    });

    it('should use application/x-www-form-urlencoded Content-Type', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(createMockConfig({ cache }));
      await client.getToken();

      const headers = getLastFetchHeaders(mockFetch);
      expect(headers?.['Content-Type']).toBe('application/x-www-form-urlencoded');
    });

    it('should include grant_type=client_credentials in request body', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(createMockConfig({ cache }));
      await client.getToken();

      const body = getLastFetchBody(mockFetch);
      expect(body).toContain('grant_type=client_credentials');
    });

    it('should include client_id and client_secret in request body', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(createMockConfig({ cache }));
      await client.getToken();

      const body = getLastFetchBody(mockFetch);
      expect(body).toContain(`client_id=${TEST_CLIENT_ID}`);
      expect(body).toContain(`client_secret=${TEST_CLIENT_SECRET}`);
    });

    it('should add issued_at timestamp to response', async () => {
      const mockToken = createMockToken();
      delete mockToken.issued_at; // Remove issued_at from mock response
      mockFetchSuccess(mockFetch, mockToken);

      const beforeRequest = Math.floor(Date.now() / 1000);
      client = new M2MClient(createMockConfig({ cache }));
      const token = await client.getToken();
      const afterRequest = Math.floor(Date.now() / 1000);

      expect(token.issued_at).toBeDefined();
      expect(token.issued_at).toBeGreaterThanOrEqual(beforeRequest);
      expect(token.issued_at).toBeLessThanOrEqual(afterRequest);
    });
  });

  describe('Request with Scopes', () => {
    it('should send scopes as space-separated string', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(
        createMockConfig({
          cache,
          scopes: ['users:read', 'users:write', 'orders:read'],
        }),
      );
      await client.getToken();

      const body = getLastFetchBody(mockFetch);
      expect(body).toContain('scope=');
      expect(body).toContain('users:read');
      expect(body).toContain('users:write');
      expect(body).toContain('orders:read');
    });

    it('should not include scope parameter when scopes array is empty', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(
        createMockConfig({
          cache,
          scopes: [],
        }),
      );
      await client.getToken();

      const body = getLastFetchBody(mockFetch);
      expect(body).not.toContain('scope=');
    });

    it('should not include scope parameter when scopes is undefined', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(
        createMockConfig({
          cache,
          scopes: undefined,
        }),
      );
      await client.getToken();

      const body = getLastFetchBody(mockFetch);
      expect(body).not.toContain('scope=');
    });

    it('should correctly join multiple scopes', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      const scopes = ['api:read', 'api:write', 'admin:users'];
      client = new M2MClient(
        createMockConfig({
          cache,
          scopes,
        }),
      );
      await client.getToken();

      const body = getLastFetchBody(mockFetch);
      const decodedBody = decodeURIComponent(body || '');
      expect(decodedBody).toContain(`scope=${scopes.join(' ')}`);
    });
  });

  describe('Request with Audience', () => {
    it('should send audience as space-separated string', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(
        createMockConfig({
          cache,
          audience: ['users-api', 'orders-api'],
        }),
      );
      await client.getToken();

      const body = getLastFetchBody(mockFetch);
      expect(body).toContain('audience=');
      expect(body).toContain('users-api');
      expect(body).toContain('orders-api');
    });

    it('should not include audience parameter when audience array is empty', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(
        createMockConfig({
          cache,
          audience: [],
        }),
      );
      await client.getToken();

      const body = getLastFetchBody(mockFetch);
      expect(body).not.toContain('audience=');
    });

    it('should not include audience parameter when audience is undefined', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(
        createMockConfig({
          cache,
          audience: undefined,
        }),
      );
      await client.getToken();

      const body = getLastFetchBody(mockFetch);
      expect(body).not.toContain('audience=');
    });

    it('should correctly join multiple audiences', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      const audiences = ['api-service', 'users-service', 'orders-service'];
      client = new M2MClient(
        createMockConfig({
          cache,
          audience: audiences,
        }),
      );
      await client.getToken();

      const body = getLastFetchBody(mockFetch);
      const decodedBody = decodeURIComponent(body || '');
      expect(decodedBody).toContain(`audience=${audiences.join(' ')}`);
    });
  });

  describe('Token Request Options', () => {
    it('should override default scopes when custom scopes provided', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(
        createMockConfig({
          cache,
          scopes: ['default:read', 'default:write'],
        }),
      );

      const customScopes = ['custom:read', 'custom:admin'];
      await client.getToken({ scopes: customScopes });

      const body = getLastFetchBody(mockFetch);
      const decodedBody = decodeURIComponent(body || '');
      expect(decodedBody).toContain(`scope=${customScopes.join(' ')}`);
      expect(decodedBody).not.toContain('default:read');
    });

    it('should override default audience when custom audience provided', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(
        createMockConfig({
          cache,
          audience: ['default-api'],
        }),
      );

      const customAudience = ['custom-api', 'special-service'];
      await client.getToken({ audience: customAudience });

      const body = getLastFetchBody(mockFetch);
      const decodedBody = decodeURIComponent(body || '');
      expect(decodedBody).toContain(`audience=${customAudience.join(' ')}`);
      expect(decodedBody).not.toContain('default-api');
    });

    it('should bypass cache when forceRefresh is true', async () => {
      const firstToken = createMockToken({ access_token: 'first-token' });
      const secondToken = createMockToken({ access_token: 'second-token' });

      mockFetchSuccess(mockFetch, firstToken);
      mockFetchSuccess(mockFetch, secondToken);

      client = new M2MClient(createMockConfig({ cache }));

      // First request - should fetch and cache
      const token1 = await client.getToken();
      expect(token1.access_token).toBe('first-token');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second request without forceRefresh - should use cache
      const token2 = await client.getToken();
      expect(token2.access_token).toBe('first-token');
      expect(mockFetch).toHaveBeenCalledTimes(1); // Still 1 call

      // Third request with forceRefresh - should fetch new token
      const token3 = await client.getToken({ forceRefresh: true });
      expect(token3.access_token).toBe('second-token');
      expect(mockFetch).toHaveBeenCalledTimes(2); // Now 2 calls
    });

    it('should use cache on subsequent calls without forceRefresh', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(createMockConfig({ cache }));

      // First call - should fetch
      await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second call - should use cache
      await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(1); // Still 1

      // Third call - should use cache
      await client.getToken();
      expect(mockFetch).toHaveBeenCalledTimes(1); // Still 1
    });

    it('should combine custom scopes and audience in single request', async () => {
      const mockToken = createMockToken();
      mockFetchSuccess(mockFetch, mockToken);

      client = new M2MClient(createMockConfig({ cache }));

      const customScopes = ['read:all', 'write:all'];
      const customAudience = ['api-1', 'api-2'];

      await client.getToken({
        scopes: customScopes,
        audience: customAudience,
      });

      const body = getLastFetchBody(mockFetch);
      const decodedBody = decodeURIComponent(body || '');

      expect(decodedBody).toContain(`scope=${customScopes.join(' ')}`);
      expect(decodedBody).toContain(`audience=${customAudience.join(' ')}`);
    });
  });
});
