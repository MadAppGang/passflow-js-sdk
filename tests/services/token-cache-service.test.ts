/**
 * Token Cache Service Tests
 *
 * Tests for the TokenCacheService which handles:
 * - Token caching and parsing
 * - Token expiration checking
 * - Automatic token refresh
 * - Visibility/page lifecycle management
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { AuthAPI } from '../../lib/api/auth';
import { TokenCacheService } from '../../lib/services/token-cache-service';
import type { StorageManager } from '../../lib/storage';
import { PassflowEvent, type PassflowStore } from '../../lib/store';
import { AUTH_RESPONSE, COOKIE_MODE_TOKENS, EXPIRED_TOKENS, FULLY_EXPIRED_TOKENS, VALID_TOKENS } from '../helpers/fixtures';
import { createMockAuthApi, createMockPassflowStore, createMockStorageManager } from '../helpers/mocks';

describe('TokenCacheService', () => {
  let tokenCacheService: TokenCacheService;
  let mockStorageManager: ReturnType<typeof createMockStorageManager>;
  let mockAuthApi: ReturnType<typeof createMockAuthApi>;
  let mockStore: ReturnType<typeof createMockPassflowStore>;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();

    mockStorageManager = createMockStorageManager();
    mockAuthApi = createMockAuthApi();
    mockStore = createMockPassflowStore();

    tokenCacheService = new TokenCacheService(
      mockStorageManager as unknown as StorageManager,
      mockAuthApi as unknown as AuthAPI,
      mockStore as unknown as PassflowStore,
    );
  });

  afterEach(() => {
    tokenCacheService.destroy();
    vi.useRealTimers();
  });

  describe('Constructor', () => {
    test('creates service with dependencies', () => {
      expect(tokenCacheService).toBeDefined();
      expect(tokenCacheService.tokensCache).toBeUndefined();
      expect(tokenCacheService.isRefreshing).toBe(false);
      expect(tokenCacheService.tokenExpiredFlag).toBe(false);
    });
  });

  describe('setTokensCache', () => {
    test('sets tokens and parses them', () => {
      tokenCacheService.setTokensCache(VALID_TOKENS);

      expect(tokenCacheService.tokensCache).toEqual(VALID_TOKENS);
      expect(tokenCacheService.parsedTokensCache).toBeDefined();
      expect(tokenCacheService.parsedTokensCache?.access_token).toBeDefined();
    });

    test('sets undefined to clear cache', () => {
      tokenCacheService.setTokensCache(VALID_TOKENS);
      tokenCacheService.setTokensCache(undefined);

      expect(tokenCacheService.tokensCache).toBeUndefined();
      expect(tokenCacheService.parsedTokensCache).toBeUndefined();
    });

    test('parses all token types when present', () => {
      tokenCacheService.setTokensCache(VALID_TOKENS);

      expect(tokenCacheService.parsedTokensCache?.access_token).toBeDefined();
      expect(tokenCacheService.parsedTokensCache?.id_token).toBeDefined();
      expect(tokenCacheService.parsedTokensCache?.refresh_token).toBeDefined();
      expect(tokenCacheService.parsedTokensCache?.scopes).toEqual(VALID_TOKENS.scopes);
    });

    test('handles missing optional tokens', () => {
      const tokensWithoutRefresh = {
        access_token: VALID_TOKENS.access_token,
        scopes: VALID_TOKENS.scopes,
      };

      tokenCacheService.setTokensCache(tokensWithoutRefresh);

      expect(tokenCacheService.parsedTokensCache?.access_token).toBeDefined();
      expect(tokenCacheService.parsedTokensCache?.id_token).toBeUndefined();
      expect(tokenCacheService.parsedTokensCache?.refresh_token).toBeUndefined();
    });
  });

  describe('getTokens', () => {
    test('returns undefined when no tokens cached', () => {
      expect(tokenCacheService.getTokens()).toBeUndefined();
    });

    test('returns cached tokens', () => {
      tokenCacheService.setTokensCache(VALID_TOKENS);

      expect(tokenCacheService.getTokens()).toEqual(VALID_TOKENS);
    });
  });

  describe('getParsedTokens', () => {
    test('returns undefined when no tokens cached', () => {
      expect(tokenCacheService.getParsedTokens()).toBeUndefined();
    });

    test('returns parsed tokens', () => {
      tokenCacheService.setTokensCache(VALID_TOKENS);

      const parsed = tokenCacheService.getParsedTokens();
      expect(parsed).toBeDefined();
      expect(parsed?.access_token?.sub).toBe('user-123');
    });
  });

  describe('isExpired', () => {
    test('returns true when no tokens cached', () => {
      expect(tokenCacheService.isExpired()).toBe(true);
    });

    test('returns false for valid tokens', () => {
      tokenCacheService.setTokensCache(VALID_TOKENS);

      expect(tokenCacheService.isExpired()).toBe(false);
    });

    test('returns true for expired tokens', () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);

      expect(tokenCacheService.isExpired()).toBe(true);
    });
  });

  describe('initialize', () => {
    test('loads tokens from storage and caches them', () => {
      mockStorageManager.getTokens.mockReturnValue(VALID_TOKENS);

      tokenCacheService.initialize();

      expect(mockStorageManager.getTokens).toHaveBeenCalled();
      expect(tokenCacheService.tokensCache).toEqual(VALID_TOKENS);
    });

    test('starts token check with no tokens', () => {
      mockStorageManager.getTokens.mockReturnValue(undefined);

      tokenCacheService.initialize();

      // Should not set tokens but should start checking
      expect(tokenCacheService.tokensCache).toBeUndefined();
    });

    test('sets expired flag for expired tokens in storage', () => {
      mockStorageManager.getTokens.mockReturnValue(EXPIRED_TOKENS);

      tokenCacheService.initialize();

      expect(tokenCacheService.tokenExpiredFlag).toBe(true);
      expect(mockStore.notify).toHaveBeenCalledWith(PassflowEvent.TokenCacheExpired, { isExpired: true });
    });

    test('notifies error on storage exception', () => {
      mockStorageManager.getTokens.mockImplementation(() => {
        throw new Error('Storage error');
      });

      tokenCacheService.initialize();

      expect(mockStore.notify).toHaveBeenCalledWith(PassflowEvent.Error, expect.objectContaining({ message: 'Storage error' }));
      expect(tokenCacheService.tokensCache).toBeUndefined();
    });
  });

  describe('getTokensWithRefresh', () => {
    test('returns undefined when no tokens cached', async () => {
      const result = await tokenCacheService.getTokensWithRefresh();

      expect(result).toBeUndefined();
    });

    test('returns cached tokens when not expired', async () => {
      tokenCacheService.setTokensCache(VALID_TOKENS);

      const result = await tokenCacheService.getTokensWithRefresh();

      expect(result).toEqual(VALID_TOKENS);
      expect(mockAuthApi.refreshToken).not.toHaveBeenCalled();
    });

    test('refreshes expired tokens', async () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockResolvedValue(AUTH_RESPONSE);

      await tokenCacheService.getTokensWithRefresh();

      expect(mockAuthApi.refreshToken).toHaveBeenCalledWith(
        EXPIRED_TOKENS.refresh_token,
        EXPIRED_TOKENS.scopes,
        EXPIRED_TOKENS.access_token,
      );
    });

    test('does not refresh when tokenExpiredFlag is set', async () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);
      tokenCacheService.tokenExpiredFlag = true;

      await tokenCacheService.getTokensWithRefresh();

      expect(mockAuthApi.refreshToken).not.toHaveBeenCalled();
    });

    test('notifies error on refresh failure', async () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValue(new Error('Refresh failed'));

      await tokenCacheService.getTokensWithRefresh();

      expect(mockStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({ message: 'Refresh failed' }),
      );
    });
  });

  describe('Token Check Interval', () => {
    test('startTokenCheck sets up interval', () => {
      tokenCacheService.setTokensCache(VALID_TOKENS);
      tokenCacheService.startTokenCheck();

      // Advance time to trigger interval
      vi.advanceTimersByTime(60000);

      // Since tokens are valid, no expiration should be notified
      expect(mockStore.notify).not.toHaveBeenCalledWith(PassflowEvent.TokenCacheExpired, expect.anything());
    });

    test('startTokenCheck clears previous interval', () => {
      tokenCacheService.startTokenCheck();
      tokenCacheService.startTokenCheck();

      // Should not throw or cause issues
      expect(tokenCacheService).toBeDefined();
    });

    test('does not start check when tokenExpiredFlag is set', () => {
      tokenCacheService.tokenExpiredFlag = true;
      tokenCacheService.setTokensCache(VALID_TOKENS);
      tokenCacheService.startTokenCheck();

      vi.advanceTimersByTime(60000);

      // Should not notify since check shouldn't run
      expect(mockStore.notify).not.toHaveBeenCalledWith(PassflowEvent.TokenCacheExpired, expect.anything());
    });

    test('interval detects token expiration', () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);
      tokenCacheService.startTokenCheck();

      vi.advanceTimersByTime(60000);

      expect(tokenCacheService.tokenExpiredFlag).toBe(true);
      expect(mockStore.notify).toHaveBeenCalledWith(PassflowEvent.TokenCacheExpired, { isExpired: true });
    });
  });

  describe('destroy', () => {
    test('stops token check interval', () => {
      tokenCacheService.startTokenCheck();
      tokenCacheService.destroy();

      // Advance time - should not cause issues after destroy
      vi.advanceTimersByTime(120000);

      expect(tokenCacheService).toBeDefined();
    });
  });

  describe('Refresh Flow', () => {
    test('notifies RefreshStart and Refresh on successful refresh', async () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockResolvedValue(AUTH_RESPONSE);

      await tokenCacheService.getTokensWithRefresh();

      expect(mockStore.notify).toHaveBeenCalledWith(PassflowEvent.RefreshStart, {});
      expect(mockStore.notify).toHaveBeenCalledWith(PassflowEvent.Refresh, expect.objectContaining({ tokens: AUTH_RESPONSE }));
    });

    test('prevents concurrent refresh calls', async () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);

      // Create a slow refresh
      let resolveRefresh: (value: unknown) => void;
      const refreshPromise = new Promise((resolve) => {
        resolveRefresh = resolve;
      });
      mockAuthApi.refreshToken.mockReturnValue(refreshPromise);

      // Start first refresh
      const refresh1 = tokenCacheService.getTokensWithRefresh();

      // Immediately try second refresh
      const refresh2 = tokenCacheService.getTokensWithRefresh();

      // Resolve the refresh
      resolveRefresh?.(AUTH_RESPONSE);

      await Promise.all([refresh1, refresh2]);

      // Should only call refreshToken once
      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(1);
    });

    test('resets tokenExpiredFlag on successful refresh', async () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);
      tokenCacheService.tokenExpiredFlag = false; // Ensure not set before
      mockAuthApi.refreshToken.mockResolvedValue(AUTH_RESPONSE);

      await tokenCacheService.getTokensWithRefresh();

      expect(tokenCacheService.tokenExpiredFlag).toBe(false);
      expect(mockStore.notify).toHaveBeenCalledWith(PassflowEvent.TokenCacheExpired, { isExpired: false });
    });

    test('clears cache on refresh error', async () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValue(new Error('Network error'));

      await tokenCacheService.getTokensWithRefresh();

      expect(tokenCacheService.tokensCache).toBeUndefined();
    });

    test('resets isRefreshing flag even on error', async () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValue(new Error('Network error'));

      await tokenCacheService.getTokensWithRefresh();

      expect(tokenCacheService.isRefreshing).toBe(false);
    });
  });

  describe('Cookie Mode Support', () => {
    test('setTokensCache handles tokens with only ID token (cookie mode)', () => {
      tokenCacheService.setTokensCache(COOKIE_MODE_TOKENS);

      expect(tokenCacheService.tokensCache).toEqual(COOKIE_MODE_TOKENS);
      expect(tokenCacheService.parsedTokensCache).toBeDefined();
      expect(tokenCacheService.parsedTokensCache?.access_token).toBeUndefined();
      expect(tokenCacheService.parsedTokensCache?.refresh_token).toBeUndefined();
      expect(tokenCacheService.parsedTokensCache?.id_token).toBeDefined();
    });

    test('getParsedTokens returns partial data in cookie mode', () => {
      tokenCacheService.setTokensCache(COOKIE_MODE_TOKENS);

      const parsed = tokenCacheService.getParsedTokens();
      expect(parsed).toBeDefined();
      expect(parsed?.access_token).toBeUndefined();
      expect(parsed?.id_token).toBeDefined();
      expect(parsed?.id_token?.email).toBe('test@example.com');
    });

    test('isExpired returns false when no access_token (cookie mode)', () => {
      tokenCacheService.setTokensCache(COOKIE_MODE_TOKENS);

      // In cookie mode, we cannot check expiry client-side
      // Return false and let server validate via 401
      expect(tokenCacheService.isExpired()).toBe(false);
    });

    test('initialize caches tokens when only ID token present (cookie mode)', () => {
      mockStorageManager.getTokens.mockReturnValue(COOKIE_MODE_TOKENS);

      tokenCacheService.initialize();

      expect(tokenCacheService.tokensCache).toEqual(COOKIE_MODE_TOKENS);
      expect(tokenCacheService.parsedTokensCache?.id_token).toBeDefined();
      expect(tokenCacheService.tokenExpiredFlag).toBe(false);
    });

    test('getTokensWithRefresh returns tokens without refresh in cookie mode', async () => {
      tokenCacheService.setTokensCache(COOKIE_MODE_TOKENS);

      const result = await tokenCacheService.getTokensWithRefresh();

      // Should return tokens without attempting refresh
      // (server handles refresh via 401 and axios interceptor)
      expect(result).toEqual(COOKIE_MODE_TOKENS);
      expect(mockAuthApi.refreshToken).not.toHaveBeenCalled();
    });

    test('parses all available tokens in partial cookie mode response', () => {
      const partialTokens = {
        id_token: COOKIE_MODE_TOKENS.id_token,
        access_token: VALID_TOKENS.access_token, // Server may still send access_token
        scopes: COOKIE_MODE_TOKENS.scopes,
      };

      tokenCacheService.setTokensCache(partialTokens);

      expect(tokenCacheService.parsedTokensCache?.access_token).toBeDefined();
      expect(tokenCacheService.parsedTokensCache?.id_token).toBeDefined();
      expect(tokenCacheService.parsedTokensCache?.refresh_token).toBeUndefined();
    });
  });
});
