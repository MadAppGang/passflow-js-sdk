/**
 * Token Cache Service Tests
 *
 * Tests for the TokenCacheService which handles:
 * - Token caching and parsing
 * - Token expiration checking
 * - Automatic token refresh (through the attached refresh controller, PFL-792)
 * - Visibility/page lifecycle management
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { AuthAPI } from '../../lib/api/auth';
import { PassflowError } from '../../lib/api/model';
import type { DeviceService } from '../../lib/device';
import type { PlatformAdapter } from '../../lib/platform';
import { localCoordination } from '../../lib/refresh/resolve';
import { AuthService } from '../../lib/services/auth-service';
import { TokenCacheService } from '../../lib/services/token-cache-service';
import type { StorageManager } from '../../lib/storage';
import { PassflowEvent, type PassflowStore } from '../../lib/store';
import type { Tokens } from '../../lib/types';
import { COOKIE_MODE_TOKENS, EXPIRED_TOKENS, VALID_ACCESS_TOKEN, VALID_ID_TOKEN, VALID_TOKENS } from '../helpers/fixtures';
import { createMockPlatform } from '../helpers/mock-platform';
import { createMockAuthApi, createMockPassflowStore, createMockStorageManager } from '../helpers/mocks';
import { jwt } from '../refresh/jwt';

/** The next refresh token of EXPIRED_TOKENS' session: same user, a later `iat`. */
const ROTATED: Tokens = {
  access_token: VALID_ACCESS_TOKEN,
  refresh_token: jwt({ sub: 'user-123', iat: 4_000_000_000, jti: 'refresh-rotated', type: 'refresh' }),
  id_token: VALID_ID_TOKEN,
  scopes: EXPIRED_TOKENS.scopes,
};

/** An authentication failure of /auth/refresh (architecture §2.6 row 2): a strike. */
const AUTH_FAILURE = () =>
  new PassflowError({
    id: 'error.token.invalid.error',
    message: 'token is invalid',
    status: 400,
    location: '/auth/refresh',
    time: '2026-11-03T00:00:00Z',
  });

/** The first and second retry delays (1 s and 3 s) plus their maximum jitter (20 %). */
const RETRY_1_MAX_MS = 1_200;
const RETRY_2_MAX_MS = 3_600;

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

  let authService: AuthService | undefined;

  afterEach(() => {
    authService?.refresh.dispose();
    authService = undefined;
    tokenCacheService.destroy();
    vi.useRealTimers();
  });

  /** Payloads of one event, in order. */
  const notified = (event: PassflowEvent) =>
    mockStore.notify.mock.calls.filter((call) => call[0] === event).map((call) => call[1]);

  /**
   * Wires a refresh controller the way Passflow does: a real AuthService over the same storage,
   * store and AuthAPI double, attached to the service under test. Storage holds `tokens` (an
   * in-memory backing behind the storage mock) and the cache is set to them.
   */
  const attachController = (tokens: Tokens) => {
    let stored: Tokens | undefined = { ...tokens };
    mockStorageManager.getTokens.mockImplementation(() => stored && { ...stored });
    mockStorageManager.saveTokens.mockImplementation((next: Tokens) => {
      stored = { ...next };
    });
    mockStorageManager.deleteTokens.mockImplementation(() => {
      stored = undefined;
    });
    authService = new AuthService(
      mockAuthApi as unknown as AuthAPI,
      { getDeviceId: () => 'mock-device-id' } as unknown as DeviceService,
      mockStorageManager as unknown as StorageManager,
      mockStore as unknown as PassflowStore,
      tokenCacheService,
      ['id', 'offline'],
      false,
      'https://auth.example.com',
      {},
      'app-1',
      undefined,
      createMockPlatform() as unknown as PlatformAdapter,
      undefined,
      { coordination: localCoordination() },
    );
    tokenCacheService.attachRefreshController(authService.refresh);
    tokenCacheService.setTokensCache({ ...tokens });
    return { stored: () => stored };
  };

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

    // PFL-792 §9.4: was "the cached tokens are sent directly to authApi"; the attached
    // controller sends the STORED tokens and saves the answer.
    test('refreshes expired tokens through the attached controller, sending the stored tokens', async () => {
      const { stored } = attachController(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockResolvedValue(ROTATED);

      const result = await tokenCacheService.getTokensWithRefresh();

      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(1);
      expect(mockAuthApi.refreshToken).toHaveBeenCalledWith(
        EXPIRED_TOKENS.refresh_token,
        EXPIRED_TOKENS.scopes,
        EXPIRED_TOKENS.access_token,
      );
      expect(result?.refresh_token).toBe(ROTATED.refresh_token);
      expect(stored()?.refresh_token).toBe(ROTATED.refresh_token);
    });

    // PFL-792 §2.1 item 6: no attached controller, no refresh.
    test('without an attached refresh controller returns the cache and sends nothing', async () => {
      tokenCacheService.setTokensCache(EXPIRED_TOKENS);

      const result = await tokenCacheService.getTokensWithRefresh();

      expect(result).toEqual(EXPIRED_TOKENS);
      expect(mockAuthApi.refreshToken).not.toHaveBeenCalled();
    });

    // PFL-792 §2.8: was "does not refresh when tokenExpiredFlag is set"; the flag is output only.
    test('refreshes even when tokenExpiredFlag is set: the flag never gates a refresh', async () => {
      attachController(EXPIRED_TOKENS);
      tokenCacheService.tokenExpiredFlag = true;
      mockAuthApi.refreshToken.mockResolvedValue(ROTATED);

      await tokenCacheService.getTokensWithRefresh();

      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(1);
      expect(tokenCacheService.tokenExpiredFlag).toBe(false);
    });

    test('notifies error on refresh failure, once, labelled as a token-check refresh', async () => {
      attachController(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValue(new Error('Refresh failed'));

      const result = await tokenCacheService.getTokensWithRefresh();

      expect(result).toEqual(EXPIRED_TOKENS);
      expect(mockStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Error,
        expect.objectContaining({ message: 'Refresh failed', operation: 'refresh', source: 'token-check' }),
      );
      expect(notified(PassflowEvent.Error)).toHaveLength(1);
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
      attachController(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockResolvedValue(ROTATED);

      await tokenCacheService.getTokensWithRefresh();

      expect(mockStore.notify).toHaveBeenCalledWith(PassflowEvent.RefreshStart, {});
      expect(mockStore.notify).toHaveBeenCalledWith(
        PassflowEvent.Refresh,
        expect.objectContaining({
          tokens: expect.objectContaining({ refresh_token: ROTATED.refresh_token }),
          source: 'refresh',
        }),
      );
    });

    test('prevents concurrent refresh calls', async () => {
      attachController(EXPIRED_TOKENS);

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

      // Let the first one send, then answer it
      await vi.waitFor(() => expect(mockAuthApi.refreshToken).toHaveBeenCalled());
      resolveRefresh?.(ROTATED);

      const [first, second] = await Promise.all([refresh1, refresh2]);

      // Should only call refreshToken once; both callers get the new tokens
      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(1);
      expect(first?.refresh_token).toBe(ROTATED.refresh_token);
      expect(second?.refresh_token).toBe(ROTATED.refresh_token);
    });

    test('resets tokenExpiredFlag on successful refresh', async () => {
      attachController(EXPIRED_TOKENS);
      tokenCacheService.tokenExpiredFlag = true; // set by the expiry check
      mockAuthApi.refreshToken.mockResolvedValue(ROTATED);

      await tokenCacheService.getTokensWithRefresh();

      expect(tokenCacheService.tokenExpiredFlag).toBe(false);
      expect(mockStore.notify).toHaveBeenCalledWith(PassflowEvent.TokenCacheExpired, { isExpired: false });
    });

    // PFL-792 §9.4, pinned defect 3 (R5): was "clears cache on refresh error".
    test('keeps the cache on a transient refresh error', async () => {
      attachController(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValue(new Error('Network error'));

      const result = await tokenCacheService.getTokensWithRefresh();

      expect(result).toEqual(EXPIRED_TOKENS);
      expect(tokenCacheService.tokensCache).toEqual(EXPIRED_TOKENS);
    });

    // PFL-792 §9.4: was "resets isRefreshing flag even on error"; isRefreshing now mirrors
    // "this instance has a cycle", so it stays set while the retry is pending.
    test('isRefreshing stays set while a retry is pending and clears once it settles', async () => {
      attachController(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValueOnce(new Error('Network error')).mockResolvedValueOnce(ROTATED);

      await tokenCacheService.getTokensWithRefresh();
      expect(tokenCacheService.isRefreshing).toBe(true);

      await vi.advanceTimersByTimeAsync(RETRY_1_MAX_MS);

      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(2);
      expect(tokenCacheService.isRefreshing).toBe(false);
      expect(tokenCacheService.tokensCache?.refresh_token).toBe(ROTATED.refresh_token);
    });
  });

  describe('Session Expired Handling', () => {
    // PFL-792 §9.4, pinned defect 3 (R5): was "emits SessionExpired event when refresh fails"
    // with a plain Error, which is a transient failure.
    test('a transient refresh failure emits no SessionExpired', async () => {
      attachController(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValue(new Error('Refresh token expired'));

      await tokenCacheService.getTokensWithRefresh();

      expect(notified(PassflowEvent.SessionExpired)).toEqual([]);
      expect(notified(PassflowEvent.RefreshFailing)).toHaveLength(1);
    });

    // PFL-792 §9.4 auth-strike variant (R4): the session does end after refreshStrikes auth failures.
    test('auth failures end the session after refreshStrikes (3): SessionExpired{refresh_failed} once', async () => {
      const { stored } = attachController(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValue(AUTH_FAILURE());

      await tokenCacheService.getTokensWithRefresh();
      await vi.advanceTimersByTimeAsync(RETRY_1_MAX_MS);
      await vi.advanceTimersByTimeAsync(RETRY_2_MAX_MS);

      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(3);
      expect(notified(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
      expect(tokenCacheService.tokensCache).toBeUndefined();
      // Storage still held the dead token, so it is deleted.
      expect(stored()).toBeUndefined();
    });

    // PFL-792 §9.4: was "sets tokenExpiredFlag to prevent infinite refresh loops"; the loop is now
    // prevented by one pending retry that every caller joins.
    test('a transient failure leaves one pending retry: a second call joins it, one request', async () => {
      attachController(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValueOnce(new Error('Refresh token expired')).mockResolvedValueOnce(ROTATED);

      await tokenCacheService.getTokensWithRefresh();
      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(1);

      // The second caller sends nothing now; it settles with the scheduled retry.
      const joined = tokenCacheService.getTokensWithRefresh();
      await vi.advanceTimersByTimeAsync(0);
      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(RETRY_1_MAX_MS);
      expect((await joined)?.refresh_token).toBe(ROTATED.refresh_token);
      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(2);
    });

    // PFL-792 §9.4, pinned defect 3 (R5): was "deletes tokens from storage when refresh fails".
    test('keeps stored tokens when a refresh fails transiently', async () => {
      const { stored } = attachController(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValue(new Error('Refresh token expired'));

      await tokenCacheService.getTokensWithRefresh();

      expect(mockStorageManager.deleteTokens).not.toHaveBeenCalled();
      expect(stored()).toEqual(EXPIRED_TOKENS);
    });

    // PFL-792 §9.4: was "stops token check interval when refresh fails"; after the strikes end the
    // session stays ended: no further request, no second SessionExpired.
    test('after the strikes end, time passing brings no further request or SessionExpired', async () => {
      attachController(EXPIRED_TOKENS);
      tokenCacheService.startTokenCheck();
      mockAuthApi.refreshToken.mockRejectedValue(AUTH_FAILURE());

      await tokenCacheService.getTokensWithRefresh();
      await vi.advanceTimersByTimeAsync(RETRY_1_MAX_MS);
      await vi.advanceTimersByTimeAsync(RETRY_2_MAX_MS);
      await vi.advanceTimersByTimeAsync(120000);

      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(3);
      expect(notified(PassflowEvent.SessionExpired)).toHaveLength(1);
    });

    // PFL-792 §9.4: was "does not retry refresh after SessionExpired" (gated by the flag); now the
    // session end itself stops it: the cache is cleared and nothing is sent.
    test('does not retry refresh after the session ended', async () => {
      attachController(EXPIRED_TOKENS);
      mockAuthApi.refreshToken.mockRejectedValue(AUTH_FAILURE());

      await tokenCacheService.getTokensWithRefresh();
      await vi.advanceTimersByTimeAsync(RETRY_1_MAX_MS);
      await vi.advanceTimersByTimeAsync(RETRY_2_MAX_MS);

      expect(await tokenCacheService.getTokensWithRefresh()).toBeUndefined();
      expect(mockAuthApi.refreshToken).toHaveBeenCalledTimes(3);
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
