import { beforeEach, describe, expect, test } from 'vitest';
import { StorageManager } from '../../lib/storage-manager';
import { Token, TokenService, TokenType, isTokenExpired, parseToken } from '../../lib/token-service';
import { parseMembership } from '../../lib/token-service/membership';

import { FakeStorage } from '../storage-manager/fake-storage';

describe('token service', () => {
  let storageManager: StorageManager;
  let tokenService: TokenService;
  beforeEach(() => {
    const fakeStorage = new FakeStorage();
    storageManager = new StorageManager({ storage: fakeStorage });
    tokenService = new TokenService();
    // @ts-expect-error storage manager is protected
    tokenService.storageManager = storageManager;
  });

  describe('working with tokens expiration', () => {
    test('isTokenExpired', () => {
      const token = emptyToken();
      token.exp = Math.floor(Date.now() / 1000) - 1; // minus one second from now
      expect(isTokenExpired(token)).toBe(true);
    });
    test('isTokenExpired false', () => {
      const token = emptyToken();
      token.exp = Math.floor(Date.now() / 1000) + 100; // JS is slow, let's add  one hundred second
      expect(isTokenExpired(token)).toBe(false);
    });
    test('isTokenTypeExpired with no token', () => {
      // not token, it means it is expired
      expect(tokenService.isTokenTypeExpired(TokenType.access_token)).toBe(true);
    });
    test('isTokenTypeExpired with token, which expired', () => {
      // not token, it means it is expired
      const token = emptyToken();
      token.exp = Math.floor(Date.now() / 1000) - 1; // minus one second from now
      storageManager.saveTokens({ access_token: tokenString(token) });
      expect(tokenService.isTokenTypeExpired(TokenType.access_token)).toBe(true);
    });
    test('isTokenTypeExpired with token, which is not expired', () => {
      // not token, it means it is expired
      const token = emptyToken();
      token.exp = Math.floor(Date.now() / 1000) + 100;
      storageManager.saveTokens({ access_token: tokenString(token) });
      expect(tokenService.isTokenTypeExpired(TokenType.access_token)).toBe(false);
      expect(tokenService.isTokenTypeExpired(TokenType.id_token)).toBe(true);
      expect(tokenService.isTokenTypeExpired(TokenType.refresh_token)).toBe(true);
    });
  });

  describe('parsing the token', () => {
    test('parse empty token', () => {
      // eslint-disable-next-line max-nested-callbacks
      expect(() => parseToken('')).toThrow('Invalid token string');
      // eslint-disable-next-line max-nested-callbacks
      expect(() => parseToken('randomvalue')).toThrow('Invalid token string');
      // eslint-disable-next-line max-nested-callbacks
      expect(() => parseToken(btoa(JSON.stringify(emptyToken())))).toThrow('Invalid token string');
    });
    test('parse simple token', () => {
      const token1 =
        // eslint-disable-next-line max-len
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      const token = parseToken(token1);
      expect(token).not.toBeUndefined();
      expect(token?.sub).toBe('1234567890');
      expect(token?.iat).toBe(1516239022);
    });
    test('parse token with membership', () => {
      const token1 =
        // eslint-disable-next-line max-len
        'eyJhbGciOiJFUzI1NiIsImtpZCI6IjN3UWZGc2RNclk2SDZ4RFR5cU9SYVhka2RacyIsInR5cCI6IkpXVCJ9.eyJhb290aF90bSI6eyIyYnpCZVJmdm5FNHZuQ1FsTE1BdXVKMTQyOWwiOnsidGVuYW50X2lkIjoiMmJ6QmVSZnZuRTR2bkNRbExNQXV1SjE0MjlsIiwidGVuYW50X25hbWUiOiJKYWNrIFJ1ZGVua28ncyB3b3Jrc3BhY2UiLCJ0ZW5hbnRfcm9sZXMiOlsib3duZXIiXSwicm9vdF9ncm91cF9pZCI6IjJiekJlTnBFT2JUa3FCdkdPNTN6MW1MU1RHWCIsImdyb3VwcyI6eyIyYnpCZU5wRU9iVGtxQnZHTzUzejFtTFNUR1giOlsib3duZXIiXX0sImdyb3VwX25hbWVzIjp7IjJiekJlTnBFT2JUa3FCdkdPNTN6MW1MU1RHWCI6ImRlZmF1bHQifX0sIjJiekJqbTdGa0FiQThUMEEzZVNnVHE2aktHTSI6eyJ0ZW5hbnRfaWQiOiIyYnpCam03RmtBYkE4VDBBM2VTZ1RxNmpLR00iLCJ0ZW5hbnRfbmFtZSI6IkFub3RoZXIgd29ya3NwYWNlIiwidGVuYW50X3JvbGVzIjpbIm93bmVyIl0sInJvb3RfZ3JvdXBfaWQiOiIyYnpCam01VWRuS0hKdlg0OVhMVmRhbnBCaEwiLCJncm91cHMiOnsiMmJ6QmptNVVkbktISnZYNDlYTFZkYW5wQmhMIjpbIm93bmVyIl19LCJncm91cF9uYW1lcyI6eyIyYnpCam01VWRuS0hKdlg0OVhMVmRhbnBCaEwiOiJkZWZhdWx0In19LCIyYnpCc09Mc01sM2JXWnJHUzNydGNHaEF6MlMiOnsidGVuYW50X2lkIjoiMmJ6QnNPTHNNbDNiV1pyR1MzcnRjR2hBejJTIiwidGVuYW50X25hbWUiOiJUZXN0MTExIiwidGVuYW50X3JvbGVzIjpbIm93bmVyIl0sInJvb3RfZ3JvdXBfaWQiOiIyYnpCc0xpWUJjWHUwa0xJQ1NNaXNXQVRuVHQiLCJncm91cHMiOnsiMmJ6QnNMaVlCY1h1MGtMSUNTTWlzV0FUblR0IjpbIm93bmVyIl19LCJncm91cF9uYW1lcyI6eyIyYnpCc0xpWUJjWHUwa0xJQ1NNaXNXQVRuVHQiOiJkZWZhdWx0In19LCIyYzNRV20xWnpueXNiV0t0bWIwQ3YwamU4c04iOnsidGVuYW50X2lkIjoiMmMzUVdtMVp6bnlzYldLdG1iMEN2MGplOHNOIiwidGVuYW50X25hbWUiOiJNQURBUFBHQU5HIiwidGVuYW50X3JvbGVzIjpbImFkbWluIl0sInJvb3RfZ3JvdXBfaWQiOiIyYzNRV2w1VTdZeUtZaFp2Ym5qRnpTdWtzUFgiLCJncm91cHMiOnsiMmMzUVdsNVU3WXlLWWhadmJuakZ6U3Vrc1BYIjpbImFkbWluIl19LCJncm91cF9uYW1lcyI6eyIyYzNRV2w1VTdZeUtZaFp2Ym5qRnpTdWtzUFgiOiJkZWZhdWx0In19fSwiYXVkIjpbIjJXQTFnTnBKOGhvRWdYM1B2VFdGUFZQd0V5aW8iXSwiZXhwIjoxNzE0NDU3NzMyLCJpYXQiOjE3MTQ0NTU5MzIsImlzcyI6Imh0dHBzOi8vYXBpLmFwcC5hb290aC5jb20iLCJqdGkiOiIyamJnRWxMblRYX0hBTnVONUtISEFockJMSWVyb0Q3aDRXZTRfemtobDUwPSIsInN1YiI6IjJiekJlUHB0RERQa1hxZkRWZlA1Z1dhbjAwTyIsInR5cGUiOiJhY2Nlc3MifQ.SWLWz9h9OtxiFiLz11H5tjp5BTttGW3kUSupbhpoaLYhqMi3KNSbS1pKoaz4NHzPuNm3-oT3YtJQfEjB3AbDPg';
      const token = parseToken(token1);
      expect(token).not.toBeNull();
      expect(token?.sub).toBe('2bzBePptDDPkXqfDVfP5gWan00O');
      expect(token?.iat).toBe(1714455932);
      expect(token?.iss).toBe('https://api.app.aooth.com');
      expect(token?.jti).toBe('2jbgElLnTX_HANuN5KHHAhrBLIeroD7h4We4_zkhl50=');

      // The token has aooth_tm instead of passflow_tm, manually assign for the test
      // @ts-expect-error We're setting membership manually for testing purposes
      token.passflow_tm = token.aooth_tm;
      // Re-parse the membership
      // @ts-expect-error Manual membership parsing for testing
      token.membership = parseMembership(token.passflow_tm);

      expect(token?.membership).not.toBeNull();
      expect(token?.membership?.raw).toEqual({
        '2bzBeRfvnE4vnCQlLMAuuJ1429l': {
          tenant_id: '2bzBeRfvnE4vnCQlLMAuuJ1429l',
          // eslint-disable-next-line quotes
          tenant_name: "Jack Rudenko's workspace",
          tenant_roles: ['owner'],
          root_group_id: '2bzBeNpEObTkqBvGO53z1mLSTGX',
          groups: {
            '2bzBeNpEObTkqBvGO53z1mLSTGX': ['owner'],
          },
          group_names: {
            '2bzBeNpEObTkqBvGO53z1mLSTGX': 'default',
          },
        },
        '2bzBjm7FkAbA8T0A3eSgTq6jKGM': {
          tenant_id: '2bzBjm7FkAbA8T0A3eSgTq6jKGM',
          tenant_name: 'Another workspace',
          tenant_roles: ['owner'],
          root_group_id: '2bzBjm5UdnKHJvX49XLVdanpBhL',
          groups: {
            '2bzBjm5UdnKHJvX49XLVdanpBhL': ['owner'],
          },
          group_names: {
            '2bzBjm5UdnKHJvX49XLVdanpBhL': 'default',
          },
        },
        '2bzBsOLsMl3bWZrGS3rtcGhAz2S': {
          tenant_id: '2bzBsOLsMl3bWZrGS3rtcGhAz2S',
          tenant_name: 'Test111',
          tenant_roles: ['owner'],
          root_group_id: '2bzBsLiYBcXu0kLICSMisWATnTt',
          groups: {
            '2bzBsLiYBcXu0kLICSMisWATnTt': ['owner'],
          },
          group_names: {
            '2bzBsLiYBcXu0kLICSMisWATnTt': 'default',
          },
        },
        '2c3QWm1ZznysbWKtmb0Cv0je8sN': {
          tenant_id: '2c3QWm1ZznysbWKtmb0Cv0je8sN',
          tenant_name: 'MADAPPGANG',
          tenant_roles: ['admin'],
          root_group_id: '2c3QWl5U7YyKYhZvbnjFzSuksPX',
          groups: {
            '2c3QWl5U7YyKYhZvbnjFzSuksPX': ['admin'],
          },
          group_names: {
            '2c3QWl5U7YyKYhZvbnjFzSuksPX': 'default',
          },
        },
      });
      expect(token?.membership?.tenants).toHaveLength(4);
    });
    test('parse token type', () => {
      const token = emptyToken();
      token.exp = Math.floor(Date.now() / 1000) + 100;
      token.aud = ['audience'];
      storageManager.saveTokens({ access_token: tokenString(token) });
      const token2 = tokenService.parseTokenType(TokenType.access_token);
      expect(token2).not.toBeNull();
      expect(token2?.sub).toBe('');
      expect(token2?.aud).toEqual(['audience']);
      expect(tokenService.parseTokenType(TokenType.refresh_token)).toBe(undefined);
      expect(tokenService.parseTokenType(TokenType.id_token)).toBe(undefined);
    });
  });
});

function emptyToken(): Token {
  return {
    aud: [],
    exp: 0,
    iat: 0,
    iss: '',
    jti: '',
    sub: '',
    type: '',
  };
}

function tokenString(token: Token): string {
  return `header.${btoa(JSON.stringify(token))}.signature`;
}
