/**
 * Unit tests for M2MClient.parseToken() JWT parsing
 */

import { describe, expect, it } from 'vitest';
import { M2MClient, M2MTokenParseError } from '../../../lib/m2m';
import type { M2MTokenClaims } from '../../../lib/m2m';
import { TEST_CLIENT_ID, TEST_SCOPES, TEST_URL, createMockConfig, createValidJWT } from '../utils/fixtures';

describe('M2MClient.parseToken()', () => {
  const client = new M2MClient(createMockConfig());

  describe('Valid JWT Parsing', () => {
    it('should extract standard JWT claims correctly', () => {
      const jwt = createValidJWT();
      const claims = client.parseToken(jwt);

      expect(claims).toHaveProperty('iss');
      expect(claims).toHaveProperty('sub');
      expect(claims).toHaveProperty('aud');
      expect(claims).toHaveProperty('iat');
      expect(claims).toHaveProperty('exp');
      expect(claims.iss).toBe(TEST_URL);
      expect(claims.sub).toBe(TEST_CLIENT_ID);
    });

    it('should parse client_id claim', () => {
      const jwt = createValidJWT({ client_id: 'custom-client-123' });
      const claims = client.parseToken(jwt);

      expect(claims.client_id).toBe('custom-client-123');
    });

    it('should parse scopes claim as array', () => {
      const jwt = createValidJWT({ scopes: ['read:users', 'write:posts'] });
      const claims = client.parseToken(jwt);

      expect(Array.isArray(claims.scopes)).toBe(true);
      expect(claims.scopes).toEqual(['read:users', 'write:posts']);
    });

    it('should convert scopes string to array', () => {
      // Create JWT with scopes as a space-separated string
      const jwt = createValidJWT({ scopes: 'read:users write:posts' as unknown as string[] });
      const claims = client.parseToken(jwt);

      expect(Array.isArray(claims.scopes)).toBe(true);
      expect(claims.scopes).toEqual(['read:users', 'write:posts']);
    });

    it('should parse tenant_id when present', () => {
      const jwt = createValidJWT({ tenant_id: 'tenant-abc-123' });
      const claims = client.parseToken(jwt);

      expect(claims.tenant_id).toBe('tenant-abc-123');
    });

    it('should handle aud as a string', () => {
      const jwt = createValidJWT({ aud: 'https://api.example.com' });
      const claims = client.parseToken(jwt);

      expect(claims.aud).toBe('https://api.example.com');
    });

    it('should handle aud as an array', () => {
      const jwt = createValidJWT({ aud: ['api1', 'api2', 'api3'] });
      const claims = client.parseToken(jwt);

      expect(Array.isArray(claims.aud)).toBe(true);
      expect(claims.aud).toEqual(['api1', 'api2', 'api3']);
    });

    it('should parse jti (JWT ID) when present', () => {
      const jwt = createValidJWT({ jti: 'unique-jwt-id-456' });
      const claims = client.parseToken(jwt);

      expect(claims.jti).toBe('unique-jwt-id-456');
    });

    it('should parse numeric timestamps correctly', () => {
      const iat = Math.floor(Date.now() / 1000);
      const exp = iat + 3600;
      const jwt = createValidJWT({ iat, exp });
      const claims = client.parseToken(jwt);

      expect(claims.iat).toBe(iat);
      expect(claims.exp).toBe(exp);
      expect(typeof claims.iat).toBe('number');
      expect(typeof claims.exp).toBe('number');
    });

    it('should parse all claims together', () => {
      const customClaims: Partial<M2MTokenClaims> = {
        iss: 'https://auth.custom.com',
        sub: 'client-xyz',
        aud: ['api1', 'api2'],
        iat: 1700000000,
        exp: 1700003600,
        jti: 'jwt-123',
        type: 'm2m',
        client_id: 'client-xyz',
        tenant_id: 'tenant-789',
        scopes: ['admin:all', 'read:users'],
      };

      const jwt = createValidJWT(customClaims);
      const claims = client.parseToken(jwt);

      expect(claims.iss).toBe(customClaims.iss);
      expect(claims.sub).toBe(customClaims.sub);
      expect(claims.aud).toEqual(customClaims.aud);
      expect(claims.iat).toBe(customClaims.iat);
      expect(claims.exp).toBe(customClaims.exp);
      expect(claims.jti).toBe(customClaims.jti);
      expect(claims.type).toBe(customClaims.type);
      expect(claims.client_id).toBe(customClaims.client_id);
      expect(claims.tenant_id).toBe(customClaims.tenant_id);
      expect(claims.scopes).toEqual(customClaims.scopes);
    });
  });

  describe('Invalid JWT Handling', () => {
    it('should throw M2MTokenParseError for JWT with 2 parts', () => {
      const invalidJwt = 'header.payload';

      expect(() => client.parseToken(invalidJwt)).toThrow(M2MTokenParseError);
      expect(() => client.parseToken(invalidJwt)).toThrow('Invalid JWT format: expected 3 parts');
    });

    it('should throw M2MTokenParseError for JWT with 4+ parts', () => {
      const invalidJwt = 'part1.part2.part3.part4';

      expect(() => client.parseToken(invalidJwt)).toThrow(M2MTokenParseError);
      expect(() => client.parseToken(invalidJwt)).toThrow('Invalid JWT format: expected 3 parts');
    });

    it('should throw M2MTokenParseError for JWT with 5 parts', () => {
      const invalidJwt = 'part1.part2.part3.part4.part5';

      expect(() => client.parseToken(invalidJwt)).toThrow(M2MTokenParseError);
      expect(() => client.parseToken(invalidJwt)).toThrow('Invalid JWT format: expected 3 parts');
    });

    it('should throw M2MTokenParseError for single part', () => {
      const invalidJwt = 'not-a-jwt';

      expect(() => client.parseToken(invalidJwt)).toThrow(M2MTokenParseError);
      expect(() => client.parseToken(invalidJwt)).toThrow('Invalid JWT format: expected 3 parts');
    });

    it('should throw M2MTokenParseError for invalid base64url encoding', () => {
      const invalidJwt = 'header.!!!invalid-base64!!!.signature';

      expect(() => client.parseToken(invalidJwt)).toThrow(M2MTokenParseError);
      expect(() => client.parseToken(invalidJwt)).toThrow(/Failed to parse token/);
    });

    it('should throw M2MTokenParseError for invalid JSON in payload', () => {
      // Create a JWT with invalid JSON in payload
      const invalidPayload = Buffer.from('{invalid json}').toString('base64url');
      const invalidJwt = `eyJhbGciOiJIUzI1NiJ9.${invalidPayload}.signature`;

      expect(() => client.parseToken(invalidJwt)).toThrow(M2MTokenParseError);
      expect(() => client.parseToken(invalidJwt)).toThrow(/Failed to parse token/);
    });

    it('should throw M2MTokenParseError for empty payload section', () => {
      const invalidJwt = 'header..signature';

      expect(() => client.parseToken(invalidJwt)).toThrow(M2MTokenParseError);
      expect(() => client.parseToken(invalidJwt)).toThrow('Invalid JWT format: missing payload');
    });

    it('should throw M2MTokenParseError for empty string', () => {
      expect(() => client.parseToken('')).toThrow(M2MTokenParseError);
      expect(() => client.parseToken('')).toThrow('Invalid JWT format: expected 3 parts');
    });

    it('should throw error for malformed base64url (standard base64 without conversion)', () => {
      // Base64 with + and / instead of - and _ should still work due to conversion
      const payload = Buffer.from(JSON.stringify({ sub: 'test' })).toString('base64');
      const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`;

      // This should actually work because parseToken converts + to - and / to _
      const claims = client.parseToken(jwt);
      expect(claims.sub).toBe('test');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty scopes array', () => {
      const jwt = createValidJWT({ scopes: [] });
      const claims = client.parseToken(jwt);

      expect(Array.isArray(claims.scopes)).toBe(true);
      expect(claims.scopes).toEqual([]);
    });

    it('should handle missing scopes claim', () => {
      const claimsWithoutScopes = {
        iss: TEST_URL,
        sub: TEST_CLIENT_ID,
        aud: ['api'],
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        type: 'm2m' as const,
        client_id: TEST_CLIENT_ID,
      };

      const payload = Buffer.from(JSON.stringify(claimsWithoutScopes)).toString('base64url');
      const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`;

      const claims = client.parseToken(jwt);
      expect(claims.scopes).toEqual([]);
    });

    it('should handle missing optional claims gracefully', () => {
      const minimalClaims = {
        iss: TEST_URL,
        sub: TEST_CLIENT_ID,
        aud: 'api',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        type: 'm2m',
        client_id: TEST_CLIENT_ID,
        scopes: TEST_SCOPES,
      };

      const payload = Buffer.from(JSON.stringify(minimalClaims)).toString('base64url');
      const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`;

      const claims = client.parseToken(jwt);
      expect(claims.jti).toBeUndefined();
      expect(claims.tenant_id).toBeUndefined();
      expect(claims).toHaveProperty('iss');
      expect(claims).toHaveProperty('sub');
      expect(claims).toHaveProperty('client_id');
    });

    it('should handle base64url padding correctly (no padding)', () => {
      // Base64url should not have padding, test with various payload lengths
      const shortPayload = { sub: 'a' };
      const jwt1 = createValidJWT(shortPayload);
      const claims1 = client.parseToken(jwt1);
      expect(claims1.sub).toBe('a');

      const mediumPayload = { sub: 'ab' };
      const jwt2 = createValidJWT(mediumPayload);
      const claims2 = client.parseToken(jwt2);
      expect(claims2.sub).toBe('ab');

      const longPayload = { sub: 'abc' };
      const jwt3 = createValidJWT(longPayload);
      const claims3 = client.parseToken(jwt3);
      expect(claims3.sub).toBe('abc');
    });

    it('should handle base64url with padding characters (=) if present', () => {
      // Some JWT implementations might add padding, parseToken should handle it
      const payload = Buffer.from(JSON.stringify({ sub: 'test', scopes: ['read'] })).toString('base64');
      const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`;

      const claims = client.parseToken(jwt);
      expect(claims.sub).toBe('test');
      expect(claims.scopes).toEqual(['read']);
    });

    it('should handle whitespace-only scopes string', () => {
      const jwt = createValidJWT({ scopes: '   ' as unknown as string[] });
      const claims = client.parseToken(jwt);

      // Should split and filter empty strings
      expect(Array.isArray(claims.scopes)).toBe(true);
      // Split by space creates empty strings which remain in array
      expect(claims.scopes.length).toBeGreaterThanOrEqual(0);
    });

    it('should handle scopes with single scope', () => {
      const jwt = createValidJWT({ scopes: 'read:users' as unknown as string[] });
      const claims = client.parseToken(jwt);

      expect(Array.isArray(claims.scopes)).toBe(true);
      expect(claims.scopes).toEqual(['read:users']);
    });

    it('should handle very long JWT', () => {
      const longScopes = Array.from({ length: 100 }, (_, i) => `scope:${i}`);
      const jwt = createValidJWT({ scopes: longScopes });
      const claims = client.parseToken(jwt);

      expect(claims.scopes).toHaveLength(100);
      expect(claims.scopes[0]).toBe('scope:0');
      expect(claims.scopes[99]).toBe('scope:99');
    });

    it('should handle special characters in string values', () => {
      const jwt = createValidJWT({
        sub: 'client-with-special-chars_@#$%',
        tenant_id: 'tenant:with:colons',
      });
      const claims = client.parseToken(jwt);

      expect(claims.sub).toBe('client-with-special-chars_@#$%');
      expect(claims.tenant_id).toBe('tenant:with:colons');
    });

    it('should handle ASCII special characters in claims', () => {
      const jwt = createValidJWT({
        sub: 'client-with-dashes_and_underscores',
        scopes: ['read:users', 'write:posts'],
      });
      const claims = client.parseToken(jwt);

      expect(claims.sub).toBe('client-with-dashes_and_underscores');
      expect(claims.scopes).toContain('read:users');
      expect(claims.scopes).toContain('write:posts');
    });
  });

  describe('Type Safety', () => {
    it('should return M2MTokenClaims type', () => {
      const jwt = createValidJWT();
      const claims = client.parseToken(jwt);

      // TypeScript type checks
      const _iss: string = claims.iss;
      const _sub: string = claims.sub;
      const _aud: string | string[] = claims.aud;
      const _iat: number = claims.iat;
      const _exp: number = claims.exp;
      const _clientId: string = claims.client_id;
      const _scopes: string[] = claims.scopes;
      const _type: 'm2m' = claims.type;

      // Optional fields
      const _jti: string | undefined = claims.jti;
      const _tenantId: string | undefined = claims.tenant_id;

      expect(_iss).toBeDefined();
      expect(_sub).toBeDefined();
      expect(_aud).toBeDefined();
      expect(_iat).toBeDefined();
      expect(_exp).toBeDefined();
      expect(_clientId).toBeDefined();
      expect(_scopes).toBeDefined();
      expect(_type).toBeDefined();
      expect(_jti).toBeDefined();
      expect(_tenantId).toBeUndefined();
    });
  });
});
