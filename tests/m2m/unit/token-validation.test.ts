/**
 * M2M Client Token Validation Tests
 *
 * Tests for M2MClient.isTokenExpired() method covering basic expiration checks,
 * threshold parameters, time calculations, and edge cases.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { M2MClient } from '../../../lib/m2m';
import type { M2MTokenResponse } from '../../../lib/m2m';
import { createMockConfig, createMockToken } from '../utils/fixtures';

describe('M2MClient - Token Validation', () => {
  let client: M2MClient;

  beforeEach(() => {
    client = new M2MClient(createMockConfig());
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Basic Expiration Check', () => {
    it('should return true for expired token', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const expiredToken: M2MTokenResponse = createMockToken({
        issued_at: now - 3700,
        expires_in: 3600,
      });

      expect(client.isTokenExpired(expiredToken)).toBe(true);
    });

    it('should return false for valid token', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const validToken: M2MTokenResponse = createMockToken({
        issued_at: now - 1000,
        expires_in: 3600,
      });

      expect(client.isTokenExpired(validToken)).toBe(false);
    });

    it('should return true for null token', () => {
      expect(client.isTokenExpired(null)).toBe(true);
    });

    it('should return true for undefined token', () => {
      expect(client.isTokenExpired(undefined)).toBe(true);
    });
  });

  describe('Threshold Parameter', () => {
    it('should use default threshold of 0', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const tokenExpiringNow: M2MTokenResponse = createMockToken({
        issued_at: now - 3600,
        expires_in: 3600,
      });

      // At exact expiry with threshold=0
      expect(client.isTokenExpired(tokenExpiringNow)).toBe(true);
    });

    it('should consider custom threshold in calculation', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 3000,
        expires_in: 3600,
      });

      // Token expires in 600 seconds
      // With threshold of 300, should still be valid
      expect(client.isTokenExpired(token, 300)).toBe(false);

      // With threshold of 700, should be expired
      expect(client.isTokenExpired(token, 700)).toBe(true);
    });

    it('should return true when token expires within threshold', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 3400,
        expires_in: 3600,
      });

      // Token expires in 200 seconds
      // Threshold of 300 means it should be considered expired
      expect(client.isTokenExpired(token, 300)).toBe(true);
    });

    it('should return false when token expires outside threshold', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 2000,
        expires_in: 3600,
      });

      // Token expires in 1600 seconds
      // Threshold of 300 means it should still be valid
      expect(client.isTokenExpired(token, 300)).toBe(false);
    });
  });

  describe('Time Calculations', () => {
    it('should use issued_at + expires_in for expiration time', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: 999000,
        expires_in: 3600,
      });

      // Expires at: 999000 + 3600 = 1002600
      // Now: 1000000
      // Not expired yet
      expect(client.isTokenExpired(token)).toBe(false);
    });

    it('should fall back to calculation when issued_at missing', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const tokenWithoutIssuedAt: M2MTokenResponse = createMockToken({
        expires_in: 3600,
      });
      delete tokenWithoutIssuedAt.issued_at;

      // Should calculate: issued_at = now - expires_in = 1000000 - 3600 = 996400
      // Expires at: 996400 + 3600 = 1000000 (right now)
      expect(client.isTokenExpired(tokenWithoutIssuedAt)).toBe(true);
    });

    it('should handle various expires_in values (3600)', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 100,
        expires_in: 3600,
      });

      // Token expires in 3500 seconds
      expect(client.isTokenExpired(token)).toBe(false);
    });

    it('should handle various expires_in values (7200)', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 100,
        expires_in: 7200,
      });

      // Token expires in 7100 seconds
      expect(client.isTokenExpired(token)).toBe(false);
    });

    it('should handle various expires_in values (1800)', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 1800,
        expires_in: 1800,
      });

      // Token expires exactly now
      expect(client.isTokenExpired(token)).toBe(true);
    });

    it('should handle short-lived tokens (300 seconds)', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 100,
        expires_in: 300,
      });

      // Token expires in 200 seconds
      expect(client.isTokenExpired(token)).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle token exactly at expiration boundary', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 3600,
        expires_in: 3600,
      });

      // Token expires exactly now
      expect(client.isTokenExpired(token)).toBe(true);
    });

    it('should handle token exactly at expiration boundary with threshold', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 3300,
        expires_in: 3600,
      });

      // Token expires in 300 seconds
      // With threshold of 300, should be considered expired (>=)
      expect(client.isTokenExpired(token, 300)).toBe(true);
    });

    it('should handle token with expires_in=0', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now,
        expires_in: 0,
      });

      // Token expires immediately
      expect(client.isTokenExpired(token)).toBe(true);
    });

    it('should handle negative threshold', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 3650,
        expires_in: 3600,
      });

      // Token expired 50 seconds ago
      // Negative threshold of -100 extends validity by 100 seconds
      // So it's treated as still valid
      expect(client.isTokenExpired(token, -100)).toBe(false);
    });

    it('should handle negative threshold on valid token', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 3550,
        expires_in: 3600,
      });

      // Token expires in 50 seconds
      // Negative threshold of -100 means we add 100s buffer
      expect(client.isTokenExpired(token, -100)).toBe(false);
    });

    it('should handle large threshold values', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 100,
        expires_in: 3600,
      });

      // Token expires in 3500 seconds
      // Threshold of 10000 means it should be expired
      expect(client.isTokenExpired(token, 10000)).toBe(true);
    });

    it('should handle threshold larger than expires_in', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now,
        expires_in: 300,
      });

      // Token expires in 300 seconds
      // Threshold of 500 (larger than expires_in) means it should be expired
      expect(client.isTokenExpired(token, 500)).toBe(true);
    });

    it('should handle very large expires_in values', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now,
        expires_in: 86400 * 365, // 1 year
      });

      // Token expires in 1 year
      expect(client.isTokenExpired(token)).toBe(false);
    });

    it('should handle token issued in the future', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now + 100, // Issued 100 seconds in the future
        expires_in: 3600,
      });

      // Expires at: (now + 100) + 3600 = now + 3700
      // Should not be expired
      expect(client.isTokenExpired(token)).toBe(false);
    });

    it('should handle millisecond precision correctly', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000 + 999); // Add 999ms

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 3600,
        expires_in: 3600,
      });

      // Even with 999ms added, should floor to same second
      // Token expires at: (now - 3600) + 3600 = now
      expect(client.isTokenExpired(token)).toBe(true);
    });

    it('should be consistent across multiple calls with same time', () => {
      const now = 1000000;
      vi.setSystemTime(now * 1000);

      const token: M2MTokenResponse = createMockToken({
        issued_at: now - 1000,
        expires_in: 3600,
      });

      const result1 = client.isTokenExpired(token);
      const result2 = client.isTokenExpired(token);
      const result3 = client.isTokenExpired(token);

      expect(result1).toBe(result2);
      expect(result2).toBe(result3);
      expect(result1).toBe(false);
    });
  });
});
