/**
 * Fake cache implementation for M2M Authentication tests
 */

import type { M2MTokenCache, M2MTokenResponse } from '../../../lib/m2m';

/**
 * Fake cache for testing M2MClient with inspection capabilities
 */
export class FakeCache implements M2MTokenCache {
  private cache: Map<string, { token: M2MTokenResponse; expiresAt: number }> = new Map();
  private callCounts = {
    get: 0,
    set: 0,
    delete: 0,
  };
  private lastKey: string | null = null;
  private shouldThrowError = false;
  private errorMessage = 'Cache error';

  /**
   * Get cached token by key
   */
  get(key: string): Promise<M2MTokenResponse | null> {
    this.callCounts.get++;
    this.lastKey = key;

    if (this.shouldThrowError) {
      return Promise.reject(new Error(this.errorMessage));
    }

    const entry = this.cache.get(key);
    if (!entry) return Promise.resolve(null);

    // Check if expired
    if (Date.now() >= entry.expiresAt) {
      this.cache.delete(key);
      return Promise.resolve(null);
    }

    return Promise.resolve(entry.token);
  }

  /**
   * Cache a token with TTL
   */
  set(key: string, token: M2MTokenResponse, ttl: number): Promise<void> {
    this.callCounts.set++;
    this.lastKey = key;

    if (this.shouldThrowError) {
      return Promise.reject(new Error(this.errorMessage));
    }

    this.cache.set(key, {
      token,
      expiresAt: Date.now() + ttl * 1000,
    });
    return Promise.resolve();
  }

  /**
   * Delete cached token
   */
  delete(key: string): Promise<void> {
    this.callCounts.delete++;
    this.lastKey = key;

    if (this.shouldThrowError) {
      return Promise.reject(new Error(this.errorMessage));
    }

    this.cache.delete(key);
    return Promise.resolve();
  }

  // ========== Inspection Methods ==========

  /**
   * Get the number of times get() was called
   */
  getCallCount(): number {
    return this.callCounts.get;
  }

  /**
   * Get the number of times set() was called
   */
  setCallCount(): number {
    return this.callCounts.set;
  }

  /**
   * Get the number of times delete() was called
   */
  deleteCallCount(): number {
    return this.callCounts.delete;
  }

  /**
   * Get the last key that was accessed
   */
  getLastKey(): string | null {
    return this.lastKey;
  }

  /**
   * Get all call counts
   */
  getAllCallCounts(): { get: number; set: number; delete: number } {
    return { ...this.callCounts };
  }

  /**
   * Check if a key exists in the cache
   */
  has(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) return false;

    // Check if expired
    if (Date.now() >= entry.expiresAt) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Get the number of cached entries
   */
  size(): number {
    // Clean up expired entries first
    for (const [key, entry] of this.cache.entries()) {
      if (Date.now() >= entry.expiresAt) {
        this.cache.delete(key);
      }
    }
    return this.cache.size;
  }

  /**
   * Get all cached keys
   */
  keys(): string[] {
    // Clean up expired entries first
    for (const [key, entry] of this.cache.entries()) {
      if (Date.now() >= entry.expiresAt) {
        this.cache.delete(key);
      }
    }
    return Array.from(this.cache.keys());
  }

  // ========== Control Methods ==========

  /**
   * Simulate an error on the next operation
   */
  simulateError(message = 'Cache error'): void {
    this.shouldThrowError = true;
    this.errorMessage = message;
  }

  /**
   * Stop simulating errors
   */
  stopSimulatingError(): void {
    this.shouldThrowError = false;
  }

  /**
   * Clear the cache and reset all state
   */
  clear(): void {
    this.cache.clear();
    this.callCounts = {
      get: 0,
      set: 0,
      delete: 0,
    };
    this.lastKey = null;
    this.shouldThrowError = false;
    this.errorMessage = 'Cache error';
  }

  /**
   * Reset call counts without clearing the cache
   */
  resetCallCounts(): void {
    this.callCounts = {
      get: 0,
      set: 0,
      delete: 0,
    };
  }

  /**
   * Manually expire a cached token
   */
  expireToken(key: string): void {
    const entry = this.cache.get(key);
    if (entry) {
      entry.expiresAt = Date.now() - 1000; // 1 second ago
    }
  }

  /**
   * Get the TTL (time-to-live) remaining for a key in seconds
   */
  getTTL(key: string): number {
    const entry = this.cache.get(key);
    if (!entry) return 0;

    const remaining = entry.expiresAt - Date.now();
    return Math.max(0, Math.floor(remaining / 1000));
  }

  /**
   * Manually set a token without incrementing call counts (for test setup)
   */
  setTokenDirectly(key: string, token: M2MTokenResponse, ttl: number): void {
    this.cache.set(key, {
      token,
      expiresAt: Date.now() + ttl * 1000,
    });
  }

  /**
   * Get the raw cache entry (for advanced inspection)
   */
  getRawEntry(key: string): { token: M2MTokenResponse; expiresAt: number } | undefined {
    return this.cache.get(key);
  }
}
