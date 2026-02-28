/**
 * M2MClient Constructor Validation Tests
 */

import { describe, expect, it } from 'vitest';
import { M2MClient } from '../../../lib/m2m/client';
import { M2MConfigError } from '../../../lib/m2m/errors';
import { M2M_DEFAULTS } from '../../../lib/m2m/types';
import { TEST_CLIENT_ID, TEST_CLIENT_SECRET, TEST_URL, createMockConfig } from '../utils/fixtures';

describe('M2MClient Constructor', () => {
  describe('Configuration Validation', () => {
    it('should create client with valid configuration', () => {
      const config = createMockConfig();
      const client = new M2MClient(config);

      expect(client).toBeInstanceOf(M2MClient);
      expect(client.url).toBe(TEST_URL);
      expect(client.clientId).toBe(TEST_CLIENT_ID);
    });

    it('should throw M2MConfigError when URL is missing', () => {
      const config = createMockConfig({ url: undefined as unknown as string });

      expect(() => new M2MClient(config)).toThrow(M2MConfigError);
      expect(() => new M2MClient(config)).toThrow('M2M client requires a URL');
    });

    it('should throw M2MConfigError when clientId is missing', () => {
      const config = createMockConfig({ clientId: undefined as unknown as string });

      expect(() => new M2MClient(config)).toThrow(M2MConfigError);
      expect(() => new M2MClient(config)).toThrow('M2M client requires a clientId');
    });

    it('should throw M2MConfigError when clientSecret is missing', () => {
      const config = createMockConfig({ clientSecret: undefined as unknown as string });

      expect(() => new M2MClient(config)).toThrow(M2MConfigError);
      expect(() => new M2MClient(config)).toThrow('M2M client requires a clientSecret');
    });

    it('should throw M2MConfigError when URL is empty string', () => {
      const config = createMockConfig({ url: '' });

      expect(() => new M2MClient(config)).toThrow(M2MConfigError);
      expect(() => new M2MClient(config)).toThrow('M2M client requires a URL');
    });

    it('should throw M2MConfigError when clientId is empty string', () => {
      const config = createMockConfig({ clientId: '' });

      expect(() => new M2MClient(config)).toThrow(M2MConfigError);
      expect(() => new M2MClient(config)).toThrow('M2M client requires a clientId');
    });

    it('should throw M2MConfigError when clientSecret is empty string', () => {
      const config = createMockConfig({ clientSecret: '' });

      expect(() => new M2MClient(config)).toThrow(M2MConfigError);
      expect(() => new M2MClient(config)).toThrow('M2M client requires a clientSecret');
    });
  });

  describe('URL Normalization', () => {
    it('should normalize URL with trailing slash', () => {
      const config = createMockConfig({ url: 'https://api.passflow.cloud/' });
      const client = new M2MClient(config);

      expect(client.url).toBe('https://api.passflow.cloud');
    });

    it('should normalize URL with multiple trailing slashes', () => {
      const config = createMockConfig({ url: 'https://api.passflow.cloud///' });
      const client = new M2MClient(config);

      // The regex replace(/\/$/, '') only removes the last trailing slash
      expect(client.url).toBe('https://api.passflow.cloud//');
    });

    it('should keep URL without trailing slash unchanged', () => {
      const config = createMockConfig({ url: 'https://api.passflow.cloud' });
      const client = new M2MClient(config);

      expect(client.url).toBe('https://api.passflow.cloud');
    });
  });

  describe('Default Values', () => {
    it('should apply default timeout', () => {
      const config = createMockConfig();
      const client = new M2MClient(config);

      // Access private config via type casting for testing
      const configInternal = (client as { config: { timeout: number } }).config;
      expect(configInternal.timeout).toBe(M2M_DEFAULTS.TIMEOUT);
    });

    it('should apply default retries', () => {
      const config = createMockConfig();
      const client = new M2MClient(config);

      const configInternal = (client as { config: { retries: number } }).config;
      expect(configInternal.retries).toBe(M2M_DEFAULTS.RETRIES);
    });

    it('should apply default retryDelay', () => {
      const config = createMockConfig();
      const client = new M2MClient(config);

      const configInternal = (client as { config: { retryDelay: number } }).config;
      expect(configInternal.retryDelay).toBe(M2M_DEFAULTS.RETRY_DELAY);
    });

    it('should apply default refreshThreshold', () => {
      const config = createMockConfig();
      const client = new M2MClient(config);

      const configInternal = (client as { config: { refreshThreshold: number } }).config;
      expect(configInternal.refreshThreshold).toBe(M2M_DEFAULTS.REFRESH_THRESHOLD);
    });

    it('should apply default autoRefresh', () => {
      const config = createMockConfig();
      const client = new M2MClient(config);

      const configInternal = (client as { config: { autoRefresh: boolean } }).config;
      expect(configInternal.autoRefresh).toBe(false);
    });

    it('should override default timeout with custom value', () => {
      const customTimeout = 5000;
      const config = createMockConfig({ timeout: customTimeout });
      const client = new M2MClient(config);

      const configInternal = (client as { config: { timeout: number } }).config;
      expect(configInternal.timeout).toBe(customTimeout);
    });

    it('should override default retries with custom value', () => {
      const customRetries = 5;
      const config = createMockConfig({ retries: customRetries });
      const client = new M2MClient(config);

      const configInternal = (client as { config: { retries: number } }).config;
      expect(configInternal.retries).toBe(customRetries);
    });

    it('should override default retryDelay with custom value', () => {
      const customRetryDelay = 2000;
      const config = createMockConfig({ retryDelay: customRetryDelay });
      const client = new M2MClient(config);

      const configInternal = (client as { config: { retryDelay: number } }).config;
      expect(configInternal.retryDelay).toBe(customRetryDelay);
    });

    it('should override default refreshThreshold with custom value', () => {
      const customRefreshThreshold = 60;
      const config = createMockConfig({ refreshThreshold: customRefreshThreshold });
      const client = new M2MClient(config);

      const configInternal = (client as { config: { refreshThreshold: number } }).config;
      expect(configInternal.refreshThreshold).toBe(customRefreshThreshold);
    });

    it('should override default autoRefresh with custom value', () => {
      const config = createMockConfig({ autoRefresh: true });
      const client = new M2MClient(config);

      const configInternal = (client as { config: { autoRefresh: boolean } }).config;
      expect(configInternal.autoRefresh).toBe(true);
    });
  });
});
