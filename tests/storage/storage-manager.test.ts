/// <reference types="vitest" />

import type { Mock } from 'vitest';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { StorageManager } from '../../lib/storage/index';
import { TokenType } from '../../lib/token/token';
import { FakeStorage } from './fake-storage';

// Create a type for our mock functions
type MockFn = Mock & { mockReset: () => void };

describe('storage manager', () => {
  let storageManager: StorageManager;
  let fakeStorage: FakeStorage;
  let getSpy: MockFn;
  let setSpy: MockFn;
  let removeSpy: MockFn;

  beforeEach(() => {
    fakeStorage = new FakeStorage();
    storageManager = new StorageManager({ storage: fakeStorage });
    getSpy = vi.spyOn(fakeStorage, 'getItem') as MockFn;
    setSpy = vi.spyOn(fakeStorage, 'setItem') as MockFn;
    removeSpy = vi.spyOn(fakeStorage, 'removeItem') as MockFn;
  });

  afterEach(() => {
    vi.clearAllMocks();
    getSpy.mockReset();
    setSpy.mockReset();
    removeSpy.mockReset();
  });

  describe('managing tokens', () => {
    test('should get null, no tokens exists', () => {
      const token = storageManager.getToken(TokenType.access_token);
      expect(token).toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(1);
    });

    test('should get token', () => {
      storageManager.saveTokens({ access_token: 'access' });
      let token = storageManager.getToken(TokenType.access_token);
      expect(token).not.toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(1);
      expect(setSpy).toHaveBeenCalledTimes(1);
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(2);
      expect(setSpy).toHaveBeenCalledTimes(1);
      token = storageManager.getToken(TokenType.id_token);
      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
    });

    test('should get null for unsupported token type', () => {
      storageManager.saveTokens({ access_token: 'access' });
      const token = storageManager.getToken(TokenType.reset_token);
      expect(token).toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(1);
      expect(setSpy).toHaveBeenCalledTimes(1);
    });

    test('delete all tokens', () => {
      storageManager.saveTokens({
        access_token: 'access',
        id_token: 'id',
        refresh_token: 'refresh',
      });

      let token = storageManager.getToken(TokenType.access_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).not.toBeUndefined();

      storageManager.deleteTokens();
      token = storageManager.getToken(TokenType.access_token);
      expect(token).toBeUndefined();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).toBeUndefined();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).toBeUndefined();

      expect(getSpy).toHaveBeenCalledTimes(6);
      expect(setSpy).toHaveBeenCalledTimes(3);
      expect(removeSpy).toHaveBeenCalledTimes(4);
    });

    test('delete one tokens', () => {
      storageManager.saveTokens({
        access_token: 'access',
        id_token: 'id',
        refresh_token: 'refresh',
      });

      let token = storageManager.getToken(TokenType.access_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).not.toBeUndefined();

      storageManager.deleteToken(TokenType.id_token);
      token = storageManager.getToken(TokenType.access_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).toBeUndefined();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).not.toBeUndefined();
      token = storageManager.getToken(TokenType.reset_token);
      expect(token).toBeUndefined();

      expect(getSpy).toHaveBeenCalledTimes(7);
      expect(setSpy).toHaveBeenCalledTimes(3);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });

    test('get tokens test', () => {
      storageManager.saveTokens({
        access_token: 'access',
        id_token: 'id',
        refresh_token: 'refresh',
        scopes: ['scope1', 'scope2'],
      });
      const tokens = storageManager.getTokens();
      expect(tokens).not.toBeUndefined();
      expect(tokens?.access_token).not.toBeUndefined();
      expect(tokens?.id_token).not.toBeUndefined();
      expect(tokens?.refresh_token).not.toBeUndefined();
      expect(tokens?.scopes).not.toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(4);
      expect(setSpy).toHaveBeenCalledTimes(4);
      expect(removeSpy).toHaveBeenCalledTimes(0);
    });
  });

  describe('managing additional storage data', () => {
    test('get device id', () => {
      const did = storageManager.getDeviceId();
      expect(did).toBeUndefined();
      expect(getSpy).toHaveBeenCalledTimes(1);
    });

    test('set device id', () => {
      let did = storageManager.getDeviceId();
      expect(did).toBeUndefined();

      storageManager.setDeviceId('device-1234');
      did = storageManager.getDeviceId();
      expect(did).not.toBeUndefined();

      storageManager.deleteDeviceId();
      did = storageManager.getDeviceId();
      expect(did).toBeUndefined();

      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });

    test('persist invitation token', () => {
      let invitation = storageManager.getInvitationToken();
      expect(invitation).toBeUndefined();

      storageManager.setInvitationToken('invitation-tokne-1234');
      invitation = storageManager.getInvitationToken();
      expect(invitation).not.toBeUndefined();

      storageManager.deleteInvitationToken();
      invitation = storageManager.getInvitationToken();
      expect(invitation).toBeUndefined();

      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });

    test('persist redirection url', () => {
      let redirectUrl = storageManager.getPreviousRedirectUrl();
      expect(redirectUrl).toBeUndefined();

      storageManager.setPreviousRedirectUrl('redirect-url-1234');
      redirectUrl = storageManager.getPreviousRedirectUrl();
      expect(redirectUrl).not.toBeUndefined();

      storageManager.deletePreviousRedirectUrl();
      redirectUrl = storageManager.getPreviousRedirectUrl();
      expect(redirectUrl).toBeUndefined();

      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });
  });
});
