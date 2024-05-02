import { StorageManager } from '../../storage-manager';
import { TokenType } from '../../token-service';

import { FakeStorage } from './fake-storage';

describe('storage manager', () => {
  const storageManager = new StorageManager();
  let getSpy: jest.SpyInstance<string | null, [key: string], unknown>;
  let setSpy: jest.SpyInstance<void, [key: string, value: string], unknown>;
  let removeSpy: jest.SpyInstance<void, [key: string], unknown>;

  beforeEach(() => {
    storageManager.storage = new FakeStorage();
    getSpy = jest.spyOn(storageManager.storage, 'getItem');
    setSpy = jest.spyOn(storageManager.storage, 'setItem');
    removeSpy = jest.spyOn(storageManager.storage, 'removeItem');
  });

  afterEach(() => {
    jest.clearAllMocks();
    getSpy.mockReset();
    setSpy.mockReset();
    removeSpy.mockReset();
  });

  describe('managing tokens', () => {
    test('should get null, no tokens exists', () => {
      const token = storageManager.getToken(TokenType.access_token);
      expect(token).toBeNull();
      expect(getSpy).toHaveBeenCalledTimes(1);
    });
    test('should get token', () => {
      storageManager.saveTokens({ access_token: 'access' });
      let token = storageManager.getToken(TokenType.access_token);
      expect(token).not.toBeNull();
      expect(getSpy).toHaveBeenCalledTimes(1);
      expect(setSpy).toHaveBeenCalledTimes(1);
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).toBeNull();
      expect(getSpy).toHaveBeenCalledTimes(2);
      expect(setSpy).toHaveBeenCalledTimes(1);
      token = storageManager.getToken(TokenType.id_token);
      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
    });
    test('should get null for unsupported token type', () => {
      storageManager.saveTokens({ access_token: 'access' });
      const token = storageManager.getToken(TokenType.reset_token);
      expect(token).toBeNull();
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
      expect(token).not.toBeNull();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).not.toBeNull();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).not.toBeNull();

      storageManager.deleteTokens();
      token = storageManager.getToken(TokenType.access_token);
      expect(token).toBeNull();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).toBeNull();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).toBeNull();

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
      expect(token).not.toBeNull();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).not.toBeNull();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).not.toBeNull();

      storageManager.deleteToken(TokenType.id_token);
      token = storageManager.getToken(TokenType.access_token);
      expect(token).not.toBeNull();
      token = storageManager.getToken(TokenType.id_token);
      expect(token).toBeNull();
      token = storageManager.getToken(TokenType.refresh_token);
      expect(token).not.toBeNull();
      token = storageManager.getToken(TokenType.reset_token);
      expect(token).toBeNull();

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
      expect(tokens).not.toBeNull();
      expect(tokens?.access_token).not.toBeNull();
      expect(tokens?.id_token).not.toBeNull();
      expect(tokens?.refresh_token).not.toBeNull();
      expect(tokens?.scopes).not.toBeNull();
      expect(getSpy).toHaveBeenCalledTimes(4);
      expect(setSpy).toHaveBeenCalledTimes(4);
      expect(removeSpy).toHaveBeenCalledTimes(0);
    });
  });

  describe('managing additional storage data', () => {
    test('get device id', () => {
      const did = storageManager.getDeviceId();
      expect(did).toBeNull();
      expect(getSpy).toHaveBeenCalledTimes(1);
    });
    test('set device id', () => {
      let did = storageManager.getDeviceId();
      expect(did).toBeNull();

      storageManager.setDeviceId('device-1234');
      did = storageManager.getDeviceId();
      expect(did).not.toBeNull();

      storageManager.deleteDeviceId();
      did = storageManager.getDeviceId();
      expect(did).toBeNull();

      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });

    test('persist invitation token', () => {
      let invitation = storageManager.getInvitationToken();
      expect(invitation).toBeNull();

      storageManager.setInvitationToken('invitation-tokne-1234');
      invitation = storageManager.getInvitationToken();
      expect(invitation).not.toBeNull();

      storageManager.deleteInvitationToken();
      invitation = storageManager.getInvitationToken();
      expect(invitation).toBeNull();

      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });

    test('persist redirection url', () => {
      let redirectUrl = storageManager.getPreviousRedirectUrl();
      expect(redirectUrl).toBeNull();

      storageManager.setPreviousRedirectUrl('redirect-url-1234');
      redirectUrl = storageManager.getPreviousRedirectUrl();
      expect(redirectUrl).not.toBeNull();

      storageManager.deletePreviousRedirectUrl();
      redirectUrl = storageManager.getPreviousRedirectUrl();
      expect(redirectUrl).toBeNull();

      expect(getSpy).toHaveBeenCalledTimes(3);
      expect(setSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).toHaveBeenCalledTimes(1);
    });
  });
});
