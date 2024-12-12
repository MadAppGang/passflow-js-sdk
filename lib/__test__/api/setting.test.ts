import { PassflowConfig, PassflowEndpointPaths, SettingAPI } from 'lib/api';
import { AxiosClient } from 'lib/api/axios-client';

const mockSettingsAll = {
  password_policy: {
    restrict_min_password_length: true,
    min_password_length: 8,
    reject_compromised: true,
    enforce_password_strength: 'average',
    require_lowercase: true,
    require_uppercase: true,
    require_number: true,
    require_symbol: true,
  },
  passkey_provider: {
    name: 'aooth.com',
    display_name: 'Aooth server',
    id_field: 'email',
    validation: 'none',
    registration: {
      user_verification: 'discouraged',
      authenticator_attachment: 'any',
      discoverable_key: 'preferred',
      attestation_metadata: 'preferred',
      extensions: null,
    },
  },
};

describe('AppAPI', () => {
  let settingAPI: SettingAPI;

  beforeEach(() => {
    const mockConfig: PassflowConfig = {
      appId: 'test-app-id',
      url: 'https://test-base-url.com',
    };

    settingAPI = new SettingAPI(mockConfig);
  });

  describe('getSettingsAll', () => {
    it('Should call getSettingAll method', async () => {
      const axiosClientGetMock = jest.spyOn(AxiosClient.prototype, 'get').mockResolvedValue(mockSettingsAll);
      const settings = await settingAPI.getSettingsAll();

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.settingsAll);
      expect(settings).toEqual(mockSettingsAll);
    });
  });

  describe('getPasswordPolicySettings', () => {
    it('Should call getPasswordPolicySettings method', async () => {
      const axiosClientGetMock = jest.spyOn(AxiosClient.prototype, 'get').mockResolvedValue(mockSettingsAll.password_policy);
      const settings = await settingAPI.getPasswordPolicySettings();

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.settingsPasswordPolicy);
      expect(settings).toEqual(mockSettingsAll.password_policy);
    });
  });

  describe('getPasskeySettings', () => {
    it('Should call getPasskeySettings method', async () => {
      const axiosClientGetMock = jest.spyOn(AxiosClient.prototype, 'get').mockResolvedValue(mockSettingsAll.passkey_provider);
      const settings = await settingAPI.getPasskeySettings();

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.settingsPasskey);
      expect(settings).toEqual(mockSettingsAll.passkey_provider);
    });
  });
});
