import { AoothConfig, AoothEndpointPaths, AppAPI } from 'lib/api';
import { AxiosClient } from 'lib/api/axios-client';

const mockAppSettings = {
  id: '2UOCBvXSzD6HNDyLXXNAnRO9zuu',
  secret: '',
  active: false,
  name: 'The new super app',
  description: 'The app created in postman',
  offline: true,
  type: 'web',
  redirect_urls: null,
  login_app_settings: null,
  custom_email_templates: false,
  auth_strategies: [
    {
      strategy: {
        identity: 'email',
        challenge: 'password',
        transport: 'none',
      },
      type: 'first_factor_internal',
    },
    {
      strategy: {
        identity: 'phone',
        challenge: 'password',
        transport: 'none',
      },
      type: 'first_factor_internal',
    },
    {
      strategy: {
        identity: 'phone',
        challenge: 'otm',
        transport: 'sms',
      },
      type: 'first_factor_internal',
    },
    {
      strategy: {
        identity: 'email',
        challenge: 'magic_link',
        transport: 'email',
      },
      type: 'first_factor_internal',
    },
  ],
  custom_sms_messages: null,
  registration_allowed: true,
  passwordless_registration_allowed: true,
  anonymous_registration_allowed: false,
  fim_merge_by_email_allowed: true,
  debug_otp_code_allowed: false,
  debug_otp_code_for_registration: '',
};

const mockAppSettingsError = {
  error: {
    id: 'error.not.found',
    message: 'app with id test-app-id not found!',
    status: 404,
    location: '/go/src/github.com/madappgang/aooth/web/routers/app_router.go:52',
    time: '2023-10-31T12:15:29.263132239Z',
  },
};

describe('AppAPI', () => {
  let appAPI: AppAPI;

  beforeAll(() => {
    const mockConfig: AoothConfig = {
      appId: 'test-app-id',
      url: 'https://test-base-url.com',
    };

    appAPI = new AppAPI(mockConfig);
  });

  describe('getAppSettings', () => {
    it('Should call get method with the correct appId', async () => {
      const axiosClientGetMock = jest.spyOn(AxiosClient.prototype, 'get').mockResolvedValue(mockAppSettings);
      const appSettings = await appAPI.getAppSettings();

      expect(axiosClientGetMock).toHaveBeenCalledWith(AoothEndpointPaths.appSettings);
      expect(appSettings).toEqual(mockAppSettings);
    });

    it('Should call get method with the incorrect appId', async () => {
      const axiosClientGetMock = jest.spyOn(AxiosClient.prototype, 'get').mockResolvedValue(mockAppSettingsError);
      const appSettings = await appAPI.getAppSettings();

      expect(axiosClientGetMock).toHaveBeenCalledWith(AoothEndpointPaths.appSettings);
      expect(appSettings).toEqual(mockAppSettingsError);
    });
  });
});
