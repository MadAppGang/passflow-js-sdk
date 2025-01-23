import { AxiosClient } from './axios-client';
import {
  type PassflowConfig,
  PassflowEndpointPaths,
  type PassflowPasskeySettings,
  type PassflowPasswordPolicySettings,
  type PassflowSettingsAll,
} from './model';

export class SettingAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  getSettingsAll(): Promise<PassflowSettingsAll> {
    return this.axiosClient.get<PassflowSettingsAll>(PassflowEndpointPaths.settingsAll);
  }

  getPasswordPolicySettings(): Promise<PassflowPasswordPolicySettings> {
    return this.axiosClient.get<PassflowPasswordPolicySettings>(PassflowEndpointPaths.settingsPasswordPolicy);
  }

  getPasskeySettings(): Promise<PassflowPasskeySettings> {
    return this.axiosClient.get<PassflowPasskeySettings>(PassflowEndpointPaths.settingsPasskey);
  }
}
