import { AxiosClient } from './axios-client';
import {
  PassflowConfig,
  PassflowEndpointPaths,
  PassflowPasskeySettings,
  PassflowPasswordPolicySettings,
  PassflowSettingsAll,
} from './model';

export class SettingAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  async getSettingsAll(): Promise<PassflowSettingsAll> {
    return this.axiosClient.get<PassflowSettingsAll>(PassflowEndpointPaths.settingsAll);
  }

  async getPasswordPolicySettings(): Promise<PassflowPasswordPolicySettings> {
    return this.axiosClient.get<PassflowPasswordPolicySettings>(PassflowEndpointPaths.settingsPasswordPolicy);
  }

  async getPasskeySettings(): Promise<PassflowPasskeySettings> {
    return this.axiosClient.get<PassflowPasskeySettings>(PassflowEndpointPaths.settingsPasskey);
  }
}
