import { AxiosClient } from './axios-client';
import { AoothConfig, AoothEndpointPaths, AoothPasskeySettings, AoothPasswordPolicySettings, AoothSettingsAll } from './model';

export class SettingAPI {
  protected axiosClient: AxiosClient;

  constructor(config: AoothConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  async getSettingsAll(): Promise<AoothSettingsAll> {
    return this.axiosClient.get<AoothSettingsAll>(AoothEndpointPaths.settingsAll);
  }

  async getPasswordPolicySettings(): Promise<AoothPasswordPolicySettings> {
    return this.axiosClient.get<AoothPasswordPolicySettings>(AoothEndpointPaths.settingsPasswordPolicy);
  }

  async getPasskeySettings(): Promise<AoothPasskeySettings> {
    return this.axiosClient.get<AoothPasskeySettings>(AoothEndpointPaths.settingsPasskey);
  }
}
