import { AxiosClient } from './axios-client';
import { AoothConfig, AoothEndpointPaths, AppSettings } from './model';

export class AppAPI {
  protected axiosClient: AxiosClient;

  constructor(config: AoothConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  async getAppSettings(): Promise<AppSettings> {
    return this.axiosClient.get<AppSettings>(AoothEndpointPaths.appSettings);
  }
}
