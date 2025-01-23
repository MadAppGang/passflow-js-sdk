import { AxiosClient } from './axios-client';
import { type AppSettings, type PassflowConfig, PassflowEndpointPaths } from './model';

export class AppAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  getAppSettings(): Promise<AppSettings> {
    return this.axiosClient.get<AppSettings>(PassflowEndpointPaths.appSettings);
  }
}
