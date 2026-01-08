import { DeviceService } from '../device';
import { StorageManager } from '../storage';

import { AxiosClient } from './axios-client';
import { type AppSettings, type PassflowConfig, PassflowEndpointPaths } from './model';

export class AppAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig, storageManager?: StorageManager, deviceService?: DeviceService) {
    this.axiosClient = new AxiosClient(config, storageManager, deviceService);
  }

  getAppSettings(): Promise<AppSettings> {
    return this.axiosClient.get<AppSettings>(PassflowEndpointPaths.appSettings);
  }
}
