import { DeviceService } from '../device';
import { StorageManager } from '../storage';

import { AxiosClient } from './axios-client';
import { CLIAuthCompleteRequest, CLIAuthStatusResponse, PassflowConfig, PassflowEndpointPaths, pathWithParams } from './model';

export class CLIAuthAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig, storageManager?: StorageManager, deviceService?: DeviceService) {
    this.axiosClient = new AxiosClient(config, storageManager, deviceService);
  }

  setAppId(appId: string): void {
    this.axiosClient.setAppId(appId);
  }

  getCLIAuthStatus(sessionId: string): Promise<CLIAuthStatusResponse> {
    const url = pathWithParams(PassflowEndpointPaths.cliAuthStatus, { sessionId });
    return this.axiosClient.get<CLIAuthStatusResponse>(url);
  }

  completeCLIAuth(request: CLIAuthCompleteRequest): Promise<void> {
    return this.axiosClient.post<void, CLIAuthCompleteRequest>(PassflowEndpointPaths.cliAuthComplete, request);
  }
}
