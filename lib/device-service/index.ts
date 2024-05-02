import { v4 as uuidv4 } from 'uuid';

import { StorageManager } from '../storage-manager';

export class DeviceService {
  private storageManager: StorageManager;

  constructor() {
    this.storageManager = new StorageManager();
  }

  getDeviceId(): string {
    const deviceId = this.storageManager.getDeviceId();
    if (!deviceId) {
      const newDeviceId = this.generateUniqueDeviceId();
      this.storageManager.setDeviceId(newDeviceId);
      return newDeviceId;
    }
    return deviceId;
  }

  generateUniqueDeviceId(): string {
    return uuidv4();
  }
}
