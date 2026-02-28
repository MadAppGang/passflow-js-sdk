/**
 * Device Service
 *
 * Manages device identification for security and tracking purposes.
 * Generates and persists unique device IDs using UUID v4.
 * Used for device-based authentication and session management.
 *
 * @module device
 */

import { v4 as uuidv4 } from 'uuid';

import { StorageManager } from '../storage';

export class DeviceService {
  private storageManager: StorageManager;

  constructor(storageManager?: StorageManager) {
    this.storageManager = storageManager ?? new StorageManager();
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
