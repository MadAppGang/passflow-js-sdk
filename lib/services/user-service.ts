import { startRegistration } from '@simplewebauthn/browser';
import { OS, PassflowSuccessResponse, UserAPI } from '../api';

/**
 * Service for managing user profile and passkeys
 */
export class UserService {
  constructor(
    private userAPI: UserAPI,
    private deviceService: DeviceService,
  ) {}

  /**
   * Get user's registered passkeys
   * @returns Promise with passkeys array
   */
  getUserPasskeys() {
    return this.userAPI.getUserPasskeys();
  }

  /**
   * Rename a user passkey
   * @param name The new name for the passkey
   * @param passkeyId The ID of the passkey to rename
   * @returns Promise with success response
   */
  renameUserPasskey(name: string, passkeyId: string): Promise<PassflowSuccessResponse> {
    return this.userAPI.renameUserPasskey(name, passkeyId);
  }

  /**
   * Delete a user passkey
   * @param passkeyId The ID of the passkey to delete
   * @returns Promise with success response
   */
  deleteUserPasskey(passkeyId: string): Promise<PassflowSuccessResponse> {
    return this.userAPI.deleteUserPasskey(passkeyId);
  }

  /**
   * Add a new passkey for the current user
   * @param options Optional parameters for the passkey
   * @returns Promise that resolves when the passkey is added
   */
  async addUserPasskey({
    relyingPartyId,
    passkeyUsername,
    passkeyDisplayName,
  }: {
    relyingPartyId?: string;
    passkeyUsername?: string;
    passkeyDisplayName?: string;
  } = {}): Promise<void> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    const { challenge_id, publicKey } = await this.userAPI.addUserPasskeyStart({
      relyingPartyId: relyingPartyId || window?.location?.hostname,
      deviceId,
      os,
      passkeyDisplayName,
      passkeyUsername,
    });
    // user handle should be base64 encoded for simplewebauthn lib we are using
    publicKey.user.id = btoa(publicKey.user.id);
    const webauthn = await startRegistration({ optionsJSON: publicKey });
    return await this.userAPI.addUserPasskeyComplete(webauthn, deviceId, challenge_id);
  }
}

// We need to import DeviceService after the class definition to avoid circular dependency
import { DeviceService } from '../device';
