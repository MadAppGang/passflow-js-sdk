/**
 * The assurance-upgrade API — the prepare round of a step-up.
 *
 * One endpoint, deliberately. The commit round is `POST /auth/refresh`, which
 * belongs to `AuthAPI` because that is the only path that stores the rotated
 * tokens; splitting it off here would elevate the session on the server and
 * leave the client holding stale ones.
 *
 * Constructed exactly like `AuthAPI`, sharing `StorageManager` and
 * `DeviceService`, which is what makes cookie mode, CSRF and the device headers
 * work without duplicating any of it.
 */

import type { AxiosRequestConfig } from 'axios';

import type { DeviceService } from '../device';
import type { StorageManager } from '../storage';
import { markUpgradeTransaction } from '../upgrade/markers';

import { AxiosClient } from './axios-client';
import { type PassflowConfig, PassflowEndpointPaths, type UpgradeStartWire } from './model';

/** The `POST /auth/upgrade/start` request body. `relying_party_id` is passkey-only. */
export type UpgradeStartPayload = {
  method: string;
  relying_party_id?: string;
};

export class UpgradeAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig, storageManager?: StorageManager, deviceService?: DeviceService) {
    this.axiosClient = new AxiosClient(config, storageManager, deviceService);
  }

  setAppId(appId: string): void {
    this.axiosClient.setAppId(appId);
  }

  /**
   * Issues a single-use, session-bound upgrade challenge.
   *
   * Returns the raw snake_case body: normalisation is the transport's job, and
   * keeping it out of here means the wire shape has exactly one definition.
   *
   * The request carries the upgrade-transaction marker, so a 401 from this round
   * — a stale access token, a foreign session — is recognised as part of an
   * elevation by the response interceptor and does not invalidate the session
   * behind the user's back.
   */
  startUpgrade(payload: UpgradeStartPayload): Promise<UpgradeStartWire> {
    return this.axiosClient.post<UpgradeStartWire, UpgradeStartPayload>(
      PassflowEndpointPaths.upgradeStart,
      payload,
      markUpgradeTransaction<AxiosRequestConfig>({}),
    );
  }
}
