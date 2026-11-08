/**
 * The assurance-upgrade API.
 *
 * For the token session only the prepare round is here. Its commit round is
 * `POST /auth/refresh`, which belongs to `AuthAPI` because that is the only path
 * that stores the new token pair. The hosted cookie session's two rounds are
 * both here, because they store nothing.
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
import { type PassflowConfig, PassflowEndpointPaths, type UpgradeRefreshField, type UpgradeStartWire } from './model';

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

  /**
   * Issues an upgrade challenge for the hosted sign-in session. Authenticated by the session
   * cookie alone: no bearer is sent and no stored token is refreshed first (see `AxiosClient`).
   * Same answer shape as `startUpgrade`.
   */
  startHostedUpgrade(payload: UpgradeStartPayload): Promise<UpgradeStartWire> {
    return this.axiosClient.post<UpgradeStartWire, UpgradeStartPayload>(PassflowEndpointPaths.hostedUpgradeStart, payload, {
      withCredentials: true,
    });
  }

  /**
   * Proves the factor for the hosted sign-in session. The body is the proof itself, not wrapped.
   * The server answers 204 and issues nothing, so nothing is stored.
   */
  async commitHostedUpgrade(upgrade: UpgradeRefreshField): Promise<void> {
    await this.axiosClient.post<void, UpgradeRefreshField>(PassflowEndpointPaths.hostedUpgrade, upgrade, {
      withCredentials: true,
    });
  }
}
