/**
 * `setAppId` changes the app id every later request sends, whether or not the client was
 * built with one. Real AxiosClient over a real StorageManager; only the HTTP adapter is stubbed.
 */

import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { beforeEach, describe, expect, test } from 'vitest';
import { AxiosClient } from '../../lib/api/axios-client';
import { APP_ID_HEADER_KEY } from '../../lib/constants';
import { StorageManager } from '../../lib/storage';
import { createMockPlatform } from '../helpers/mock-platform';

describe('AxiosClient.setAppId', () => {
  let sent: InternalAxiosRequestConfig[];

  const build = (appId?: string) => {
    const client = new AxiosClient(
      { url: 'https://api.example.com', ...(appId ? { appId } : {}), platform: createMockPlatform() },
      new StorageManager({ prefix: '' }),
    );
    (client as unknown as { instance: { defaults: { adapter: unknown } } }).instance.defaults.adapter = async (
      config: InternalAxiosRequestConfig,
    ): Promise<AxiosResponse> => {
      sent.push(config);
      return { data: {}, status: 200, statusText: 'OK', headers: {}, config };
    };
    return client;
  };

  beforeEach(() => {
    localStorage.clear();
    sent = [];
  });

  test('a client built with an app id sends the new one after setAppId', async () => {
    const client = build('A');
    client.setAppId('B');

    await client.get('/settings');

    expect(sent).toHaveLength(1);
    expect(sent[0].headers.get(APP_ID_HEADER_KEY)).toBe('B');
  });

  test('a client built without an app id sends the one set later', async () => {
    const client = build();
    client.setAppId('B');

    await client.get('/settings');

    expect(sent[0].headers.get(APP_ID_HEADER_KEY)).toBe('B');
  });
});
