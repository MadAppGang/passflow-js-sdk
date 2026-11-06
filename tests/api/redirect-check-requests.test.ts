/** `checkRedirectUrl`: what goes on the wire and what a caller gets back, through the real AxiosClient. */
import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios';
import { describe, expect, test } from 'vitest';
import { AuthAPI } from '../../lib/api/auth';
import { StorageManager } from '../../lib/storage';
import { TEST_CONFIG } from '../helpers/fixtures';

const setup = (status: number, data: unknown) => {
  localStorage.clear();
  const api = new AuthAPI(TEST_CONFIG, new StorageManager({ prefix: '' }));
  const requests: InternalAxiosRequestConfig[] = [];
  const adapter: AxiosAdapter = async (config) => {
    requests.push(config);
    const response = { data, status, statusText: '', headers: {}, config };
    if (status >= 400) throw Object.assign(new Error(`status ${status}`), { isAxiosError: true, config, response });
    return response;
  };
  (api as unknown as { axiosClient: { instance: { defaults: { adapter: unknown } } } }).axiosClient.instance.defaults.adapter =
    adapter;
  return { api, requests };
};

describe('checkRedirectUrl', () => {
  test('posts the address and resolves to the one the server answers with', async () => {
    const { api, requests } = setup(200, { redirect_url: 'https://app.example/canonical' });
    await expect(api.checkRedirectUrl('https://app.example/given')).resolves.toBe('https://app.example/canonical');
    expect(requests[0].url).toBe('/auth/redirect/check');
    expect(requests[0].method).toBe('post');
    expect(JSON.parse(requests[0].data)).toEqual({ redirect_url: 'https://app.example/given' });
  });

  test('a refusal rejects with the server error id', async () => {
    const { api } = setup(400, {
      error: { id: 'error.app.redirect.url.not.registered', message: 'Not registered', status: 400 },
    });
    await expect(api.checkRedirectUrl('https://other.example')).rejects.toMatchObject({
      id: 'error.app.redirect.url.not.registered',
      status: 400,
    });
  });

  test('a failure with no server error still rejects', async () => {
    const { api } = setup(500, 'internal failure');
    await expect(api.checkRedirectUrl('https://app.example')).rejects.toMatchObject({ id: 'error.redirect.check' });
  });

  test('a gateway 502 rejects with the service-unavailable error', async () => {
    const { api } = setup(502, 'bad gateway');
    await expect(api.checkRedirectUrl('https://app.example')).rejects.toMatchObject({
      id: 'error.service.unavailable',
      status: 502,
    });
  });
});
