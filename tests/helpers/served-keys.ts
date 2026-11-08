/**
 * For tests that land tokens in the URL outside the PKCE harness: serves the configured server's
 * discovery document and JWKS through axios' default adapter, with node's WebCrypto, and returns
 * a token set issued with the published key. Everything is restored when the test finishes.
 *
 * The app settings are served too, for an app in Simple mode (`pkce_enabled: false`): core accepts
 * URL tokens only for apps in Simple mode.
 */
import { webcrypto } from 'node:crypto';
import axios, { type AxiosAdapter, AxiosError } from 'axios';
import { onTestFinished, vi } from 'vitest';
import {
  DISCOVERY_PATH,
  discoveryBody,
  generateSigningKey,
  type IssuedTokens,
  issuedTokens,
  JWKS_PATH,
  jwksBody,
} from './signed-tokens';

export async function serveIssuedTokens(): Promise<IssuedTokens> {
  const key = await generateSigningKey();
  const replies: Record<string, unknown> = {
    [DISCOVERY_PATH]: discoveryBody(),
    [JWKS_PATH]: jwksBody(key),
    '/app/settings': { pkce_enabled: false },
  };
  const original = axios.defaults.adapter;
  const adapter: AxiosAdapter = async (config) => {
    const data = replies[new URL(config.url ?? '', 'https://unset.example').pathname];
    if (data === undefined) throw new AxiosError('Network Error', 'ERR_NETWORK', config);
    return { data, status: 200, statusText: 'OK', headers: {}, config };
  };
  axios.defaults.adapter = adapter;
  vi.stubGlobal('crypto', webcrypto);
  onTestFinished(() => {
    axios.defaults.adapter = original;
    vi.unstubAllGlobals();
  });
  return issuedTokens(key);
}
