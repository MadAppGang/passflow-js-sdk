/**
 * `createClient` — the greenfield surface, for a developer with no HTTP client
 * of their own.
 *
 * It is **not a fourth code path**: it is `axios.create(config)` followed by the
 * axios adapter, which is why it cannot drift from `attachAuth`. The attach is
 * passed in rather than imported so this module holds no scope, no controller
 * and no options — only the constructor.
 *
 * It also costs no new dependency: `axios` is already a hard dependency of this
 * package. This is the one place axios' own types are deliberately back on the
 * public surface — `attachAuth`'s structural `ResponseInterceptorHost` exists to
 * avoid exactly that, and the asymmetry is the point: a developer asking us to
 * BUILD their client has accepted axios, while one handing us their own must not
 * be pinned to our major.
 */

import axios, { type AxiosInstance, type CreateAxiosDefaults } from 'axios';

import type { ResponseInterceptorHost } from './axios-adapter';

/**
 * axios' own create options plus nothing of ours, so `baseURL`, `headers`,
 * `timeout`, `adapter` and interceptor ordering all stay the customer's.
 *
 * A `baseURL` is NOT read as a declared backend: that would be the derived
 * interception model through a side door. An un-declared `baseURL` gets a
 * `'challenge-out-of-scope'` diagnostic naming `backend` as the fix.
 */
export type CreateClientConfig = CreateAxiosDefaults;

export const createUpgradeClient = (
  config: CreateClientConfig | undefined,
  attachAuth: (host: ResponseInterceptorHost) => () => void,
): AxiosInstance => {
  const instance = axios.create(config);
  attachAuth(instance);
  return instance;
};
