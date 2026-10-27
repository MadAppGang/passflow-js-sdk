import type { UpgradeInterceptorOptions } from '../../lib/upgrade/core';

export const base = 'https://app.example/page';
export const challengeHeader = 'Bearer error="insufficient_user_authentication", acr_values="2"';
export const challengeResponse = (status = 401, params = challengeHeader) =>
  new Response(JSON.stringify({ error: 'upgrade_required', acr_values: '2' }), {
    status,
    headers: { 'www-authenticate': params, 'content-type': 'application/json' },
  });
export const options = (overrides: Partial<UpgradeInterceptorOptions> = {}): UpgradeInterceptorOptions => ({
  scope: { passflow: { origin: 'https://app.example' }, backend: ['https://app.example'] },
  elevate: async () => {},
  onUpgradeDiagnostic: () => {},
  ...overrides,
});
export const deferred = <T>() => {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
};
export const scopeFixtures = [
  { id: 'SF-1', input: '/api/x', inside: true },
  { id: 'SF-2', input: '//evil.example/x', inside: false },
  { id: 'SF-3', input: '/' + String.fromCharCode(92) + 'evil.example/x', inside: false },
  { id: 'SF-4', input: '/' + String.fromCharCode(9) + '/evil.example/x', inside: false },
  { id: 'SF-5', input: '/' + String.fromCharCode(10) + '/evil.example/x', inside: false },
  { id: 'SF-6', input: '/' + String.fromCharCode(13) + '/evil.example/x', inside: false },
  { id: 'SF-7', input: String.fromCharCode(92, 92) + 'evil.example/x', inside: false },
  { id: 'SF-8', input: String.fromCharCode(92) + '/evil.example/x', inside: false },
  { id: 'SF-9', input: '/%5Cevil.example/x', inside: true },
  { id: 'SF-10', input: '/%5cevil.example/x', inside: true },
  { id: 'SF-11', input: '/%09/evil.example/x', inside: true },
  { id: 'SF-12', input: '/%2F%2Fevil.example/x', inside: true },
];
