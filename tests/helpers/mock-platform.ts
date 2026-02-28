import { type Mock, vi } from 'vitest';
import type { PlatformAdapter } from '../../lib/platform';

export type MockPlatform = {
  storage: object;
  getCurrentUrl: Mock;
  replaceUrl: Mock;
  navigateTo: Mock;
  onForeground: Mock;
  onBackground: Mock;
  onBeforeUnload: Mock;
  isInForeground: Mock;
  openAuthUrl: Mock;
  passkeys: {
    startRegistration: Mock;
    startAuthentication: Mock;
  };
  btoa: Mock;
  atob: Mock;
  cookiesSupported: Mock;
  getDeviceType: Mock;
};

export function createMockPlatform(overrides?: Partial<MockPlatform>): MockPlatform & PlatformAdapter {
  return {
    storage: {},
    getCurrentUrl: vi.fn().mockReturnValue({
      href: 'https://test-hostname.com/',
      origin: 'https://test-hostname.com',
      pathname: '/',
      search: '',
      hash: '',
      hostname: 'test-hostname.com',
    }),
    replaceUrl: vi.fn(),
    navigateTo: vi.fn(),
    onForeground: vi.fn().mockReturnValue(vi.fn()),
    onBackground: vi.fn().mockReturnValue(vi.fn()),
    onBeforeUnload: vi.fn().mockReturnValue(vi.fn()),
    isInForeground: vi.fn().mockReturnValue(true),
    openAuthUrl: vi.fn().mockResolvedValue({ callbackSearch: '', callbackHash: '' }),
    passkeys: {
      startRegistration: vi.fn().mockResolvedValue({ id: 'reg-id' }),
      startAuthentication: vi.fn().mockResolvedValue({ id: 'auth-id' }),
    },
    btoa: vi.fn().mockImplementation((s: string) => Buffer.from(s).toString('base64')),
    atob: vi.fn().mockImplementation((s: string) => Buffer.from(s, 'base64').toString('utf-8')),
    cookiesSupported: vi.fn().mockReturnValue(false),
    getDeviceType: vi.fn().mockReturnValue('web'),
    ...overrides,
  } as MockPlatform & PlatformAdapter;
}
