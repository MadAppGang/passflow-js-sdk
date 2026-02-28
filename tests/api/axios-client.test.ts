import { beforeEach, describe, expect, test, vi } from 'vitest';
import { AxiosClient } from '../../lib/api/axios-client';
import { APP_ID_HEADER_KEY, DEVICE_ID_HEADER_KEY, DEVICE_TYPE_HEADER_KEY } from '../../lib/constants';
import { createMockPlatform } from '../helpers/mock-platform';

// Mock axios
vi.mock('axios', () => ({
  default: {
    create: vi.fn(() => ({
      interceptors: {
        request: { use: vi.fn() },
        response: { use: vi.fn() },
      },
      request: vi.fn(),
    })),
  },
  AxiosError: class AxiosError extends Error {},
}));

// Mock DeviceService
vi.mock('../../lib/device', () => ({
  DeviceService: vi.fn(() => ({
    getDeviceId: () => 'test-device-id-123',
  })),
}));

// Configurable storage mock — tests can override getItem behavior
let mockStorageGetItem: (key: string) => string | null = () => null;

vi.mock('../../lib/storage', () => ({
  StorageManager: vi.fn(() => ({
    getTokens: () => null,
    getScopes: () => [],
    storage: {
      getItem: (key: string) => mockStorageGetItem(key),
      // biome-ignore lint/suspicious/noEmptyBlockStatements: intentional no-op for mock
      setItem: () => {},
      // biome-ignore lint/suspicious/noEmptyBlockStatements: intentional no-op for mock
      removeItem: () => {},
    },
  })),
}));

// Mock TokenService
vi.mock('../../lib/token', () => ({
  TokenService: vi.fn(() => ({})),
  isTokenExpired: vi.fn(),
  parseToken: vi.fn(),
}));

describe('AxiosClient Device Headers', () => {
  let _axiosClient: AxiosClient;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('should include device headers in default headers', async () => {
    const config = {
      url: 'https://api.example.com',
      appId: 'test-app-id',
    };

    _axiosClient = new AxiosClient(config);

    // Get the mocked axios module
    const axios = await import('axios');
    const mockAxiosCreate = vi.mocked(axios.default.create);

    // Verify that axios.create was called with the correct headers
    expect(mockAxiosCreate).toHaveBeenCalledWith({
      baseURL: 'https://api.example.com',
      headers: expect.objectContaining({
        Accept: 'application/json',
        'Content-Type': 'application/json',
        [APP_ID_HEADER_KEY]: 'test-app-id',
        [DEVICE_ID_HEADER_KEY]: 'test-device-id-123',
        [DEVICE_TYPE_HEADER_KEY]: 'web',
      }),
    });
  });

  test('should include device headers even without appId', async () => {
    const config = {
      url: 'https://api.example.com',
    };

    _axiosClient = new AxiosClient(config);

    // Get the mocked axios module
    const axios = await import('axios');
    const mockAxiosCreate = vi.mocked(axios.default.create);

    // Verify that axios.create was called with device headers even without appId
    expect(mockAxiosCreate).toHaveBeenCalledWith({
      baseURL: 'https://api.example.com',
      headers: expect.objectContaining({
        Accept: 'application/json',
        'Content-Type': 'application/json',
        [DEVICE_ID_HEADER_KEY]: 'test-device-id-123',
        [DEVICE_TYPE_HEADER_KEY]: 'web',
      }),
    });

    // Verify that appId header is not included when no appId is provided
    const callArgs = mockAxiosCreate.mock.calls[0][0];
    expect(callArgs.headers).not.toHaveProperty(APP_ID_HEADER_KEY);
  });

  test('should set device type header to "web"', async () => {
    const config = {
      url: 'https://api.example.com',
      appId: 'test-app-id',
    };

    _axiosClient = new AxiosClient(config);

    // Get the mocked axios module
    const axios = await import('axios');
    const mockAxiosCreate = vi.mocked(axios.default.create);

    const callArgs = mockAxiosCreate.mock.calls[0][0];
    expect(callArgs.headers[DEVICE_TYPE_HEADER_KEY]).toBe('web');
  });
});

describe('AxiosClient Cookie Support Enforcement', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset storage behavior
    mockStorageGetItem = () => null;
  });

  test('should throw when cookie mode is persisted but platform does not support cookies', () => {
    // Simulate persisted cookie delivery mode from a previous session
    mockStorageGetItem = (key: string) => {
      if (key === 'passflow_delivery_mode') return 'cookie';
      return null;
    };

    const platform = createMockPlatform({
      cookiesSupported: vi.fn().mockReturnValue(false),
    });

    expect(() => {
      new AxiosClient({ url: 'https://api.example.com', platform });
    }).toThrow('Cookie delivery mode is configured but cookies are not supported');
  });

  test('should not throw when cookie mode is persisted and platform supports cookies', () => {
    // Simulate persisted cookie delivery mode
    mockStorageGetItem = (key: string) => {
      if (key === 'passflow_delivery_mode') return 'cookie';
      return null;
    };

    const platform = createMockPlatform({
      cookiesSupported: vi.fn().mockReturnValue(true),
    });

    expect(() => {
      new AxiosClient({ url: 'https://api.example.com', platform });
    }).not.toThrow();
  });

  test('should not throw when delivery mode is json_body regardless of cookie support', () => {
    // Default: no persisted delivery mode (falls back to json_body)
    const platform = createMockPlatform({
      cookiesSupported: vi.fn().mockReturnValue(false),
    });

    expect(() => {
      new AxiosClient({ url: 'https://api.example.com', platform });
    }).not.toThrow();
  });
});
