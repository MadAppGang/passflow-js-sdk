import { beforeEach, describe, expect, test, vi } from 'vitest';
import { AxiosClient } from '../../lib/api/axios-client';
import { APP_ID_HEADER_KEY, DEVICE_ID_HEADER_KEY, DEVICE_TYPE_HEADER_KEY } from '../../lib/constants';

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
vi.mock('../../lib/device-service', () => ({
  DeviceService: vi.fn(() => ({
    getDeviceId: () => 'test-device-id-123',
  })),
}));

// Mock StorageManager
vi.mock('../../lib/storage-manager', () => ({
  StorageManager: vi.fn(() => ({
    getTokens: () => null,
    getScopes: () => [],
  })),
}));

// Mock TokenService
vi.mock('../../lib/token-service', () => ({
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
