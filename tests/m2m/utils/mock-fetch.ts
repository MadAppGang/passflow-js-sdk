/**
 * Mock fetch utilities for M2M Authentication tests
 */

import { type Mock, vi } from 'vitest';

/**
 * Mock fetch response interface
 */
interface MockFetchResponse {
  ok: boolean;
  status: number;
  statusText: string;
  headers: Headers;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}

/**
 * Setup fetch mock with vi.fn()
 */
export function setupFetchMock(): Mock {
  const mockFetch = vi.fn();
  global.fetch = mockFetch as unknown as typeof fetch;
  return mockFetch;
}

/**
 * Mock a successful fetch response
 */
export function mockFetchSuccess(mockFetch: Mock, data: unknown, headers?: Record<string, string>): void {
  const responseHeaders = new Headers(headers || {});

  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: responseHeaders,
    json: async () => data,
    text: async () => JSON.stringify(data),
  } satisfies MockFetchResponse);
}

/**
 * Mock a fetch error response
 */
export function mockFetchError(mockFetch: Mock, status: number, data: unknown, headers?: Record<string, string>): void {
  const responseHeaders = new Headers(headers || {});

  mockFetch.mockResolvedValueOnce({
    ok: false,
    status,
    statusText: getStatusText(status),
    headers: responseHeaders,
    json: async () => data,
    text: async () => JSON.stringify(data),
  } satisfies MockFetchResponse);
}

/**
 * Mock a network error (connection failure)
 */
export function mockNetworkError(mockFetch: Mock, error?: Error): void {
  const networkError = error || new TypeError('Failed to fetch');
  mockFetch.mockRejectedValueOnce(networkError);
}

/**
 * Mock a timeout (AbortError)
 */
export function mockTimeout(mockFetch: Mock): void {
  const timeoutError = new Error('The operation was aborted');
  timeoutError.name = 'AbortError';
  mockFetch.mockRejectedValueOnce(timeoutError);
}

/**
 * Reset fetch mock to initial state
 */
export function resetFetchMock(mockFetch: Mock): void {
  mockFetch.mockReset();
}

/**
 * Get HTTP status text for common status codes
 */
function getStatusText(status: number): string {
  const statusTexts: Record<number, string> = {
    200: 'OK',
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    429: 'Too Many Requests',
    500: 'Internal Server Error',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
  };

  return statusTexts[status] || 'Unknown';
}

/**
 * Create a mock Response object (for advanced usage)
 */
export function createMockResponse(
  data: unknown,
  options: {
    status?: number;
    statusText?: string;
    headers?: Record<string, string>;
  } = {},
): MockFetchResponse {
  const status = options.status || 200;
  const responseHeaders = new Headers(options.headers || {});

  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: options.statusText || getStatusText(status),
    headers: responseHeaders,
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

/**
 * Assert that fetch was called with correct parameters
 */
export function assertFetchCalledWith(
  mockFetch: Mock,
  expectedUrl: string,
  expectedOptions?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  },
): void {
  expect(mockFetch).toHaveBeenCalled();

  const callArgs = mockFetch.mock.calls[0];
  const [url, options] = callArgs as [string, RequestInit];

  expect(url).toBe(expectedUrl);

  if (expectedOptions?.method) {
    expect(options.method).toBe(expectedOptions.method);
  }

  if (expectedOptions?.headers) {
    const actualHeaders = options.headers as Record<string, string>;
    for (const [key, value] of Object.entries(expectedOptions.headers)) {
      expect(actualHeaders[key]).toBe(value);
    }
  }

  if (expectedOptions?.body) {
    expect(options.body).toBe(expectedOptions.body);
  }
}

/**
 * Get the request body from the last fetch call
 */
export function getLastFetchBody(mockFetch: Mock): string | undefined {
  const lastCall = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
  if (!lastCall) return undefined;

  const [, options] = lastCall as [string, RequestInit];
  return options.body as string | undefined;
}

/**
 * Get the request headers from the last fetch call
 */
export function getLastFetchHeaders(mockFetch: Mock): Record<string, string> | undefined {
  const lastCall = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
  if (!lastCall) return undefined;

  const [, options] = lastCall as [string, RequestInit];
  return options.headers as Record<string, string> | undefined;
}

/**
 * Mock multiple fetch responses in sequence
 */
export function mockFetchSequence(mockFetch: Mock, responses: Array<{ data: unknown; status?: number }>): void {
  for (const response of responses) {
    const status = response.status || 200;
    const responseHeaders = new Headers();

    mockFetch.mockResolvedValueOnce({
      ok: status >= 200 && status < 300,
      status,
      statusText: getStatusText(status),
      headers: responseHeaders,
      json: async () => response.data,
      text: async () => JSON.stringify(response.data),
    } satisfies MockFetchResponse);
  }
}
