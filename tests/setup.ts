import { vi } from 'vitest';

// Mock window location
const mockLocation = {
  hostname: 'example.com',
  origin: 'https://example.com',
  href: 'https://example.com',
  pathname: '/',
  search: '',
  hash: '',
  replace: vi.fn(),
  reload: vi.fn(),
  assign: vi.fn(),
};

Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
});

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: vi.fn((key: string) => store[key] || null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = String(value);
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    length: 0,
    key: vi.fn((_index: number) => null),
  };
})();

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
  writable: false,
});

// Mock URLSearchParams
class MockURLSearchParams {
  params: Map<string, string>;

  constructor(init?: string | Record<string, string>) {
    this.params = new Map();
    if (init) {
      if (typeof init === 'string') {
        init.split('&').forEach((param) => {
          const [key, value] = param.split('=');
          if (key) this.params.set(key, value || '');
        });
      } else if (typeof init === 'object') {
        Object.entries(init).forEach(([key, value]) => {
          this.params.set(key, value);
        });
      }
    }
  }

  get(key: string): string | null {
    return this.params.get(key) || null;
  }

  set(key: string, value: string): void {
    this.params.set(key, value);
  }

  delete(key: string): void {
    this.params.delete(key);
  }

  toString(): string {
    const result: string[] = [];
    this.params.forEach((value, key) => {
      result.push(`${key}=${value}`);
    });
    return result.join('&');
  }

  get size(): number {
    return this.params.size;
  }
}

// biome-ignore lint/suspicious/noExplicitAny: <explanation>
global.URLSearchParams = MockURLSearchParams as any;
