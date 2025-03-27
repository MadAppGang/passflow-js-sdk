// Mock global objects and APIs

// Mock window location
const mockLocation = {
  hostname: 'example.com',
  origin: 'https://example.com',
  href: 'https://example.com',
  pathname: '/',
  search: '',
  hash: '',
  replace: jest.fn(),
  reload: jest.fn(),
  assign: jest.fn(),
};

Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
});

// Mock localStorage
const localStorageMock = (function() {
  let store = {};
  return {
    getItem: jest.fn(key => store[key] || null),
    setItem: jest.fn((key, value) => {
      store[key] = value.toString();
    }),
    removeItem: jest.fn(key => {
      delete store[key];
    }),
    clear: jest.fn(() => {
      store = {};
    }),
    length: 0,
    key: jest.fn(index => null)
  };
})();

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
  writable: false
});

// Mock URLSearchParams
global.URLSearchParams = class URLSearchParams {
  constructor(init) {
    this.params = new Map();
    if (init) {
      if (typeof init === 'string') {
        init.split('&').forEach(param => {
          const [key, value] = param.split('=');
          this.params.set(key, value);
        });
      } else if (typeof init === 'object') {
        Object.entries(init).forEach(([key, value]) => {
          this.params.set(key, value);
        });
      }
    }
  }

  get(key) {
    return this.params.get(key) || null;
  }

  set(key, value) {
    return this.params.set(key, value);
  }

  delete(key) {
    return this.params.delete(key);
  }

  toString() {
    const result = [];
    this.params.forEach((value, key) => {
      result.push(`${key}=${value}`);
    });
    return result.join('&');
  }

  get size() {
    return this.params.size;
  }
}; 