import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import {
  APP_ID_HEADER_KEY,
  AUTHORIZATION_HEADER_KEY,
  DEVICE_ID_HEADER_KEY,
  DEVICE_TYPE_HEADER_KEY,
  PASSFLOW_CLOUD_URL,
  TOKEN_EXPIRY_BUFFER_SECONDS,
} from '../constants';

import { DeviceService } from '../device';
import { StorageManager } from '../storage';
import { TokenService, isTokenExpired, parseToken } from '../token';

import {
  PassflowAuthorizationResponse,
  PassflowConfig,
  PassflowEndpointPaths,
  PassflowError,
  PassflowResponseError,
  RequestMethod,
  RequestOptions,
} from './model';

export enum HttpStatuses {
  badRequest = 400,
  unauthorized = 401,
  tooManyRequests = 429,
  internalServerError = 500,
  success = 200,
  created = 201,
}

// Rate limiting retry configuration
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY_MS = 1000;

export class AxiosClient {
  private instance: AxiosInstance;
  protected storageManager: StorageManager;
  protected deviceService: DeviceService;
  private refreshPromise: Promise<AxiosResponse<PassflowAuthorizationResponse>> | null = null;
  private isRefreshing = false;

  tokenService: TokenService;

  origin = window.location.origin;
  url: string;
  appId?: string;

  protected defaultHeaders: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };

  private readonly nonAccessTokenEndpoints = ['/auth/', '/settings', '/settings/'];
  private readonly protectedEndpoints = ['logout', 'refresh'];

  constructor(config: PassflowConfig, storageManager?: StorageManager, deviceService?: DeviceService) {
    const { url, appId, keyStoragePrefix } = config;

    this.url = url || PASSFLOW_CLOUD_URL;

    // Use provided instances or create new ones (backward compatibility)
    this.storageManager =
      storageManager ??
      new StorageManager({
        prefix: keyStoragePrefix ?? '',
      });
    this.deviceService = deviceService ?? new DeviceService(this.storageManager);
    this.tokenService = new TokenService(this.storageManager);

    if (appId) {
      this.appId = appId;

      this.defaultHeaders = {
        ...this.defaultHeaders,
        [APP_ID_HEADER_KEY]: appId,
      };
    }

    // Add device headers
    const deviceId = this.deviceService.getDeviceId();
    this.defaultHeaders = {
      ...this.defaultHeaders,
      [DEVICE_ID_HEADER_KEY]: deviceId,
      [DEVICE_TYPE_HEADER_KEY]: 'web',
    };

    this.instance = axios.create({
      baseURL: this.url,
      headers: { ...this.defaultHeaders },
    });

    this.instance.interceptors.request.use(async (axiosConfig: InternalAxiosRequestConfig) => {
      // Request to non-access token endpoints
      if (this.isNonAuthEndpoint(axiosConfig.url)) {
        return axiosConfig;
      }

      // Request to refresh token endpoint
      if (axiosConfig.url?.includes('refresh')) {
        if (this.isRefreshing) {
          // Abort duplicate refresh requests
          const controller = new AbortController();
          controller.abort();
          axiosConfig.signal = controller.signal;
          return axiosConfig;
        }
        return axiosConfig;
      }

      // Request to access token endpoints
      const tokens = this.storageManager.getTokens();
      const scopes = this.storageManager.getScopes();

      if (tokens?.access_token) {
        const access = parseToken(tokens.access_token);

        // Check if token is expired with buffer
        if (isTokenExpired(access, TOKEN_EXPIRY_BUFFER_SECONDS) && tokens.refresh_token) {
          try {
            // If refresh is already in progress, wait for it
            if (this.refreshPromise) {
              const response = await this.refreshPromise;
              if (response.data) {
                // Use the new token from the completed refresh
                axiosConfig.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${response.data.access_token}`;
              }
              return axiosConfig;
            }

            // Start new refresh
            this.isRefreshing = true;
            const payload = {
              refresh_token: tokens.refresh_token,
              scopes,
            };

            this.refreshPromise = this.instance.post<PassflowAuthorizationResponse>(PassflowEndpointPaths.refresh, payload, {
              headers: {
                [AUTHORIZATION_HEADER_KEY]: `Bearer ${tokens.refresh_token}`,
              },
            });

            const response = await this.refreshPromise;

            if (response.data) {
              // Update storage BEFORE processing queued requests
              this.storageManager.saveTokens(response.data);
              axiosConfig.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${response.data.access_token}`;
            }

            // Clear refresh state immediately after successful refresh
            this.refreshPromise = null;
            this.isRefreshing = false;

            return axiosConfig;
          } catch (error) {
            // On failure, clear refresh state immediately so future requests can retry
            this.refreshPromise = null;
            this.isRefreshing = false;
            // Clear tokens on auth failure
            this.storageManager.deleteTokens();
            return Promise.reject(error);
          }
        }

        axiosConfig.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${tokens.access_token}`;

        return axiosConfig;
      }
      return axiosConfig;
    });

    this.instance.interceptors.response.use(
      (response: AxiosResponse) => response,
      async (e: AxiosError) => {
        // Handle rate limiting with retry logic
        if (e.response?.status === HttpStatuses.tooManyRequests) {
          return await this.handleRateLimitError(e);
        }
        return this.handleAxiosError(e);
      },
    );
  }

  private isProtectedEndpoint(url?: string): boolean {
    return this.protectedEndpoints.some((endpoint) => url?.includes(endpoint));
  }

  private isNonAuthEndpoint(url?: string): boolean {
    return this.nonAccessTokenEndpoints.some((endpoint) => url?.includes(endpoint)) && !this.isProtectedEndpoint(url);
  }

  private async handleRateLimitError(e: AxiosError): Promise<AxiosResponse> {
    const config = e.config;
    if (!config) {
      return Promise.reject(e);
    }

    // Only retry idempotent requests to avoid duplicate operations
    const method = config.method?.toUpperCase();
    const isIdempotent = ['GET', 'HEAD', 'OPTIONS'].includes(method || '');

    if (!isIdempotent) {
      // Don't retry non-idempotent requests - could cause duplicates
      return Promise.reject(e);
    }

    // Track retry attempts on the config object
    const retryCount = (config as AxiosRequestConfig & { _retryCount?: number })._retryCount || 0;

    if (retryCount >= MAX_RETRIES) {
      // Max retries exceeded, reject with original error
      return Promise.reject(e);
    }

    // Calculate delay with exponential backoff
    let delayMs = INITIAL_RETRY_DELAY_MS * Math.pow(2, retryCount);

    // Check for Retry-After header (can be in seconds or HTTP date)
    const retryAfter = e.response?.headers?.['retry-after'];
    if (retryAfter) {
      const retryAfterNum = Number.parseInt(retryAfter, 10);
      if (!Number.isNaN(retryAfterNum)) {
        // Retry-After is in seconds
        delayMs = retryAfterNum * 1000;
      } else {
        // Retry-After is an HTTP date
        const retryDate = new Date(retryAfter);
        if (!Number.isNaN(retryDate.getTime())) {
          delayMs = Math.max(0, retryDate.getTime() - Date.now());
        }
      }
    }

    // Wait for the calculated delay
    await new Promise((resolve) => setTimeout(resolve, delayMs));

    // Increment retry count and retry the request
    (config as AxiosRequestConfig & { _retryCount?: number })._retryCount = retryCount + 1;
    return this.instance.request(config);
  }

  // eslint-disable-next-line complexity
  // biome-ignore lint/suspicious/useAwait: <explanation>
  private async handleAxiosError(e: AxiosError): Promise<unknown> {
    // Handle network
    if (!e.response) {
      return Promise.reject(e);
    }

    const status = e.response.status as HttpStatuses;
    const errorData = e.response.data as Record<string, unknown>;

    // If we have a response with error data in Passflow format
    if ('error' in errorData && typeof errorData.error === 'object' && errorData.error !== null) {
      const { error } = errorData as PassflowResponseError;

      return Promise.reject(new PassflowError(error));
    }

    // For non-Passflow format errors, create a generic PassflowError
    return Promise.reject(
      new PassflowError({
        id: `error.http.${status}`,
        message: e.message || 'An error occurred',
        status: status,
        location: e.config?.url || 'unknown',
        time: new Date().toISOString(),
      }),
    );
  }

  private async send<T, D>(method: RequestMethod, path: string, options?: RequestOptions<D>): Promise<T> {
    const response = await this.instance.request<T>({
      method,
      url: path,
      ...options,
    });
    return response.data;
  }

  get<T>(path: string, config?: AxiosRequestConfig): Promise<T> {
    return this.send(RequestMethod.GET, path, config);
  }

  post<T, D>(path: string, data?: D, config?: AxiosRequestConfig): Promise<T> {
    return this.send(RequestMethod.POST, path, { data, ...config });
  }

  put<T, D>(path: string, data?: D, config?: AxiosRequestConfig): Promise<T> {
    return this.send(RequestMethod.PUT, path, { data, ...config });
  }

  patch<T, D>(path: string, data?: D, config?: AxiosRequestConfig): Promise<T> {
    return this.send(RequestMethod.PATCH, path, { data, ...config });
  }

  delete<T>(path: string, config?: AxiosRequestConfig): Promise<T> {
    return this.send(RequestMethod.DELETE, path, config);
  }
}
