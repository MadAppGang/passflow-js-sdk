import { APP_ID_HEADER_KEY, AUTHORIZATION_HEADER_KEY, PASSFLOW_CLOUD_URL } from '../constants';

import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse, InternalAxiosRequestConfig } from 'axios';

import { StorageManager } from '../storage-manager';
import { TokenService, isTokenExpired, parseToken } from '../token-service';

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
  internalServerError = 500,
  success = 200,
  created = 201,
}

export class AxiosClient {
  private instance: AxiosInstance;
  protected storageManager: StorageManager;
  private refreshPromise: Promise<AxiosResponse<PassflowAuthorizationResponse>> | null = null;

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

  constructor(config: PassflowConfig) {
    const { url, appId, keyStoragePrefix } = config;

    this.url = url || PASSFLOW_CLOUD_URL;

    this.storageManager = new StorageManager({
      prefix: keyStoragePrefix ?? '',
    });
    this.tokenService = new TokenService();

    if (appId) {
      this.appId = appId;

      this.defaultHeaders = {
        ...this.defaultHeaders,
        [APP_ID_HEADER_KEY]: appId,
      };
    }

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
        if (this.refreshPromise) {
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

        if (isTokenExpired(access) && tokens.refresh_token) {
          try {
            if (this.refreshPromise) {
              const response = await this.refreshPromise;
              if (response.data) {
                axiosConfig.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${response.data.access_token}`;
              }
              return axiosConfig;
            }

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
              this.storageManager.saveTokens(response.data);
              axiosConfig.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${response.data.access_token}`;
            }

            return axiosConfig;
          } catch (error) {
            this.refreshPromise = null;
            return Promise.reject(error);
          } finally {
            this.refreshPromise = null;
          }
        }

        axiosConfig.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${tokens.access_token}`;

        return axiosConfig;
      }
      return axiosConfig;
    });

    this.instance.interceptors.response.use(
      (response: AxiosResponse) => response,
      (e: AxiosError) => this.handleAxiosError(e),
    );
  }

  private isProtectedEndpoint(url?: string): boolean {
    return this.protectedEndpoints.some((endpoint) => url?.includes(endpoint));
  }

  private isNonAuthEndpoint(url?: string): boolean {
    return this.nonAccessTokenEndpoints.some((endpoint) => url?.includes(endpoint)) && !this.isProtectedEndpoint(url);
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
