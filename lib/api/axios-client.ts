import { AOOTH_CLOUD_URL, APP_ID_HEADER_KEY, AUTHORIZATION_HEADER_KEY, DEFAULT_SCOPES } from 'lib/constants';

import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import axiosRetry from 'axios-retry';

import { StorageManager } from '../storage-manager';
import { TokenService, TokenType } from '../token-service';

import {
  AoothAuthorizationResponse,
  AoothConfig,
  AoothEndpointPaths,
  AoothError,
  AoothResponseError,
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

  tokenService: TokenService;

  origin = window.location.origin;
  url: string;
  appId?: string;

  protected defaultHeaders: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };

  constructor(config: AoothConfig) {
    const { url, appId } = config;

    this.url = url || AOOTH_CLOUD_URL;

    this.storageManager = new StorageManager();
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

    axiosRetry(this.instance, { retries: 3 });

    this.instance.interceptors.request.use((axiosConfig: InternalAxiosRequestConfig) => {
      const accessToken = this.storageManager.getToken(TokenType.access_token);
      const currentToken = axiosConfig.headers.Authorization;
      if (accessToken && !currentToken) axiosConfig.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${accessToken}`;
      return axiosConfig;
    });

    this.instance.interceptors.response.use(
      (response) => response,
      (e: AxiosError) => this.handleAxiosError(e),
    );
  }

  // eslint-disable-next-line complexity
  private async handleAxiosError(e: AxiosError): Promise<unknown> {
    /* Aooth returns 400 error if token has expired */
    const originalRequest = e.config;
    const accessToken = this.storageManager.getToken(TokenType.access_token);
    const refreshToken = this.storageManager.getToken(TokenType.refresh_token);

    if (e.response && refreshToken && originalRequest) {
      const status = e.response.status as HttpStatuses;
      const errorData = e.response.data as Error;
      if ('message' in errorData) return Promise.reject(e);

      const { error } = errorData as AoothResponseError;

      if (status === HttpStatuses.internalServerError || error.id === 'error.token.blocked') return Promise.reject(e);
      if (status === HttpStatuses.badRequest && error.id.includes('token')) {
        const payload = {
          access: accessToken,
          scopes: DEFAULT_SCOPES,
        };

        const tokens = await this.post<AoothAuthorizationResponse, typeof payload>(AoothEndpointPaths.refresh, payload, {
          headers: {
            [AUTHORIZATION_HEADER_KEY]: `Bearer ${refreshToken}`,
          },
        });

        this.storageManager.saveTokens(tokens);
        originalRequest.headers[AUTHORIZATION_HEADER_KEY] = `Bearer ${tokens.access_token}`;
        return this.instance(originalRequest);
      }
    }

    return Promise.reject(e);
  }

  private handleResponse<T>(response: AxiosResponse<T>): T {
    if (response.status >= 200 && response.status < 300) {
      return response.data;
    } else {
      throw new Error(`Request failed with status ${response.status}`);
    }
  }

  private handleError(e: unknown): never {
    if (axios.isAxiosError(e) && e.response) {
      const { error } = e.response.data as AoothResponseError;
      throw new AoothError(error);
    }

    throw e;
  }

  private async send<T, D>(method: RequestMethod, path: string, options?: RequestOptions<D>): Promise<T> {
    try {
      const response = await this.instance.request<T>({
        method,
        url: path,
        ...options,
      });

      return this.handleResponse<T>(response);
    } catch (e) {
      this.handleError(e);
    }
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
