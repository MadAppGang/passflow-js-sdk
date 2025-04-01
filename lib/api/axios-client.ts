import { APP_ID_HEADER_KEY, AUTHORIZATION_HEADER_KEY, PASSFLOW_CLOUD_URL } from '../constants';

import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import axiosRetry from 'axios-retry';

import { StorageManager } from '../storage-manager';
import { TokenService, TokenType } from '../token-service';

import { PassflowConfig, PassflowError, PassflowResponseError, RequestMethod, RequestOptions } from './model';

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

  constructor(config: PassflowConfig) {
    const { url, appId } = config;

    this.url = url || PASSFLOW_CLOUD_URL;

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
      (response: AxiosResponse) => response,
      (e: AxiosError) => this.handleAxiosError(e),
    );
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
