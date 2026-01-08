/**
 * Token Service
 *
 * JWT token parsing, validation, and utility functions.
 * Provides platform-agnostic Base64 decoding for SSR/Node.js support.
 * Handles token expiry calculations with configurable buffer time.
 *
 * @module token
 */

import { TOKEN_EXPIRY_BUFFER_SECONDS } from '../constants';
import { StorageManager } from '../storage';

import { parseMembership } from './membership';
import { Token, TokenType } from './token';

/**
 * Decodes a Base64-encoded string in a platform-agnostic way.
 * Works in both browser (using atob) and Node.js (using Buffer) environments.
 *
 * @param base64 - The Base64 string to decode
 * @returns Decoded string
 */
function decodeBase64(base64: string): string {
  // Browser environment
  if (typeof window !== 'undefined' && typeof window.atob === 'function') {
    return window.atob(base64);
  }

  // Node.js environment
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  throw new Error('No Base64 decoding method available in this environment');
}

export class TokenService {
  protected storageManager: StorageManager;

  constructor(storageManager: StorageManager) {
    this.storageManager = storageManager;
  }

  /**
   * Checks if a token is not exists or expired.
   *
   * @param {TokenType} ttype - The token type to check.
   * @returns {boolean} Returns true if the token is expired or not exists, false otherwise.
   */
  isTokenTypeExpired(ttype: TokenType): boolean {
    const tokenString = this.storageManager.getToken(ttype);
    if (!tokenString) return true;

    const token = parseToken(tokenString);
    return token ? isTokenExpired(token) : true;
  }

  /**
   * Parse token from storage by type.
   * Please be aware that this method does not check if the token signature and if the token is valid.
   *
   * @param {TokenType} tokenType - The token type to check.
   * @returns {Token | undefined} Returns token with parsed user membership or undefined.
   */
  parseTokenType(tokenType: TokenType): Token | undefined {
    const token = this.storageManager.getToken(tokenType);
    if (!token) return undefined;
    return parseToken(token);
  }
}

/**
 * Checks if a token is expired.
 *
 * @param {Token} token - The token to check.
 * @param {number} bufferSeconds - Time buffer in seconds to consider token expired early
 *                                 This prevents race conditions where token expires during request
 * @returns {boolean} Returns true if the token is expired or will expire within buffer time, false otherwise.
 */
export function isTokenExpired(token: Token, bufferSeconds = TOKEN_EXPIRY_BUFFER_SECONDS): boolean {
  const currentUnixTime = Math.floor(Date.now() / 1000);
  return currentUnixTime + bufferSeconds > token.exp;
}

/**
 * Parse token from string. Please be aware that this method does not check if the token signature and if the token is valid.
 *
 * @param {string} tokenString - The token string representation.
 * @returns {Token } Returns token with parsed user membership or undefined.
 */
export function parseToken(tokenString: string): Token {
  const base64Url = tokenString.split('.')[1];

  if (!base64Url) throw new Error('Invalid token string');

  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if necessary (some JWTs don't include padding)
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);

  // Use the platform-agnostic decoder
  const decoded = decodeBase64(padded);

  const jsonPayload = decodeURIComponent(
    decoded
      .split('')
      .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
      .join(''),
  );

  const parsedToken = JSON.parse(jsonPayload) as Token;
  parsedToken.membership =
    parsedToken.passflow_tm && parsedToken.type !== 'invite' ? parseMembership(parsedToken.passflow_tm) : undefined;
  return parsedToken;
}
