import { StorageManager } from '../storage-manager';

import { parseMembership } from './membership';
import { Token, TokenType } from './token';

export class TokenService {
  protected storageManager = new StorageManager();

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
 * @returns {boolean} Returns true if the token is expired, false otherwise.
 */
export function isTokenExpired(token: Token): boolean {
  const currentUnixTime = Math.floor(Date.now() / 1000);
  return currentUnixTime > token.exp;
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
  const jsonPayload = decodeURIComponent(
    window
      .atob(base64)
      .split('')
      .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
      .join(''),
  );

  const parsedToken = JSON.parse(jsonPayload) as Token;
  parsedToken.membership = parsedToken.aooth_tm ? parseMembership(parsedToken.aooth_tm) : undefined;
  return parsedToken;
}
