import { StorageManager } from '../storage-manager';
import { Tokens } from '../types';

import { parseMembership } from './membership';
import { Token, TokenType } from './token';

export class TokenService {
  protected storageManager = new StorageManager();

  /**
   * Checks if a token is expired.
   *
   * @param {Token} token - The token to check.
   * @returns {boolean} Returns true if the token is expired, false otherwise.
   */
  isTokenExpired(token: Token): boolean {
    const currentUnixTime = Math.floor(Date.now() / 1000);
    return currentUnixTime < token.exp;
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

    const token = this.parseToken(tokenString);
    return token ? this.isTokenExpired(token) : true;
  }

  /**
   * Parse token from string. Please be aware that this method does not check if the token signature and if the token is valid.
   *
   * @param {string} tokenString - The token string representation.
   * @returns {Token | null} Returns token with parsed user membership or null.
   */
  parseToken(tokenString: string): Token | null {
    const base64Url = tokenString.split('.')[1];

    if (!base64Url) throw new Error('Invalid token');

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

  /**
   * Parse token from storage by type.
   * Please be aware that this method does not check if the token signature and if the token is valid.
   *
   * @param {TokenType} tokenType - The token type to check.
   * @returns {Token | null} Returns token with parsed user membership or null.
   */
  parseTokenType(tokenType: TokenType): Token | null {
    const token = this.storageManager.getToken(tokenType);

    if (!token) return null;

    return this.parseToken(token);
  }

  /**
   * Save tokens to the storage.
   *
   * @param {string} accessToken - Access token, should be always set.
   * @param {string | null} refreshToken - Refresh token or null.
   * @param {string | null} idToken - ID token or null.
   * @returns {Tokens} Returns tokens object.
   */
  saveTokens(accessToken: string, refreshToken: string | null, idToken: string | null): Tokens {
    const tokensObject: Tokens = {
      access_token: accessToken,
      refresh_token: refreshToken ?? undefined,
      id_token: idToken ?? undefined,
    };

    this.storageManager.saveTokens(tokensObject);
    return tokensObject;
  }
}
