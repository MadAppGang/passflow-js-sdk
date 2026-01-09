import { ERROR_MESSAGE_MAX_LENGTH, USERNAME_MAX_LENGTH, USERNAME_MIN_LENGTH } from '../constants';

/**
 * Validates JWT token format (not signature, just structure)
 * Checks that the token has 3 parts separated by dots and each part is valid base64url
 *
 * @param token - The token string to validate
 * @returns true if the token has valid JWT format, false otherwise
 */
export function isValidJWTFormat(token: string): boolean {
  if (!token || typeof token !== 'string') return false;

  const parts = token.split('.');
  if (parts.length !== 3) return false;

  // Check each part is valid base64url (alphanumeric, underscore, hyphen only)
  const base64UrlPattern = /^[A-Za-z0-9_-]+$/;
  return parts.every((part) => base64UrlPattern.test(part) && part.length > 0);
}

/**
 * Sanitizes error messages from URL parameters to prevent XSS
 * Removes HTML tags and limits length
 *
 * @param message - The error message to sanitize
 * @returns Sanitized error message
 */
export function sanitizeErrorMessage(message: string): string {
  // Remove any HTML tags
  const cleaned = message.replace(/<[^>]*>/g, '');
  // Limit length to prevent excessively long error messages
  return cleaned.substring(0, ERROR_MESSAGE_MAX_LENGTH);
}

/**
 * Validates email format using RFC 5322 simplified pattern
 *
 * @param email - The email string to validate
 * @returns true if valid email format, false otherwise
 */
export function isValidEmail(email: string): boolean {
  if (!email || typeof email !== 'string') return false;

  const trimmed = email.trim();
  if (trimmed.length === 0) return false;

  // RFC 5322 simplified pattern
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailPattern.test(trimmed);
}

/**
 * Validates phone number format (E.164 format)
 *
 * @param phone - The phone number string to validate
 * @returns true if valid phone format, false otherwise
 */
export function isValidPhoneNumber(phone: string): boolean {
  if (!phone || typeof phone !== 'string') return false;

  const trimmed = phone.trim();

  // E.164 format: +[country code][number] (1-15 digits after +)
  const phonePattern = /^\+[1-9]\d{1,14}$/;
  return phonePattern.test(trimmed);
}

/**
 * Validates username format
 *
 * @param username - The username string to validate
 * @returns true if valid username format, false otherwise
 */
export function isValidUsername(username: string): boolean {
  if (!username || typeof username !== 'string') return false;

  const trimmed = username.trim();
  if (trimmed.length < USERNAME_MIN_LENGTH || trimmed.length > USERNAME_MAX_LENGTH) return false;

  // Alphanumeric, underscore, hyphen only
  const usernamePattern = /^[a-zA-Z0-9_-]+$/;
  return usernamePattern.test(trimmed);
}

/**
 * Validates TOTP code format (6 numeric digits)
 *
 * @param code - The TOTP code to validate
 * @returns true if valid TOTP code format (exactly 6 digits), false otherwise
 */
export function isValidTOTPCode(code: string): boolean {
  if (!code || typeof code !== 'string') return false;

  // TOTP codes must be exactly 6 numeric digits
  const totpPattern = /^\d{6}$/;
  return totpPattern.test(code);
}

/**
 * Normalizes and validates recovery code format
 * Converts to uppercase and removes whitespace
 *
 * @param code - The recovery code to normalize and validate
 * @returns Normalized recovery code if valid, null if invalid
 */
export function normalizeRecoveryCode(code: string): string | null {
  if (!code || typeof code !== 'string') return null;

  // Normalize: uppercase and remove all whitespace
  const normalized = code.toUpperCase().replace(/\s+/g, '');

  // Basic validation: must be alphanumeric
  // Accept reasonable lengths (4-16 chars) to allow API to do final validation
  // This allows formats like "ABCD1234", "ABCD-1234", or even "INVALID" for testing
  const recoveryPattern = /^[A-Z0-9-]{4,16}$/;

  if (!recoveryPattern.test(normalized)) return null;

  return normalized;
}
