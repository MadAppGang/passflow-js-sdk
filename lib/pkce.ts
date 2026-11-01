/**
 * RFC 7636 proof key: the verifier stays on this client, its S256 hash goes to
 * the server with the sign-in, and the server answers with a code that only the
 * verifier redeems.
 */
export type PkcePair = {
  verifier: string;
  challenge: string;
};

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// 32 random bytes encode to 43 characters, the shortest verifier RFC 7636 §4.1 allows.
const VERIFIER_BYTES = 32;

// Written out because `btoa` is not available on every platform this SDK runs on.
const base64UrlEncode = (bytes: Uint8Array): string => {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] as number;
    const b = bytes[i + 1];
    const c = bytes[i + 2];
    out += BASE64URL_ALPHABET.charAt(a >> 2);
    out += BASE64URL_ALPHABET.charAt(((a & 0x03) << 4) | ((b ?? 0) >> 4));
    if (b !== undefined) out += BASE64URL_ALPHABET.charAt(((b & 0x0f) << 2) | ((c ?? 0) >> 6));
    if (c !== undefined) out += BASE64URL_ALPHABET.charAt(c & 0x3f);
  }
  return out;
};

// `crypto.subtle` exists only in a secure context, so a plain-http page lands here.
const webCrypto = (): Crypto => {
  const crypto = globalThis.crypto;
  if (!crypto?.subtle) {
    throw new Error('PKCE needs the Web Crypto API, which is available only in a secure context (https or localhost)');
  }
  return crypto;
};

/** BASE64URL(SHA256(ASCII(verifier))), RFC 7636 §4.2. */
export const s256Challenge = async (verifier: string): Promise<string> => {
  const digest = await webCrypto().subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
};

export const createPkcePair = async (): Promise<PkcePair> => {
  const verifier = base64UrlEncode(webCrypto().getRandomValues(new Uint8Array(VERIFIER_BYTES)));
  return { verifier, challenge: await s256Challenge(verifier) };
};
