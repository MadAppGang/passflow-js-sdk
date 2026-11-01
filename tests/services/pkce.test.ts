import { describe, expect, test } from 'vitest';
import { createPkcePair, s256Challenge } from '../../lib/pkce';

describe('pkce', () => {
  test('s256Challenge matches the RFC 7636 appendix B vector', async () => {
    expect(await s256Challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });

  test('createPkcePair gives a verifier the server accepts, bound to its challenge', async () => {
    const { verifier, challenge } = await createPkcePair();

    expect(verifier).toMatch(/^[A-Za-z0-9\-._~]{43,128}$/);
    expect(challenge).toBe(await s256Challenge(verifier));
  });

  test('createPkcePair gives a new verifier each time', async () => {
    const first = await createPkcePair();
    const second = await createPkcePair();

    expect(first.verifier).not.toBe(second.verifier);
  });
});
