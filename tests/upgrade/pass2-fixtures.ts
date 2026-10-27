import type { UpgradeChallenge } from '../../lib/upgrade/challenge';
import type { UpgradePromptRequest, UpgradePromptResult } from '../../lib/upgrade/controller';
import { deferred } from './fetch-fixtures';

export const challenge = (level = 2): UpgradeChallenge => ({
  status: 401,
  acrValues: String(level),
  requiredLevel: level,
  channels: ['header'],
});

// A prompt boundary, not a mocked controller. Tests drive the documented selection/answer protocol.
export function promptDriver() {
  const requests: UpgradePromptRequest[] = [];
  const answers: ReturnType<typeof deferred<UpgradePromptResult>>[] = [];
  return {
    requests,
    prompt: (request: UpgradePromptRequest) => {
      requests.push(request);
      const answer = deferred<UpgradePromptResult>();
      answers.push(answer);
      return answer.promise;
    },
    select: (index = 0, factor: 'totp' | 'passkey' = 'totp') => requests[index].onFactorSelected(factor),
    submit: (index = 0, factor: 'totp' | 'passkey' = 'totp') =>
      answers[index].resolve({ type: 'submit', factor, code: '123456' }),
    cancel: (index = 0) => answers[index].resolve({ type: 'cancel' }),
  };
}

export const jwt = (claims: Record<string, unknown>) => {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return (
    encode({ alg: 'none', typ: 'JWT' }) +
    '.' +
    encode({
      exp: 4102444800,
      iat: 1700000000,
      aud: ['qa'],
      iss: 'https://auth.example',
      ...claims,
    }) +
    '.qa'
  );
};

export const tokensFor = (sub: string, sid: string, acr = '1') => ({
  access_token: jwt({ sub, sid, acr, type: 'access' }),
  refresh_token: jwt({ sub, sid, type: 'refresh' }),
  id_token: jwt({ sub, sid, acr, type: 'id' }),
  scopes: ['openid', 'offline'],
});

export const observed = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ ok: true as const, value }),
    (error) => ({ ok: false as const, error }),
  );
