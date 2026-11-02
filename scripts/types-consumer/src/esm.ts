// Consumer fixture for scripts/check-types-consumer.mjs (ESM, the `import` condition).
// It touches representative exports by value and by type, so the shipped declarations are
// resolved and checked (skipLibCheck: false) under node16, nodenext and bundler.
import {
  M2MClient,
  type M2MClientConfig,
  Passflow,
  type PassflowConfig,
  PassflowEvent,
  type PassflowSubscriber,
  parseUpgradeChallenge,
  SDK_VERSION,
  type Token,
  TokenDeliveryMode,
  type UpgradeChallenge,
} from '@passflow/core';

const config: PassflowConfig = { appId: 'app', url: 'https://example.com' };
export const pf: Passflow = new Passflow(config);
export const mode: TokenDeliveryMode = TokenDeliveryMode.JsonBody;
export const m2mConfig: M2MClientConfig = { url: 'https://example.com', clientId: 'id', clientSecret: 's' };
export const m2m: M2MClient = new M2MClient(m2mConfig);
export const sub: PassflowSubscriber = { onAuthChange: () => undefined };
export const ev: PassflowEvent = PassflowEvent.SignIn;
export const tok = null as Token | null;
export const ch: UpgradeChallenge | undefined = parseUpgradeChallenge(401, () => null);
export const v: string = SDK_VERSION;
