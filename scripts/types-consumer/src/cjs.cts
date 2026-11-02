// Consumer fixture for scripts/check-types-consumer.mjs (CJS, the `require` condition).
// A .cts file under node16 resolves @passflow/core through `exports.require.types`, which
// must not point at a file TypeScript reads as ESM-only (TS1479).
import { M2MClient, Passflow, type PassflowConfig, TokenDeliveryMode } from '@passflow/core';

const config: PassflowConfig = { appId: 'app' };
export const pf: Passflow = new Passflow(config);
export const mode: TokenDeliveryMode = TokenDeliveryMode.Cookie;
export const m2m: M2MClient = new M2MClient({ url: 'u', clientId: 'c', clientSecret: 's' });
