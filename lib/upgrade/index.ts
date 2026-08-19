export {
  INSUFFICIENT_USER_AUTHENTICATION,
  UPGRADE_REQUIRED,
  parseChallengeBody,
  parseChallengeHeader,
  parseUpgradeChallenge,
  type UpgradeChallenge,
} from './challenge';

export {
  DEFAULT_UPGRADE_FACTORS,
  factorRegistry,
  passkeyFactor,
  recoveryCodesFactor,
  UpgradeFactorError,
  totpFactor,
  type UpgradeAssertion,
  type UpgradeAssertContext,
  type UpgradeFactor,
  type UpgradeFactorInput,
  type UpgradeFactorType,
  type UpgradePrepared,
} from './factors';

export {
  UpgradeCancelledError,
  UpgradeController,
  UpgradeUnsatisfiableError,
  type UpgradeControllerOptions,
  type UpgradePromptHandler,
  type UpgradePromptRequest,
  type UpgradePromptResult,
  type UpgradeTransport,
} from './controller';

export { selectFactors } from './select';
