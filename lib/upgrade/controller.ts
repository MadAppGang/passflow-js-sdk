/**
 * Upgrade orchestration.
 *
 * Turns a parsed RFC 9470 challenge into an elevated session: pick a factor,
 * ask the user, run the prepare round if the factor needs one, assert, then
 * commit through `POST /auth/refresh` with the `upgrade` field.
 *
 * The controller owns no UI. It calls out to a prompt handler, which the React
 * layer (or any consumer) implements — that is what keeps the same logic
 * usable from a headless client.
 */

import type { UpgradeChallenge } from './challenge';
import {
  DEFAULT_UPGRADE_FACTORS,
  type UpgradeAssertion,
  type UpgradeFactor,
  UpgradeFactorError,
  type UpgradeFactorType,
  type UpgradePrepared,
  factorRegistry,
} from './factors';
import { selectFactors } from './select';

import type { PlatformAdapter } from '../platform';

/** What the UI is shown when a upgrade is required. */
export type UpgradePromptRequest = {
  /** What the server demanded. */
  challenge: UpgradeChallenge;
  /** Usable factors, already ordered — the suggested one first. */
  factors: readonly UpgradeFactor[];
  /** Failure from the previous attempt, when the user is retrying. */
  previousError?: Error;
};

/** The user's answer to a upgrade prompt. */
export type UpgradePromptResult = { type: 'submit'; factor: UpgradeFactorType; code?: string } | { type: 'cancel' };

/** Renders the upgrade UI and resolves once the user submits or backs out. */
export type UpgradePromptHandler = (request: UpgradePromptRequest) => Promise<UpgradePromptResult>;

/** Transport seam — the controller never touches axios directly, so it stays testable. */
export type UpgradeTransport = {
  /** `POST /auth/upgrade/begin`. Only called for factors whose `requiresPrepare` is true. */
  prepare(method: UpgradeFactorType): Promise<UpgradePrepared>;
  /** `POST /auth/refresh` carrying `upgrade`. Resolves once elevated tokens are stored. */
  commit(factor: UpgradeFactorType, assertion: UpgradeAssertion): Promise<void>;
};

export type UpgradeControllerOptions = {
  transport: UpgradeTransport;
  prompt: UpgradePromptHandler;
  platform: PlatformAdapter;
  /** Defaults to the factors this SDK can complete. */
  factors?: readonly UpgradeFactor[];
  /** How many times the user may answer wrongly before the elevation gives up. Server allows four. */
  maxAttempts?: number;
};

/** Raised when the user dismissed the upgrade rather than failing it. */
export class UpgradeCancelledError extends Error {
  constructor() {
    super('Upgrade authentication was cancelled');
    this.name = 'UpgradeCancelledError';
  }
}

/** Raised when no registered factor can satisfy the challenge. */
export class UpgradeUnsatisfiableError extends Error {
  constructor(message = 'No available authentication factor can satisfy this challenge') {
    super(message);
    this.name = 'UpgradeUnsatisfiableError';
  }
}

/**
 * The server permits four guesses against one issued challenge before it burns.
 * Stopping one short keeps the SDK from being the thing that exhausts the
 * budget, so a user who mistypes twice can still recover without re-preparing.
 */
const DEFAULT_MAX_ATTEMPTS = 3;

export class UpgradeController {
  private readonly transport: UpgradeTransport;
  private readonly prompt: UpgradePromptHandler;
  private readonly platform: PlatformAdapter;
  private readonly registry: Map<UpgradeFactorType, UpgradeFactor>;
  private readonly available: readonly UpgradeFactor[];
  private readonly maxAttempts: number;

  /**
   * The elevation currently running.
   *
   * Upgrade is single-flight on purpose. A screen that fires several protected
   * requests at once gets several challenges, and every one of them must land
   * on ONE prompt — otherwise the user sees a stack of modals and every
   * additional elevation burns a challenge for nothing.
   */
  private inFlight: Promise<void> | null = null;

  constructor(options: UpgradeControllerOptions) {
    this.transport = options.transport;
    this.prompt = options.prompt;
    this.platform = options.platform;
    this.available = options.factors ?? DEFAULT_UPGRADE_FACTORS;
    this.registry = factorRegistry(this.available);
    this.maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  }

  /**
   * Elevates the session so the challenged request can be retried.
   *
   * Concurrent callers share one elevation: the first starts it, the rest await
   * the same promise and all resolve together. Callers retry their own request
   * once this resolves; it rejects if the user cancelled or ran out of attempts.
   */
  elevate(challenge: UpgradeChallenge): Promise<void> {
    if (this.inFlight) {
      return this.inFlight;
    }
    this.inFlight = this.run(challenge).finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  private async run(challenge: UpgradeChallenge): Promise<void> {
    const factors = selectFactors(this.available, challenge);
    if (factors.length === 0) {
      throw new UpgradeUnsatisfiableError();
    }

    let previousError: Error | undefined;

    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      const answer = await this.prompt({ challenge, factors, previousError });
      if (answer.type === 'cancel') {
        throw new UpgradeCancelledError();
      }

      const factor = this.registry.get(answer.factor);
      if (!factor) {
        previousError = new UpgradeUnsatisfiableError(`Unknown authentication factor: ${answer.factor}`);
        continue;
      }

      try {
        await this.proveAndCommit(factor, answer.code);
        return;
      } catch (e) {
        // A cancelled ceremony ends the elevation — the user made a choice, and
        // re-prompting them would be nagging, not recovery.
        if (e instanceof UpgradeFactorError && e.cancelled) {
          throw new UpgradeCancelledError();
        }
        previousError = e as Error;
      }
    }

    throw previousError ?? new UpgradeUnsatisfiableError('Upgrade authentication failed');
  }

  /**
   * Runs one full proof for a single factor.
   *
   * The prepare round is re-run on every attempt rather than cached: a
   * challenge is single-use and the server consumes it atomically, so a failed
   * attempt has already spent it. Reusing the id would fail with
   * `ErrorUpgradeChallengeInvalid` and look like a bad code to the user.
   */
  private async proveAndCommit(factor: UpgradeFactor, code: string | undefined): Promise<void> {
    const prepared = factor.requiresPrepare ? await this.transport.prepare(factor.type) : undefined;
    const assertion = await factor.assert({ code, prepared, platform: this.platform });
    await this.transport.commit(factor.type, assertion);
  }
}
