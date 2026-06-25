// Circuit breaker for Tier 1 ML — prevents cascading failures when the model is unavailable.
// Tier 1: "per-source fail-open / fail-closed; on error/timeout fall back to Tier-0 verdict".
// The circuit breaker sits in front of the runner: after N consecutive failures, it opens
// and short-circuits all subsequent attempts to "degraded" without hitting the model.
// After a cooldown, it enters half-open and allows a single probe; success closes, failure re-opens.

const DEFAULT_THRESHOLD = 5; // consecutive failures to open
const DEFAULT_COOLDOWN_MS = 30_000; // 30s before half-open probe

export type CircuitState = 'closed' | 'open' | 'half-open';

export class CircuitBreaker {
  private failures = 0;
  private lastFailureTime = 0;
  private _state: CircuitState = 'closed';

  constructor(
    private readonly threshold: number = DEFAULT_THRESHOLD,
    private readonly cooldownMs: number = DEFAULT_COOLDOWN_MS,
  ) {}

  get state(): CircuitState {
    return this._state;
  }

  // True if an attempt is allowed (closed or half-open after cooldown).
  canAttempt(now: number): boolean {
    if (this._state === 'closed') return true;
    if (this._state === 'open') {
      if (now - this.lastFailureTime > this.cooldownMs) {
        this._state = 'half-open';
        return true;
      }
      return false;
    }
    // half-open: allow exactly one probe
    return true;
  }

  recordSuccess(): void {
    this.failures = 0;
    this._state = 'closed';
  }

  recordFailure(now: number): void {
    this.failures++;
    this.lastFailureTime = now;
    if (this._state === 'half-open' || this.failures >= this.threshold) {
      this._state = 'open';
    }
  }

  reset(): void {
    this.failures = 0;
    this.lastFailureTime = 0;
    this._state = 'closed';
  }
}
