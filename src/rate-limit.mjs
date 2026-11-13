import { sha256Hex } from './crypto.mjs';

/**
 * @param {string} ip
 * @param {string} pepper
 */
export function hashIp(ip, pepper) {
  return sha256Hex(`${pepper}|${ip || 'unknown'}`).slice(0, 32);
}

/**
 * Mutates draft.loginThrottle. Returns whether the attempt is locked BEFORE counting
 * a new failure, and a function-like result the caller uses after a failed password.
 * @param {object} draft
 * @param {{ ipHash: string, now: number, maxFailures: number, windowMs: number, lockMs: number }} options
 */
export function beginLoginAttempt(draft, options) {
  const throttle = ensureThrottle(draft, options.now);
  sweepIps(throttle, options.now);
  const global = throttle.global;
  const ip = touchIp(throttle, options.ipHash, options.now);
  const lockedUntil = Math.max(global.lockedUntil || 0, ip.lockedUntil || 0);
  if (lockedUntil > options.now) {
    return { locked: true, retryAfterSec: Math.ceil((lockedUntil - options.now) / 1000) };
  }
  return { locked: false, retryAfterSec: 0 };
}

/**
 * @param {object} draft
 * @param {{ ipHash: string, now: number, maxFailures: number, windowMs: number, lockMs: number }} options
 */
export function recordLoginFailure(draft, options) {
  const throttle = ensureThrottle(draft, options.now);
  const global = bump(throttle.global, options);
  const ip = bump(touchIp(throttle, options.ipHash, options.now), options);
  const lockedUntil = Math.max(global.lockedUntil || 0, ip.lockedUntil || 0);
  if (lockedUntil > options.now) {
    return { locked: true, retryAfterSec: Math.ceil((lockedUntil - options.now) / 1000) };
  }
  return { locked: false, retryAfterSec: 0 };
}

/**
 * @param {{ failures: number, windowStart: number, lockedUntil: number }} bucket
 * @param {{ now: number, maxFailures: number, windowMs: number, lockMs: number }} options
 */
function bump(bucket, options) {
  if (options.now - bucket.windowStart > options.windowMs) {
    bucket.failures = 0;
    bucket.windowStart = options.now;
  }
  bucket.failures += 1;
  if (bucket.failures >= options.maxFailures) {
    bucket.lockedUntil = options.now + options.lockMs;
  }
  return bucket;
}

/**
 * @param {object} draft
 * @param {number} now
 */
function ensureThrottle(draft, now) {
  if (!draft.loginThrottle || !draft.loginThrottle.global) {
    draft.loginThrottle = { global: { failures: 0, windowStart: now, lockedUntil: 0 }, ips: {} };
  }
  if (!draft.loginThrottle.ips) draft.loginThrottle.ips = {};
  return draft.loginThrottle;
}

/**
 * @param {object} throttle
 * @param {string} ipHash
 * @param {number} now
 */
function touchIp(throttle, ipHash, now) {
  const ips = throttle.ips;
  if (!ips[ipHash]) {
    const keys = Object.keys(ips);
    if (keys.length >= 256) {
      const oldest = keys.sort((a, b) => (ips[a].windowStart || 0) - (ips[b].windowStart || 0))[0];
      if ((ips[oldest].lockedUntil || 0) <= now) delete ips[oldest];
    }
    ips[ipHash] = { failures: 0, windowStart: now, lockedUntil: 0 };
  }
  return ips[ipHash];
}

/**
 * @param {object} throttle
 * @param {number} now
 */
function sweepIps(throttle, now) {
  for (const [key, value] of Object.entries(throttle.ips)) {
    if ((value.lockedUntil || 0) <= now && now - (value.windowStart || 0) > 60 * 60 * 1000) {
      delete throttle.ips[key];
    }
  }
}

/**
 * In-memory token-endpoint limiter. Not a substitute for login lockout.
 * @param {{ clock: { now: () => number }, max: number, windowMs: number }} options
 */
export function createWindowLimiter(options) {
  /** @type {Map<string, { count: number, start: number }>} */
  const buckets = new Map();
  return {
    /**
     * @param {string} key
     */
    hit(key) {
      const now = options.clock.now();
      const current = buckets.get(key);
      if (!current || now - current.start >= options.windowMs) {
        buckets.set(key, { count: 1, start: now });
        if (buckets.size > 1024) {
          const oldest = buckets.keys().next().value;
          buckets.delete(oldest);
        }
        return { limited: false, retryAfterSec: 0 };
      }
      current.count += 1;
      if (current.count > options.max) {
        return { limited: true, retryAfterSec: Math.ceil((options.windowMs - (now - current.start)) / 1000) };
      }
      return { limited: false, retryAfterSec: 0 };
    },
  };
}
