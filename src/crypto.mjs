import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

/** Production scrypt parameters. Verification rejects any other set. */
export const SCRYPT = Object.freeze({
  N: 32768,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024,
  keylen: 64,
  saltBytes: 16,
});

const VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
const CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * @param {number} bytes
 * @returns {string}
 */
export function randomToken(bytes) {
  if (!Number.isInteger(bytes) || bytes < 32) {
    throw new Error('token entropy must be at least 32 bytes');
  }
  return randomBytes(bytes).toString('base64url');
}

/**
 * @param {string | Buffer} value
 * @returns {string}
 */
export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function timingSafeEqualString(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) {
    timingSafeEqual(left, Buffer.alloc(left.length));
    return false;
  }
  return timingSafeEqual(left, right);
}

/**
 * @param {string} password
 */
export function assertPasswordPolicy(password) {
  if (typeof password !== 'string' || password.length < 16 || password.length > 256) {
    throw Object.assign(new Error('password does not meet policy'), { code: 'password_policy' });
  }
  if (password.includes('\0')) {
    throw Object.assign(new Error('password does not meet policy'), { code: 'password_policy' });
  }
}

/**
 * @param {string} password
 * @param {Buffer} [salt]
 */
export function hashPassword(password, salt = randomBytes(SCRYPT.saltBytes)) {
  assertPasswordPolicy(password);
  if (!Buffer.isBuffer(salt) || salt.length < SCRYPT.saltBytes) {
    return Promise.reject(Object.assign(new Error('invalid salt'), { code: 'password_policy' }));
  }
  return new Promise((resolve, reject) => {
    scrypt(password, salt, SCRYPT.keylen, {
      N: SCRYPT.N,
      r: SCRYPT.r,
      p: SCRYPT.p,
      maxmem: SCRYPT.maxmem,
    }, (err, key) => {
      if (err) {
        reject(err);
        return;
      }
      resolve({
        passwordSalt: salt.toString('base64url'),
        passwordVerifier: Buffer.from(key).toString('base64url'),
        scryptParams: {
          N: SCRYPT.N,
          r: SCRYPT.r,
          p: SCRYPT.p,
          maxmem: SCRYPT.maxmem,
          keylen: SCRYPT.keylen,
        },
      });
    });
  });
}

/**
 * Always performs scrypt when the stored parameters are well formed.
 * @param {string} password
 * @param {{ passwordSalt?: string, passwordVerifier?: string, scryptParams?: object } | null | undefined} operator
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(password, operator) {
  if (!operator || typeof password !== 'string') return false;
  const params = operator.scryptParams || {};
  if (params.N !== SCRYPT.N || params.r !== SCRYPT.r || params.p !== SCRYPT.p || params.keylen !== SCRYPT.keylen) {
    return false;
  }
  let salt;
  let expected;
  try {
    salt = Buffer.from(String(operator.passwordSalt || ''), 'base64url');
    expected = Buffer.from(String(operator.passwordVerifier || ''), 'base64url');
  } catch {
    return false;
  }
  if (salt.length < SCRYPT.saltBytes || expected.length !== SCRYPT.keylen) return false;
  if (password.length < 16 || password.length > 256 || password.includes('\0')) return false;
  const key = await new Promise((resolve, reject) => {
    scrypt(password, salt, expected.length, {
      N: SCRYPT.N,
      r: SCRYPT.r,
      p: SCRYPT.p,
      maxmem: SCRYPT.maxmem,
    }, (err, out) => {
      if (err) reject(err);
      else resolve(out);
    });
  });
  if (!Buffer.isBuffer(key) || key.length !== expected.length) return false;
  return timingSafeEqual(key, expected);
}

/**
 * @param {string} verifier
 * @returns {boolean}
 */
export function isValidPkceVerifier(verifier) {
  return typeof verifier === 'string' && VERIFIER_PATTERN.test(verifier);
}

/**
 * @param {string} challenge
 * @returns {boolean}
 */
export function isValidPkceChallenge(challenge) {
  if (typeof challenge !== 'string' || !CHALLENGE_PATTERN.test(challenge)) return false;
  const decoded = Buffer.from(challenge, 'base64url');
  return decoded.length === 32 && decoded.toString('base64url') === challenge;
}

/**
 * @param {string} verifier
 * @returns {string}
 */
export function pkceS256(verifier) {
  if (!isValidPkceVerifier(verifier)) {
    throw Object.assign(new Error('invalid code_verifier'), { code: 'invalid_grant' });
  }
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/**
 * @param {string} verifier
 * @param {string} challenge
 * @returns {boolean}
 */
export function pkceMatches(verifier, challenge) {
  if (!isValidPkceChallenge(challenge) || !isValidPkceVerifier(verifier)) return false;
  const computed = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  return timingSafeEqualString(computed, challenge);
}

/**
 * @param {string} version
 */
export function assertNodeVersion(version) {
  const major = nodeMajor(version);
  if (!Number.isInteger(major) || major < 18) {
    throw new Error(`Node.js 18 or newer is required (found ${version}). Refusing to start.`);
  }
}

/**
 * @param {string} version
 * @returns {number}
 */
export function nodeMajor(version) {
  const match = /^v?(\d+)\./.exec(String(version || ''));
  return match ? Number(match[1]) : NaN;
}
