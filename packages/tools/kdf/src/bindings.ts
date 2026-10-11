import bcryptjs from "bcryptjs";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bcryptPrehash, standardBase64, type BcryptPrehash } from "@ocs/algos";

/**
 * bcrypt, and nothing else.
 *
 * The six key *derivations* moved to `./key-source.ts` and are re-exported below, so every existing
 * caller is unchanged. The split is not tidiness: `bcryptjs` is imported at module scope here, so any
 * import from this file drags a password-hashing library into the importer's chunk -- and the cipher
 * family now derives keys through the same functions while never hashing a password.
 *
 * bcrypt comes from `bcryptjs` because `@noble` has none -- see the note in
 * `packages/algos/WHY-NOT-A-LIBRARY.md`. Unlike the hash gaps it is pure ESM with zero dependencies
 * and works unchanged in a browser, so there was no reason to write another one.
 */

/**
 * bcrypt takes the password as a string, not bytes.
 *
 * That is not this wrapper being lazy — bcrypt is *defined* over a NUL-terminated C string,
 * which is where its 72-byte limit and its historical NUL-byte truncation bugs come from.
 * Passing bytes would require choosing an encoding anyway, and UTF-8 is what every
 * implementation uses.
 */
function bcryptSetting(cost: number, salt?: string): string {
  if (salt === undefined) return bcryptjs.genSaltSync(cost);
  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{22}/.test(salt)) return salt.slice(0, 29);
  if (/^[./A-Za-z0-9]{22}$/.test(salt)) {
    return `$2b$${String(cost).padStart(2, "0")}$${salt}`;
  }
  throw new Error("bcrypt needs a 22-character bcrypt-base64 salt.");
}

export function hashBcrypt(password: string, cost: number, salt?: string): string {
  return bcryptjs.hashSync(password, bcryptSetting(cost, salt));
}

export function verifyBcrypt(password: string, stored: string): boolean {
  try {
    return bcryptjs.compareSync(password, stored);
  } catch {
    // compareSync throws on a malformed hash string rather than returning false.
    return false;
  }
}

/** Hashcat's bcrypt(md5/sha1/sha256/sha512($pass)) constructions. */
export function hashBcryptPrehash(
  password: string,
  algorithm: BcryptPrehash,
  cost: number,
  salt?: string,
): string {
  return hashBcrypt(bcryptPrehash(password, algorithm), cost, salt);
}

export function verifyBcryptPrehash(
  password: string,
  algorithm: BcryptPrehash,
  stored: string,
): boolean {
  return verifyBcrypt(bcryptPrehash(password, algorithm), stored);
}

const PASSLIB_BCRYPT_SHA256_RE =
  /^\$bcrypt-sha256\$v=2,t=2b,r=(\d{1,2})\$([./A-Za-z0-9]{22})\$([./A-Za-z0-9]{31})$/;

function passlibBcryptPassword(password: string, encodedSalt: string): string {
  const mac = hmac(
    sha256,
    new TextEncoder().encode(encodedSalt),
    new TextEncoder().encode(password),
  );
  return standardBase64(mac);
}

/** Passlib bcrypt_sha256 v2, which is HMAC-SHA256 and standard padded base64 before bcrypt. */
export function hashPasslibBcryptSha256(password: string, cost: number, salt?: string): string {
  const setting = bcryptSetting(cost, salt);
  const effectiveCost = Number(setting.slice(4, 6));
  const encodedSalt = setting.slice(7, 29);
  const bcryptPassword = passlibBcryptPassword(password, encodedSalt);
  const full = bcryptjs.hashSync(bcryptPassword, setting);
  return `$bcrypt-sha256$v=2,t=2b,r=${effectiveCost}$${encodedSalt}$${full.slice(-31)}`;
}

export function verifyPasslibBcryptSha256(password: string, stored: string): boolean {
  const parsed = PASSLIB_BCRYPT_SHA256_RE.exec(stored);
  if (!parsed) return false;
  const cost = Number(parsed[1]);
  if (cost < 4 || cost > 31) return false;
  const salt = parsed[2]!;
  const bcryptHash = `$2b$${String(cost).padStart(2, "0")}$${salt}${parsed[3]!}`;
  return verifyBcrypt(passlibBcryptPassword(password, salt), bcryptHash);
}

/** Reads the cost out of a bcrypt hash so Verify mode can report what it used. */
export function bcryptCostOf(stored: string): number | undefined {
  const passlib = PASSLIB_BCRYPT_SHA256_RE.exec(stored);
  if (passlib) return Number(passlib[1]);
  try {
    return bcryptjs.getRounds(stored);
  } catch {
    return undefined;
  }
}

export {
  md5Crypt,
  sha256Crypt,
  sha512Crypt,
  cryptVerify,
  crypt3,
  crypt3Verify,
  apr1Crypt,
  apacheSha,
  apacheShaVerify,
  formatHtpasswdRecord,
  parseHtpasswdRecord,
  unixDesCrypt,
  bsdExtendedCrypt,
  lmHash,
  ntlmHash,
  oneStepKdf,
  wpaPsk,
} from "@ocs/algos";

/**
 * The derivations, re-exported so this module stays the KDF family's single binding entry point.
 *
 * `export *` rather than a list, so a seventh derivation added next door needs no edit here.
 */
export * from "./key-source";
