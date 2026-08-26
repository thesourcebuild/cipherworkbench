/**
 * Zod-free constants and accessors for the KDF family.
 *
 * OWASP's current password-storage guidance is encoded here as named constants rather than
 * scattered through the lint rules. These numbers move over time, and when they do this is
 * the one place to change.
 */
import type { OptionValues } from "@ocs/contracts/options";
import { optNumber, optString, setOption } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;

export const OPTION_MODE = "mode";
export const OPTION_PASSWORD = "password";
export const OPTION_SALT = "salt";
export const OPTION_HASH = "hash";
export const OPTION_ITERATIONS = "iterations";
export const OPTION_KEY_LENGTH = "keyLength";
export const OPTION_INFO = "info";
export const OPTION_IKM = "ikm";
export const OPTION_SCRYPT_N = "costN";
export const OPTION_SCRYPT_R = "blockR";
export const OPTION_SCRYPT_P = "parallelP";
export const OPTION_ARGON2_VARIANT = "variant";
export const OPTION_ARGON2_MEMORY = "memoryKib";
export const OPTION_ARGON2_TIME = "timeCost";
export const OPTION_ARGON2_PARALLELISM = "parallelism";
export const OPTION_ARGON2_SECRET = "secret";
export const OPTION_ARGON2_AD = "associatedData";
export const OPTION_BCRYPT_COST = "cost";
export const OPTION_ROUNDS = "rounds";
export const OPTION_EXPECTED = "expected";

/** `availableOn` tags — one per tool, since each has a disjoint parameter set. */
export const TAG_PBKDF2 = "pbkdf2";
export const TAG_HKDF = "hkdf";
export const TAG_SCRYPT = "scrypt";
export const TAG_ARGON2 = "argon2";
export const TAG_BCRYPT = "bcrypt";
export const TAG_VERIFY = "verify";

/** Derive a new value, or check one that already exists. */
export type KdfMode = "derive" | "verify";

export function readMode(options: OptionValues): KdfMode {
  return optString(options, OPTION_MODE) === "verify" ? "verify" : "derive";
}

export function withMode(options: OptionValues, mode: KdfMode): OptionValues {
  return setOption(options, OPTION_MODE, mode);
}

// ── OWASP Password Storage Cheat Sheet, 2024 ────────────────────────────────

/** PBKDF2-HMAC-SHA256. The SHA-1 and SHA-512 figures differ; see `owaspPbkdf2Minimum`. */
export const OWASP_PBKDF2_SHA256 = 600_000;
export const OWASP_PBKDF2_SHA512 = 210_000;
export const OWASP_PBKDF2_SHA1 = 1_300_000;

/**
 * The recommended floor scales inversely with how much work the hash does per iteration,
 * which is why one number cannot cover all three. Quoting the SHA-256 figure at someone
 * using SHA-512 would overstate it by nearly 3x.
 */
export function owaspPbkdf2Minimum(hashId: string): number {
  switch (hashId) {
    case "sha512":
    case "sha384":
      return OWASP_PBKDF2_SHA512;
    case "sha1":
      return OWASP_PBKDF2_SHA1;
    default:
      return OWASP_PBKDF2_SHA256;
  }
}

/** scrypt: OWASP's minimum is N=2^17, r=8, p=1. */
export const OWASP_SCRYPT_N = 1 << 17;
export const OWASP_SCRYPT_R = 8;

/** Argon2id: RFC 9106's second recommended option — 64 MiB, t=3, p=4. */
export const OWASP_ARGON2_MEMORY_KIB = 19 * 1024;
export const OWASP_ARGON2_TIME = 2;

/** bcrypt: cost 10 is the modern floor. */
export const OWASP_BCRYPT_COST = 10;

/**
 * `ssh-keygen -a`'s default since 2013, and the floor `K002` measures against.
 *
 * Deliberately not presented as a recommendation the way the OWASP constants above are: nobody
 * publishes a password-storage figure for bcrypt-PBKDF, because it is used to unlock a key
 * interactively rather than to store a hash. It is what OpenSSH ships, which makes it the number
 * a lower setting should be compared against.
 */
export const OPENSSH_DEFAULT_ROUNDS = 16;

/**
 * The key and IV OpenSSH cuts out of the derived stream: AES-256-CTR's 32 plus 16.
 *
 * The commonest thing anyone asks bcrypt-PBKDF for, and therefore its default output length.
 */
export const OPENSSH_KEY_IV_BYTES = 48;

/** bcrypt silently ignores everything past this. Not a recommendation — a hard limit. */
export const BCRYPT_PASSWORD_LIMIT = 72;

/** Below 16 bytes a salt starts to risk collisions across a real user table. */
export const MIN_SALT_BYTES = 8;
export const RECOMMENDED_SALT_BYTES = 16;

// ── accessors ───────────────────────────────────────────────────────────────

export function readHash(options: OptionValues, fallback: string): string {
  return optString(options, OPTION_HASH) ?? fallback;
}

export function readPositiveInt(options: OptionValues, id: string, fallback: number): number {
  const raw = optNumber(options, id);
  if (raw === undefined || !Number.isInteger(raw) || raw < 1) return fallback;
  return raw;
}

export function readExpected(options: OptionValues): string | undefined {
  return optString(options, OPTION_EXPECTED);
}

export function withIterations(options: OptionValues, count: number): OptionValues {
  return setOption(options, OPTION_ITERATIONS, count);
}

export function withOption(
  options: OptionValues,
  id: string,
  value: number | string,
): OptionValues {
  return setOption(options, id, value);
}
