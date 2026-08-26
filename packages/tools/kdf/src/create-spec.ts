import {
  DEFAULT_ARGON2_VARIANT,
  DEFAULT_KDF_HASH,
  requireKdfTool,
} from "./catalogue/tool-meta";
import {
  OPTION_ARGON2_MEMORY,
  OPTION_ARGON2_PARALLELISM,
  OPTION_ARGON2_TIME,
  OPTION_ARGON2_VARIANT,
  OPTION_BCRYPT_COST,
  OPTION_HASH,
  OPTION_ITERATIONS,
  OPTION_KEY_LENGTH,
  OPTION_MODE,
  OPTION_ROUNDS,
  OPTION_SCRYPT_N,
  OPTION_SCRYPT_P,
  OPTION_SCRYPT_R,
  OWASP_ARGON2_MEMORY_KIB,
  OWASP_BCRYPT_COST,
  OWASP_PBKDF2_SHA256,
  OPENSSH_DEFAULT_ROUNDS,
  OPENSSH_KEY_IV_BYTES,
  OWASP_SCRYPT_N,
  SPEC_VERSION,
} from "./pure";
import type { KdfSpec } from "./spec";

/** The canonical default-spec factory. */
export function createSpec(options?: { variant?: string }): KdfSpec {
  const variant = options?.variant ?? "argon2";
  requireKdfTool(variant);

  const base: KdfSpec["options"] = { [OPTION_MODE]: "derive" };

  /**
   * Defaults are the current recommendations, not the algorithm minimums.
   *
   * A tool that opened on PBKDF2 with 1000 iterations would teach the wrong thing by default,
   * and most people compute something before they read the Checks panel.
   */
  switch (variant) {
    case "pbkdf2":
      base[OPTION_HASH] = DEFAULT_KDF_HASH;
      base[OPTION_ITERATIONS] = OWASP_PBKDF2_SHA256;
      base[OPTION_KEY_LENGTH] = 32;
      break;
    case "hkdf":
      base[OPTION_HASH] = DEFAULT_KDF_HASH;
      base[OPTION_KEY_LENGTH] = 32;
      break;
    /**
     * EvpKDF renders the same hash select and was the one tool that did not seed it.
     *
     * `DEFAULT_KDF_HASH` is what its resolver already falls back to -- SHA-256, which is what
     * `openssl enc` has defaulted to since 1.1.0 -- so nothing computes differently. What changes is
     * that the control shows it rather than "(not set)". The iteration count stays at 1 and the salt
     * at 8 bytes, both handled elsewhere and both historical rather than modern, because reproducing
     * an old file is this tool's only job.
     */
    case "evpkdf":
      base[OPTION_HASH] = DEFAULT_KDF_HASH;
      break;
    case "scrypt":
      base[OPTION_SCRYPT_N] = OWASP_SCRYPT_N;
      base[OPTION_SCRYPT_R] = 8;
      base[OPTION_SCRYPT_P] = 1;
      base[OPTION_KEY_LENGTH] = 32;
      break;
    case "argon2":
      base[OPTION_ARGON2_VARIANT] = DEFAULT_ARGON2_VARIANT;
      base[OPTION_ARGON2_MEMORY] = OWASP_ARGON2_MEMORY_KIB;
      base[OPTION_ARGON2_TIME] = 2;
      base[OPTION_ARGON2_PARALLELISM] = 1;
      base[OPTION_KEY_LENGTH] = 32;
      break;
    case "bcrypt":
      base[OPTION_BCRYPT_COST] = OWASP_BCRYPT_COST;
      break;
    case "bcryptpbkdf":
      base[OPTION_ROUNDS] = OPENSSH_DEFAULT_ROUNDS;
      base[OPTION_KEY_LENGTH] = OPENSSH_KEY_IV_BYTES;
      break;
  }

  return { specVersion: SPEC_VERSION, variant, options: base };
}
