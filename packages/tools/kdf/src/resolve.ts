import { optString } from "@ocs/contracts/pure";
import { decodeBytesOption } from "@ocs/engine";
import { kdfCatalogueFor } from "./catalogue/options";
import {
  DEFAULT_ARGON2_VARIANT,
  DEFAULT_KDF_HASH,
  requireKdfTool,
} from "./catalogue/tool-meta";
import {
  OPTION_ARGON2_MEMORY,
  OPTION_ARGON2_AD,
  OPTION_ARGON2_PARALLELISM,
  OPTION_ARGON2_SECRET,
  OPTION_ARGON2_TIME,
  OPTION_ARGON2_VARIANT,
  OPTION_BCRYPT_COST,
  OPTION_IKM,
  OPTION_INFO,
  OPTION_ITERATIONS,
  OPTION_KEY_LENGTH,
  OPTION_PASSWORD,
  OPTION_ROUNDS,
  OPTION_SALT,
  OPTION_SCRYPT_N,
  OPTION_SCRYPT_P,
  OPTION_SCRYPT_R,
  OPENSSH_DEFAULT_ROUNDS,
  OPENSSH_KEY_IV_BYTES,
  OWASP_ARGON2_MEMORY_KIB,
  OWASP_BCRYPT_COST,
  OWASP_SCRYPT_N,
  owaspPbkdf2Minimum,
  readExpected,
  readHash,
  readMode,
  readPositiveInt,
  type KdfMode,
} from "./pure";
import type { KdfSpec } from "./spec";

/**
 * Minimum salt length the algorithm itself imposes, in bytes. Absent means none — the
 * recommendation is then carried by `K004` rather than enforced here.
 */
const MIN_SALT_LENGTHS: Readonly<Record<string, number>> = {
  argon2: 8,
  // OpenBSD's `bcrypt_pbkdf` returns -1 for an empty salt rather than substituting anything.
  bcryptpbkdf: 1,
};

export interface ResolvedKdf {
  toolId: string;
  mode: KdfMode;
  /** UTF-8 bytes of the password, for the four password hashes. */
  password: Uint8Array;
  /** The password as text — bcrypt is defined over a string, not bytes. */
  passwordText: string;
  salt: Uint8Array;
  /** HKDF only. */
  ikm: Uint8Array;
  info: Uint8Array;
  hashId: string;
  iterations: number;
  keyLength: number;
  scryptN: number;
  scryptR: number;
  scryptP: number;
  argon2Variant: "argon2id" | "argon2i" | "argon2d";
  argon2MemoryKib: number;
  argon2Time: number;
  argon2Parallelism: number;
  bcryptCost: number;
  /** bcrypt-PBKDF only. Linear, unlike bcrypt's log2 cost. */
  rounds: number;
  /** Argon2's optional pepper and context binding. Empty when unset. */
  argon2Secret: Uint8Array;
  argon2AssociatedData: Uint8Array;
  /** Verify mode only. */
  expected: string | undefined;
}

export type ResolveResult =
  { ok: true; resolved: ResolvedKdf } | { ok: false; problem: string; optionId: string };

/**
 * Decodes one of this tool's `bytes` options.
 *
 * Delegates to the engine so the fallback encoding comes from the option definition rather
 * than being assumed here. `info` and `salt` default to UTF-8; hardcoding either
 * would make the form's selector disagree with what is actually computed.
 */
function decodeOption(spec: KdfSpec, id: string) {
  return decodeBytesOption(kdfCatalogueFor(spec.variant), spec.options, id);
}

/**
 * Turns a spec into everything the compute path needs, or names what is missing.
 *
 * Shared by compute, lint and describe. Note that estimating cost is deliberately *not*
 * done here: a lint rule needs to compare the configured cost against a recommendation, and
 * that comparison belongs next to the recommendation in `pure.ts` rather than being
 * duplicated into a resolved field.
 */
export function resolveKdf(spec: KdfSpec): ResolveResult {
  const tool = requireKdfTool(spec.variant);
  const mode = tool.supportsVerify ? readMode(spec.options) : "derive";

  const passwordText = optString(spec.options, OPTION_PASSWORD) ?? "";
  const password = new TextEncoder().encode(passwordText);

  const expected = readExpected(spec.options);
  if (mode === "verify" && (expected === undefined || expected.trim() === "")) {
    return {
      ok: false,
      problem: "Paste the stored hash to check against.",
      optionId: "expected",
    };
  }

  // HKDF takes key material rather than a password; everything else takes a password.
  if (spec.variant === "hkdf") {
    const ikm = decodeOption(spec, OPTION_IKM);
    if (!ikm.ok) return { ok: false, problem: ikm.error, optionId: OPTION_IKM };
    if (ikm.bytes.length === 0) {
      return { ok: false, problem: "Enter some input key material.", optionId: OPTION_IKM };
    }
  }
  /**
   * An empty password is permitted, not rejected.
   *
   * These functions are defined over any byte string, and RFC 7914's first scrypt vector
   * uses an empty password and an empty salt — a tool that refuses to reproduce the
   * standard's own test vector is wrong. Blocking it here would also be the wrong shape of
   * feedback: the checks panel says an empty password protects nothing (`K008`), which is
   * information the user can act on, while a hard error just stops them.
   */

  /**
   * bcrypt-PBKDF is the one tool here that genuinely cannot take an empty password.
   *
   * Not a policy: `bcrypt_pbkdf` returns -1 and fills the output with random bytes, and there is
   * no published vector using one. Caught here rather than in the binding so the message points at
   * the field. Every other tool in this family permits it and `K008` says what it means -- see the
   * note below on RFC 7914's own vector.
   */
  if (spec.variant === "bcryptpbkdf" && mode === "derive" && password.length === 0) {
    return {
      ok: false,
      problem: "bcrypt-PBKDF needs a password; OpenBSD's implementation refuses an empty one.",
      optionId: OPTION_PASSWORD,
    };
  }

  const saltResult = decodeOption(spec, OPTION_SALT);
  if (!saltResult.ok) return { ok: false, problem: saltResult.error, optionId: OPTION_SALT };

  const ikmResult = decodeOption(spec, OPTION_IKM);
  if (!ikmResult.ok) return { ok: false, problem: ikmResult.error, optionId: OPTION_IKM };

  const infoResult = decodeOption(spec, OPTION_INFO);
  if (!infoResult.ok) return { ok: false, problem: infoResult.error, optionId: OPTION_INFO };

  const secretResult = decodeOption(spec, OPTION_ARGON2_SECRET);
  if (!secretResult.ok) {
    return { ok: false, problem: secretResult.error, optionId: OPTION_ARGON2_SECRET };
  }

  const adResult = decodeOption(spec, OPTION_ARGON2_AD);
  if (!adResult.ok) return { ok: false, problem: adResult.error, optionId: OPTION_ARGON2_AD };

  /**
   * Salt length: a hard minimum where the algorithm has one, advice where it does not.
   *
   * PBKDF2 and scrypt accept any salt including none, and RFC 7914's first scrypt vector uses
   * an empty one — so refusing it there would make the tool unable to reproduce the standard.
   * `K004` reports that as `insecure` instead, which is advice the user can act on.
   *
   * Argon2 is different: RFC 9106 sets a floor of 8 bytes and noble enforces it by throwing.
   * That is a genuine constraint rather than a policy, so it is caught here with a message
   * that names the requirement, rather than letting a library error surface verbatim.
   */
  const minSalt = MIN_SALT_LENGTHS[spec.variant] ?? 0;
  if (mode === "derive" && saltResult.bytes.length < minSalt) {
    return {
      ok: false,
      problem:
        saltResult.bytes.length === 0
          ? `${tool.label} needs a salt of at least ${minSalt} ${minSalt === 1 ? "byte" : "bytes"}. Press Generate for 16.`
          : `${tool.label} needs a salt of at least ${minSalt} bytes; this one is ${saltResult.bytes.length}.`,
      optionId: OPTION_SALT,
    };
  }

  const hashId = readHash(spec.options, DEFAULT_KDF_HASH);
  const variantRaw = optString(spec.options, OPTION_ARGON2_VARIANT) ?? DEFAULT_ARGON2_VARIANT;
  const argon2Variant =
    variantRaw === "argon2i" || variantRaw === "argon2d" ? variantRaw : "argon2id";

  const scryptN = readPositiveInt(spec.options, OPTION_SCRYPT_N, OWASP_SCRYPT_N);
  // scrypt requires N to be a power of two, and noble throws rather than rounding.
  if (spec.variant === "scrypt" && (scryptN & (scryptN - 1)) !== 0) {
    return {
      ok: false,
      problem: `N must be a power of two; ${scryptN} is not. Try ${1 << Math.round(Math.log2(scryptN))}.`,
      optionId: OPTION_SCRYPT_N,
    };
  }

  return {
    ok: true,
    resolved: {
      toolId: spec.variant,
      mode,
      password,
      passwordText,
      salt: saltResult.bytes,
      ikm: ikmResult.bytes,
      info: infoResult.bytes,
      hashId,
      /**
       * The default differs by tool, and both defaults are deliberate.
       *
       * PBKDF2 starts at OWASP's current floor, because someone reaching for it is protecting a
       * password now. EvpKDF starts at 1, because someone reaching for *that* is reproducing a
       * file `openssl enc -k` wrote -- and OpenSSL used 1. Defaulting it to a safe number would
       * make the tool fail at the only job it has.
       */
      iterations: readPositiveInt(
        spec.options,
        OPTION_ITERATIONS,
        spec.variant === "evpkdf" ? 1 : owaspPbkdf2Minimum(hashId),
      ),
      // 48 bytes for EvpKDF and bcrypt-PBKDF alike, and for the same reason both times: a
      // 32-byte key plus a 16-byte IV is what `EVP_BytesToKey` is nearly always asked for, and
      // what OpenSSH cuts out of a bcrypt-PBKDF stream for an AES-256-CTR private-key file.
      keyLength: readPositiveInt(
        spec.options,
        OPTION_KEY_LENGTH,
        spec.variant === "evpkdf" || spec.variant === "bcryptpbkdf" ? OPENSSH_KEY_IV_BYTES : 32,
      ),
      scryptN,
      scryptR: readPositiveInt(spec.options, OPTION_SCRYPT_R, 8),
      scryptP: readPositiveInt(spec.options, OPTION_SCRYPT_P, 1),
      argon2Variant,
      argon2MemoryKib: readPositiveInt(
        spec.options,
        OPTION_ARGON2_MEMORY,
        OWASP_ARGON2_MEMORY_KIB,
      ),
      argon2Time: readPositiveInt(spec.options, OPTION_ARGON2_TIME, 2),
      argon2Parallelism: readPositiveInt(spec.options, OPTION_ARGON2_PARALLELISM, 1),
      bcryptCost: readPositiveInt(spec.options, OPTION_BCRYPT_COST, OWASP_BCRYPT_COST),
      rounds: readPositiveInt(spec.options, OPTION_ROUNDS, OPENSSH_DEFAULT_ROUNDS),
      argon2Secret: secretResult.bytes,
      argon2AssociatedData: adResult.bytes,
      expected,
    },
  };
}
