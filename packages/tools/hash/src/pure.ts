/**
 * Zod-free constants and accessors, mirroring `@ocs/contracts/pure`'s rationale:
 * the UI needs to read and write this tool's options without dragging schema
 * construction into the browser bundle.
 */
import type { OptionValues } from "@ocs/contracts/options";
import { optNumber, optString, setOption } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;
export const TOOL_FAMILY = "hash";

/** Option ids. Referenced by the catalogue, the compute path and the lint rules. */
export const OPTION_ITERATIONS = "iterations";
export const OPTION_OUTPUT_LENGTH = "outputLength";
export const OPTION_SEED = "seed";
export const OPTION_PASSES = "passes";
export const OPTION_SEED_64 = "seed64";
export const OPTION_HASH_VARIANT = "hashVariant";

/**
 * The SHA-3 addon parameters. Each is `availableOn`-gated, so SHA-256 renders none of them.
 *
 * These are what separate a keyed/domain-separated sponge from a plain digest, and getting one
 * wrong produces a valid-looking value that matches nothing -- which is why each carries a long
 * `detail` in the catalogue rather than a terse label.
 */
/**
 * BLAKE2's and BLAKE3's own parameters, which every other algorithm here ignores.
 *
 * `key` turns either into a MAC in one step -- no HMAC construction, because the key goes into the
 * initial state rather than around the outside. RFC 7693 section 2.9 for BLAKE2; the BLAKE3
 * specification's `keyed_hash` for BLAKE3. `salt` and `personalization` are BLAKE2 only, and are what
 * libsodium's `generichash` and Argon2's use of BLAKE2b are built on. `context` is BLAKE3's
 * `derive_key` mode, which is a KDF rather than a MAC and is why it cannot be combined with a key.
 */
export const OPTION_BLAKE_KEY = "blakeKey";
export const OPTION_BLAKE_SALT = "blakeSalt";
export const OPTION_BLAKE_PERSONAL = "blakePersonal";
export const OPTION_BLAKE_CONTEXT = "blakeContext";

export const OPTION_CUSTOMIZATION = "customization";
export const OPTION_FUNCTION_NAME = "functionName";
export const OPTION_BLOCK_SIZE = "blockSize";
export const OPTION_DOMAIN = "domain";
export const OPTION_TUPLE = "tuple";

/** ParallelHash's default block size in bytes. SP 800-185's own examples use 8. */
export const DEFAULT_PARALLEL_BLOCK_SIZE = 8;
export const MAX_PARALLEL_BLOCK_SIZE = 1 << 20;

/**
 * TurboSHAKE's domain-separation byte. Any value 0x01-0x7F is legal; 0x1F is the one the
 * specification uses for the bare XOF and the only one anything interoperates on by default.
 */
export const DEFAULT_TURBOSHAKE_DOMAIN = 0x1f;

export const DEFAULT_ITERATIONS = 1;

/** The double-hash construction — `H(H(x))`, as used for Bitcoin block and transaction ids. */
export const DOUBLE_HASH_ITERATIONS = 2;

/**
 * H002 fires *above* this, not at it. Two passes is a real construction -- it is
 * what Bitcoin's double-SHA-256 is -- so warning about it would teach people to
 * ignore the checks panel, which is the one thing it cannot afford. Three or more
 * has no established use and is almost always someone reaching for a password
 * KDF.
 */
export const ITERATIONS_WARN_ABOVE = DOUBLE_HASH_ITERATIONS;

/** Keeps a typo like `1e9` from freezing the tab. */
export const MAX_ITERATIONS = 100;

export function readIterations(options: OptionValues): number {
  const raw = optNumber(options, OPTION_ITERATIONS) ?? DEFAULT_ITERATIONS;
  if (!Number.isInteger(raw) || raw < 1) return DEFAULT_ITERATIONS;
  return Math.min(raw, MAX_ITERATIONS);
}

/**
 * The output length the user asked for, unclamped, or undefined if they have not
 * asked for one.
 *
 * Clamping happens in the binding (`bindings.ts`), not here, because the ceiling is
 * per-algorithm — BLAKE2s stops at 32 bytes, BLAKE2b at 64, an XOF effectively
 * nowhere — and the binding is the only place that knows which algorithm it is.
 */
/**
 * Reads a count that may have been stored as a number or as a string.
 *
 * The distinction is the whole reason this helper exists rather than a bare `optNumber`. A `number`
 * option stores a number; an `enum` option stores a *string*, because that is what a select
 * produces. HAVAL's output length and pass count are selects while SHAKE's output length is a
 * number field, so both spellings reach these readers. `optNumber` returns undefined for "24",
 * which is exactly how AEGIS's 256-bit tag length came to be inert in the app while the test suite
 * stayed green -- the tests wrote a number the form never produces. Do not narrow this back.
 */
function readCount(options: OptionValues, id: string): number | undefined {
  const raw = optNumber(options, id);
  if (raw !== undefined && Number.isInteger(raw) && raw >= 1) return raw;
  const text = optString(options, id);
  if (text === undefined) return undefined;
  const parsed = Number(text);
  if (!Number.isInteger(parsed) || parsed < 1) return undefined;
  return parsed;
}

export function readRequestedOutputLength(options: OptionValues): number | undefined {
  return readCount(options, OPTION_OUTPUT_LENGTH);
}

/** HAVAL's and Tiger's pass count. Undefined for every algorithm without one. */
export function readPasses(options: OptionValues): number | undefined {
  return readCount(options, OPTION_PASSES);
}

export function withPasses(options: OptionValues, passes: number): OptionValues {
  return setOption(options, OPTION_PASSES, String(passes));
}

export function withIterations(options: OptionValues, count: number): OptionValues {
  return setOption(options, OPTION_ITERATIONS, count);
}

/**
 * Removes the option rather than setting it to 1. A spec with no `iterations`
 * key and a spec with `iterations: 1` compute identically, so the absent form is
 * the canonical one — which keeps share links short and makes two specs that
 * mean the same thing compare equal.
 */
export function withoutIterations(options: OptionValues): OptionValues {
  return setOption(options, OPTION_ITERATIONS, undefined);
}

export function withOutputLength(options: OptionValues, bytes: number): OptionValues {
  return setOption(options, OPTION_OUTPUT_LENGTH, bytes);
}

/**
 * The xxHash seed. Absent means zero, which is what every tool that prints an xxHash
 * without mentioning a seed used.
 */
/**
 * Which of an algorithm's named variants is selected.
 *
 * A single option shared by every algorithm that has one, rather than a per-tool id: MetroHash's two
 * constant sets and t1ha's two versions are the same kind of choice, and one id means one control, one
 * reader and one seeding rule. The caller resolves an absent or unrecognised value against its own
 * list, because only the algorithm knows what its default is.
 */
export function readHashVariant(options: OptionValues): string | undefined {
  const raw = optString(options, OPTION_HASH_VARIANT);
  return raw === undefined || raw === "" ? undefined : raw;
}

export function readSeed(options: OptionValues): number {
  const raw = optNumber(options, OPTION_SEED);
  if (raw === undefined || !Number.isFinite(raw)) return 0;
  // Wrapped into the unsigned 32-bit range rather than rejected: a seed is an opaque
  // parameter, and there is no such thing as an invalid one.
  return raw >>> 0;
}

export function withSeed(options: OptionValues, seed: number): OptionValues {
  return setOption(options, OPTION_SEED, seed);
}

/** ParallelHash's block size, in bytes. */
export function readBlockSize(options: OptionValues): number {
  const raw = optNumber(options, OPTION_BLOCK_SIZE);
  if (raw === undefined || !Number.isInteger(raw) || raw < 1)
    return DEFAULT_PARALLEL_BLOCK_SIZE;
  return Math.min(raw, MAX_PARALLEL_BLOCK_SIZE);
}

/**
 * TurboSHAKE's domain byte, clamped to the legal 0x01-0x7F range rather than rejected.
 *
 * Out of range is a stale share link or a typo, and falling back to the specified default gives
 * an answer someone can compare against a reference. `H010` says when the value is not the default.
 */
export function readDomain(options: OptionValues): number {
  const raw = optNumber(options, OPTION_DOMAIN);
  if (raw === undefined || !Number.isInteger(raw) || raw < 0x01 || raw > 0x7f) {
    return DEFAULT_TURBOSHAKE_DOMAIN;
  }
  return raw;
}
