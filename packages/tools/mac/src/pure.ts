/**
 * Zod-free constants and accessors for the MAC family.
 */
import type { OptionValues } from "@ocs/contracts/options";
import { optNumber, optString, setOption } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;

export const OPTION_HASH = "hash";
export const OPTION_KMAC_VARIANT = "variant";
export const OPTION_KEY = "key";
export const OPTION_CUSTOMIZATION = "customization";
export const OPTION_OUTPUT_LENGTH = "outputLength";
export const OPTION_TRUNCATE = "truncate";
export const OPTION_SKEIN_STATE = "skeinState";

/** `availableOn` tags. */
export const TAG_HMAC = "hmac";
export const TAG_KMAC = "kmac";
export const TAG_SKEIN_MAC = "skeinmac";
export const TAG_ASCON_PRF = "asconprf";
export const TAG_HIGHWAY = "highwayhash";

export function readHash(options: OptionValues, fallback: string): string {
  return optString(options, OPTION_HASH) ?? fallback;
}

export function readKmacVariant(options: OptionValues, fallback: string): string {
  return optString(options, OPTION_KMAC_VARIANT) ?? fallback;
}

export function readCustomization(options: OptionValues): string | undefined {
  return optString(options, OPTION_CUSTOMIZATION);
}

/**
 * Requested tag length, or undefined for the algorithm's natural size.
 *
 * Truncation is a legitimate, standardised operation for HMAC — HMAC-SHA-256-128 is what
 * IPsec uses — and a footgun below about half the digest, which is why `M004` exists
 * rather than this function clamping silently.
 */
export function readTruncate(options: OptionValues): number | undefined {
  const raw = optNumber(options, OPTION_TRUNCATE);
  if (raw === undefined || !Number.isInteger(raw) || raw < 1) return undefined;
  return raw;
}

/**
 * Skein-MAC's state size in bytes: 32, 64 or 128.
 *
 * Skein-512 is the variant its authors nominate, so that is the fallback rather than the smallest.
 */
/**
 * Reads a count that may have been stored as a number or as a string.
 *
 * The distinction is the whole reason this exists rather than a bare `optNumber`. A `number` option
 * stores a number; an `enum` option stores a *string*, because that is what a select produces.
 * Skein-MAC's state size and HighwayHash's width are selects while Skein's tag length is a number
 * field, so both spellings reach these readers -- and `optNumber` returns undefined for "64", which
 * silently sends every value to the fallback.
 *
 * This family had that bug twice over and could not see it: `readSkeinState` and
 * `readKmacOutputLength` both read only the numeric spelling, and the two controls that would have
 * exposed it were invisible because `variantTag` returned `undefined`. The unit tests wrote numbers
 * the form never produces. The hash family carries the identical helper for the identical reason;
 * do not narrow either back.
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

export function readSkeinState(options: OptionValues, fallback = 64): number {
  const raw = readCount(options, OPTION_SKEIN_STATE);
  return raw === 32 || raw === 64 || raw === 128 ? raw : fallback;
}

export function readKmacOutputLength(options: OptionValues, fallback: number): number {
  const raw = readCount(options, OPTION_OUTPUT_LENGTH);
  if (raw === undefined) return fallback;
  return Math.min(raw, 1024);
}

export function withHash(options: OptionValues, hash: string): OptionValues {
  return setOption(options, OPTION_HASH, hash);
}

export function withTruncate(options: OptionValues, bytes: number | undefined): OptionValues {
  return setOption(options, OPTION_TRUNCATE, bytes);
}

export function withKey(options: OptionValues, key: string): OptionValues {
  return setOption(options, OPTION_KEY, key);
}
