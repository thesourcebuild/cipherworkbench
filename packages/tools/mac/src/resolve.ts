import { decodeBytesOption } from "@ocs/engine";
import { optString } from "@ocs/contracts/pure";
import { macCatalogueFor } from "./catalogue/options";
import {
  DEFAULT_HMAC_HASH,
  DEFAULT_KMAC_VARIANT,
  requireHmacHash,
  requireMacTool,
} from "./catalogue/tool-meta";
import {
  OPTION_KEY,
  readCustomization,
  readHash,
  readKmacOutputLength,
  readSkeinState,
  readKmacVariant,
  readTruncate,
} from "./pure";
import type { MacSpec } from "./spec";

/**
 * Accepted key lengths, read from the tool's own catalogue rather than restated here.
 *
 * This was a `Record` mirroring each `keyOption`'s `bytesLength`, and mirrors drift: adding SipHash
 * updated the catalogue and not the table, so an 8-byte key passed the resolver and failed inside the
 * implementation with a message about the algorithm rather than about the form. Asking the catalogue
 * cannot go out of step with it.
 *
 * `undefined` means the tool takes a range rather than a list -- HMAC and Skein-MAC both accept any
 * length, which for Skein is a genuine advantage over HMAC -- and `decodeBytesOption` has already
 * enforced the bounds in that case.
 */
function exactKeyLengths(toolId: string): readonly number[] | undefined {
  return macCatalogueFor(toolId).require(OPTION_KEY).bytesLength?.exact;
}

export interface ResolvedMac {
  toolId: string;
  key: Uint8Array;
  /** HMAC only. */
  hashId: string;
  /** KMAC only. */
  kmacVariant: string;
  kmacOutputLen: number;
  /** Skein-MAC only: the state size in bytes -- 32, 64 or 128. */
  skeinState: number;
  customization: Uint8Array;
  /** HMAC only — undefined means the full digest. */
  truncateTo: number | undefined;
  /** The tag length this configuration will actually produce. */
  outputLen: number;
}

export type ResolveResult =
  { ok: true; resolved: ResolvedMac } | { ok: false; problem: string; optionId: string };

/**
 * Turns a spec into everything the compute path needs, or explains what is missing.
 *
 * Shared by compute, the lint rules and `describeSpec`, so the three cannot disagree about
 * whether a key is usable — a lint rule that passed a key compute then rejected would be
 * worse than no rule.
 */
export function resolveMac(spec: MacSpec): ResolveResult {
  const tool = requireMacTool(spec.variant);

  const keyText = optString(spec.options, OPTION_KEY);
  if (keyText === undefined) {
    return { ok: false, problem: "Enter a key.", optionId: OPTION_KEY };
  }

  // Decoded through the engine so the fallback encoding comes from the catalogue's
  // `defaultBytesEncoding` rather than being assumed here — the options form reads the same
  // field to pick which entry its selector starts on, and the two must not disagree.
  const decoded = decodeBytesOption(macCatalogueFor(spec.variant), spec.options, OPTION_KEY);
  if (!decoded.ok) {
    return { ok: false, problem: decoded.error, optionId: OPTION_KEY };
  }
  const key = decoded.bytes;

  const exact = exactKeyLengths(spec.variant);
  if (exact && !exact.includes(key.length)) {
    const list = exact.join(", ");
    return {
      ok: false,
      // States what was given as well as what is required — "needs 32 bytes" alone leaves
      // the user counting hex characters.
      problem: `${tool.label} needs a key of exactly ${list} bytes; this one is ${key.length}.`,
      optionId: OPTION_KEY,
    };
  }

  if (key.length === 0) {
    return { ok: false, problem: "The key decoded to zero bytes.", optionId: OPTION_KEY };
  }

  const hashId = readHash(spec.options, DEFAULT_HMAC_HASH);
  const kmacVariant = readKmacVariant(spec.options, DEFAULT_KMAC_VARIANT);
  const kmacDefaultLen = kmacVariant === "kmac256" ? 64 : 32;
  const skeinState = readSkeinState(spec.options);
  const kmacOutputLen = readKmacOutputLength(spec.options, kmacDefaultLen);
  const truncateTo = readTruncate(spec.options);

  let naturalLen: number;
  if (spec.variant === "hmac") {
    // A share link can name a hash this tool does not offer; fall back rather than blank.
    let hash;
    try {
      hash = requireHmacHash(hashId);
    } catch {
      hash = requireHmacHash(DEFAULT_HMAC_HASH);
    }
    naturalLen = hash.outputLen;
  } else if (spec.variant === "kmac") {
    naturalLen = kmacOutputLen;
  } else if (spec.variant === "skeinmac") {
    // Skein's natural tag is its state size, which is also what the option's placeholder shows.
    naturalLen = readKmacOutputLength(spec.options, skeinState);
  } else if (spec.variant === "highwayhash") {
    // One of three exact widths, not a truncation -- so an off-list value falls back to 8 rather
    // than being clamped into range, the same rule the hash family's `outputLengths` follows.
    const requested = readKmacOutputLength(spec.options, 8);
    naturalLen = requested === 16 || requested === 32 ? requested : 8;
  } else if (spec.variant === "asconprf") {
    naturalLen = readKmacOutputLength(spec.options, 32);
  } else if (spec.variant === "asconprfs") {
    // PRFShort squeezes from two state words and cannot produce more than 16 bytes.
    naturalLen = Math.min(readKmacOutputLength(spec.options, 16), 16);
  } else {
    naturalLen = tool.outputLen ?? 16;
  }

  if (spec.variant === "hmac" && truncateTo !== undefined && truncateTo > naturalLen) {
    return {
      ok: false,
      problem: `Cannot truncate to ${truncateTo} bytes — the tag is only ${naturalLen}.`,
      optionId: "truncate",
    };
  }

  const customizationText = readCustomization(spec.options) ?? "";

  return {
    ok: true,
    resolved: {
      toolId: spec.variant,
      key,
      hashId: spec.variant === "hmac" && !isOfferedHash(hashId) ? DEFAULT_HMAC_HASH : hashId,
      kmacVariant: kmacVariant === "kmac256" ? "kmac256" : "kmac128",
      kmacOutputLen,
      skeinState,
      customization: new TextEncoder().encode(customizationText),
      truncateTo,
      outputLen: truncateTo ?? naturalLen,
    },
  };
}

function isOfferedHash(id: string): boolean {
  try {
    requireHmacHash(id);
    return true;
  } catch {
    return false;
  }
}
