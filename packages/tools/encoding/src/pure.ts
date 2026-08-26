/**
 * Zod-free constants and accessors, same rationale as the other families' `pure.ts`.
 */
import type { OptionValues } from "@ocs/contracts/options";
import { optEnumOr, setOption } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;

export const OPTION_DIRECTION = "direction";
export const OPTION_VARIANT = "variant";
export const OPTION_PADDING = "padding";
export const OPTION_CASE = "case";
export const OPTION_SEPARATOR = "separator";
export const OPTION_KEY_ORDER = "keyOrder";
export const OPTION_JSON_INDENT = "jsonIndent";

export const DIRECTIONS = ["encode", "decode"] as const;
export type Direction = (typeof DIRECTIONS)[number];

/**
 * Every alphabet any tool here offers, in one union.
 *
 * One list rather than one per tool because the compute path switches on it once and because
 * `validateCatalogue` then has a single set of ids to check the choices against. A tool exposes only
 * the values that mean something for it, through its `variants` in the metadata.
 */
export const VARIANTS = [
  "rfc4648",
  "rfc4648-hex",
  "crockford",
  "bitcoin",
  "ripple",
  "flickr",
  "check",
  "standard",
  "urlsafe",
] as const;
export type Variant = (typeof VARIANTS)[number];

/**
 * Padding, as an enum rather than a boolean.
 *
 * `setOption` stores `false` by deleting the key, so absent and off are the same state and a boolean
 * cannot default to on. Padding must default to on -- RFC 4648 requires it unless a spec says
 * otherwise -- so this names both outcomes instead.
 */
export const PADDINGS = ["padded", "unpadded"] as const;
export type Padding = (typeof PADDINGS)[number];

export const CASES = ["lower", "upper"] as const;
export type HexCase = (typeof CASES)[number];

export const SEPARATORS = ["none", "space", "colon", "dash"] as const;
export type Separator = (typeof SEPARATORS)[number];

/** Literal separator for each id. `none` is the empty string, which is why this is a map. */
export const SEPARATOR_TEXT: Record<Separator, string> = {
  none: "",
  space: " ",
  colon: ":",
  dash: "-",
};

export const KEY_ORDERS = ["as-written", "sorted"] as const;
export type KeyOrder = (typeof KEY_ORDERS)[number];

export const JSON_INDENTS = ["compact", "indented"] as const;
export type JsonIndent = (typeof JSON_INDENTS)[number];

/** `availableOn` tags, so a variant-specific control only appears where it applies. */
export const TAG_ENCODE = "encode";
export const TAG_DECODE = "decode";

export function readDirection(options: OptionValues): Direction {
  return optEnumOr(options, OPTION_DIRECTION, DIRECTIONS, "encode");
}

export function readVariant(options: OptionValues, fallback: Variant): Variant {
  return optEnumOr(options, OPTION_VARIANT, VARIANTS, fallback);
}

export function readPadding(options: OptionValues): Padding {
  return optEnumOr(options, OPTION_PADDING, PADDINGS, "padded");
}

export function readCase(options: OptionValues): HexCase {
  return optEnumOr(options, OPTION_CASE, CASES, "lower");
}

export function readSeparator(options: OptionValues): Separator {
  return optEnumOr(options, OPTION_SEPARATOR, SEPARATORS, "none");
}

export function readKeyOrder(options: OptionValues): KeyOrder {
  return optEnumOr(options, OPTION_KEY_ORDER, KEY_ORDERS, "as-written");
}

export function readJsonIndent(options: OptionValues): JsonIndent {
  return optEnumOr(options, OPTION_JSON_INDENT, JSON_INDENTS, "indented");
}

export function withDirection(options: OptionValues, direction: Direction): OptionValues {
  return setOption(options, OPTION_DIRECTION, direction);
}

export function withVariant(options: OptionValues, variant: Variant): OptionValues {
  return setOption(options, OPTION_VARIANT, variant);
}
