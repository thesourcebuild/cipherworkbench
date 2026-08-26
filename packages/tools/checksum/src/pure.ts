/**
 * Zod-free constants and accessors, same rationale as `@ocs/crc/pure`: the UI reads and writes
 * these without dragging schema construction into the bundle.
 */
import type { OptionValues } from "@ocs/contracts/options";
import { optEnumOr, setOption } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;

export const OPTION_WIDTH = "width";
export const OPTION_WORD_SIZE = "wordSize";
export const OPTION_BYTE_ORDER = "byteOrder";
export const OPTION_RESULT = "result";
export const OPTION_BCC_MODE = "bccMode";

/** Widths, as strings because they are enum choices rather than free numbers. */
export const WIDTH_VALUES = ["8", "16", "32"] as const;
export type WidthValue = (typeof WIDTH_VALUES)[number];

export const BYTE_ORDER_VALUES = ["big", "little"] as const;
export type ByteOrderValue = (typeof BYTE_ORDER_VALUES)[number];

/**
 * What a one's-complement sum reports.
 *
 * An enum rather than a boolean because the default has to be "complement" — that is the
 * Internet checksum, which is what anyone opening this tool is after — and a `boolean` option
 * cannot default to true: `setOption` stores `false` by deleting the key, so absent and off are
 * the same state. Naming both outcomes is clearer anyway.
 */
export const RESULT_VALUES = ["complement", "sum"] as const;
export type ResultValue = (typeof RESULT_VALUES)[number];

export const BCC_MODE_VALUES = ["xor", "sum"] as const;
export type BccModeValue = (typeof BCC_MODE_VALUES)[number];

/** `availableOn` tag carried by the byte-order option: only meaningful once words are multi-byte. */
export const TAG_WORDS = "words";

export function readWidth(options: OptionValues, fallback: WidthValue = "8"): 8 | 16 | 32 {
  return Number(optEnumOr(options, OPTION_WIDTH, WIDTH_VALUES, fallback)) as 8 | 16 | 32;
}

export function readWordSize(options: OptionValues): 8 | 16 | 32 {
  return Number(optEnumOr(options, OPTION_WORD_SIZE, WIDTH_VALUES, "8")) as 8 | 16 | 32;
}

/**
 * `fallback` is the tool's own declared default, and callers that have a tool must pass it.
 *
 * It was a hardcoded `"big"`, which disagreed with `fletcher32`'s declared `"little"` -- invisible in
 * the app, because `createSpec` writes the declared value every time, and wrong for any spec that
 * arrives without the option at all. There is one source for the default now and it is the metadata.
 */
export function readByteOrder(
  options: OptionValues,
  fallback: ByteOrderValue = "big",
): ByteOrderValue {
  return optEnumOr(options, OPTION_BYTE_ORDER, BYTE_ORDER_VALUES, fallback);
}

/** The byte order a tool defaults to, from its own `defaults` map. */
export function declaredByteOrder(
  defaults: Readonly<Record<string, string>> | undefined,
): ByteOrderValue {
  const declared = defaults?.[OPTION_BYTE_ORDER];
  return declared === "little" ? "little" : "big";
}

export function readResult(options: OptionValues): ResultValue {
  return optEnumOr(options, OPTION_RESULT, RESULT_VALUES, "complement");
}

export function readBccMode(options: OptionValues): BccModeValue {
  return optEnumOr(options, OPTION_BCC_MODE, BCC_MODE_VALUES, "xor");
}

/** True once the input is grouped into multi-byte words, which is when byte order starts to matter. */
export function usesWords(options: OptionValues): boolean {
  return readWordSize(options) > 8;
}

export function withOption(options: OptionValues, id: string, value: string): OptionValues {
  return setOption(options, id, value);
}

/** `0x` plus the full width in hex — the way a protocol document quotes one of these. */
export function formatValue(value: number, width: number): string {
  return `0x${value
    .toString(16)
    .toUpperCase()
    .padStart(width / 4, "0")}`;
}
