/**
 * Zod-free constants and accessors. Same rationale as `@ocs/contracts/pure`: the UI
 * reads and writes these without dragging schema construction into the bundle.
 */
import type { OptionValues } from "@ocs/contracts/options";
import { optBool, optString, setOption } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;

export const OPTION_MODEL = "model";
export const OPTION_POLY = "poly";
export const OPTION_INIT = "init";
export const OPTION_XOR_OUT = "xorOut";
export const OPTION_REF_IN = "refIn";
export const OPTION_REF_OUT = "refOut";

/** The `model` value that switches on the hand-entered parameter fields. */
export const CUSTOM_MODEL = "custom";

/** `availableOn` tag the custom-parameter options carry. */
export const TAG_CUSTOM = "custom";

export function readModel(options: OptionValues, fallback: string): string {
  return optString(options, OPTION_MODEL) ?? fallback;
}

export function isCustom(options: OptionValues): boolean {
  return optString(options, OPTION_MODEL) === CUSTOM_MODEL;
}

export function readRefIn(options: OptionValues): boolean {
  return optBool(options, OPTION_REF_IN);
}

export function readRefOut(options: OptionValues): boolean {
  return optBool(options, OPTION_REF_OUT);
}

export function withModel(options: OptionValues, model: string): OptionValues {
  return setOption(options, OPTION_MODEL, model);
}

/**
 * Parses one of the hex parameter fields.
 *
 * Returns `undefined` for anything unusable rather than throwing or defaulting to
 * zero. A half-typed polynomial is the normal state of that field, and silently
 * treating `"0x04C11D"` as a complete value while the user is still typing would
 * show a confident, wrong CRC on every keystroke.
 */
export function readHexParam(options: OptionValues, id: string): bigint | undefined {
  const raw = optString(options, id);
  if (raw === undefined) return undefined;
  const cleaned = raw.trim().replace(/^0x/i, "").replace(/[\s_]/g, "");
  if (cleaned === "" || !/^[0-9a-fA-F]+$/.test(cleaned)) return undefined;
  return BigInt(`0x${cleaned}`);
}

/** Formats a parameter the way the catalogue writes it: `0x` plus the full width in hex. */
export function formatHexParam(value: bigint, width: number): string {
  return `0x${value
    .toString(16)
    .toUpperCase()
    .padStart(Math.ceil(width / 4), "0")}`;
}
