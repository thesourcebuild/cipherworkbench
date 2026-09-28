/**
 * Zod-free constants and accessors for the check digit family.
 */
import type { OptionValues } from "@ocs/contracts/options";
import { setOption } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;

export function withOption(options: OptionValues, id: string, value: string): OptionValues {
  return setOption(options, id, value);
}
