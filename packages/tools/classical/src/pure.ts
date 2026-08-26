import type { OptionValues } from "@ocs/contracts/options";
import { optEnumOr, optNumber, setOption } from "@ocs/contracts/pure";

/** Bumped only when a stored spec would no longer load. */
export const SPEC_VERSION = 1 as const;

export const OPTION_DIRECTION = "direction";
export const OPTION_SHIFT = "shift";
export const OPTION_LETTER_CASE = "letterCase";
export const OPTION_SHOW_ALL = "showAll";

export const DIRECTIONS = ["encrypt", "decrypt"] as const;
export type Direction = (typeof DIRECTIONS)[number];

export const LETTER_CASES = ["preserve", "upper", "lower"] as const;
export type LetterCase = (typeof LETTER_CASES)[number];

/**
 * Three, and it is the classical one.
 *
 * Caesar's own shift, per Suetonius, and what every worked example uses -- including the one in this
 * tool's samples. A tool that opened on 13 would be a ROT13 tool that could also do Caesar, which is
 * the wrong way round: ROT13 is reachable by typing 13, and it is a tag on this tool so searching for
 * it lands here.
 */
export const DEFAULT_SHIFT = 3;

/** `availableOn` tags, so a control only appears where it applies. */
export const TAG_ENCRYPT = "encrypt";
export const TAG_DECRYPT = "decrypt";

export function readDirection(options: OptionValues): Direction {
  return optEnumOr(options, OPTION_DIRECTION, DIRECTIONS, "encrypt");
}

export function readLetterCase(options: OptionValues): LetterCase {
  return optEnumOr(options, OPTION_LETTER_CASE, LETTER_CASES, "preserve");
}

/**
 * The shift as typed, clamped to the range the control offers.
 *
 * Clamped rather than validated, the treatment every other numeric option here gets: a value outside
 * 0..25 is a spinner mishap rather than a request, and a half-typed minus sign should not turn the
 * panel into an error. Reducing modulo 26 is a separate job and belongs to the algorithm -- see
 * `normaliseShift` -- because a *reduction* is arithmetic the cipher defines and a *clamp* is a
 * decision about a form control.
 */
export function readShift(options: OptionValues): number {
  const raw = optNumber(options, OPTION_SHIFT);
  if (raw === undefined || !Number.isFinite(raw)) return DEFAULT_SHIFT;
  return Math.min(Math.max(Math.trunc(raw), 0), 25);
}

export function withShift(options: OptionValues, shift: number): OptionValues {
  return setOption(options, OPTION_SHIFT, shift);
}

export function withDirection(options: OptionValues, direction: Direction): OptionValues {
  return setOption(options, OPTION_DIRECTION, direction);
}
