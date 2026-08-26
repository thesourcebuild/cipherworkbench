/**
 * Option ids, the enumerations behind them and the readers that narrow them.
 *
 * The eager half of the family: no `@ocs/algos` import, so listing three tools in the sidebar costs
 * nothing but the strings. Every reader has a fallback, and every fallback is the value the tool's
 * own `defaults` seeds -- a test asserts the two agree, because a form showing one value while the
 * resolver uses another is this repo's most-repeated defect.
 */
import type { OptionValue, OptionValues } from "@ocs/contracts/options";
import { optBool, optEnumOr, optNumber, setOption } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;

export const OPTION_DIRECTION = "direction";
export const OPTION_PARITY = "parity";
export const OPTION_SCOPE = "scope";
export const OPTION_DATA_BITS = "dataBits";
export const OPTION_PLACEMENT = "placement";
export const OPTION_STOP_BITS = "stopBits";
export const OPTION_BIT_ORDER = "bitOrder";
export const OPTION_INVERTED = "inverted";
export const OPTION_BAUD = "baud";
export const OPTION_SPACED = "spaced";
export const OPTION_HAMMING_CODE = "hammingCode";
export const OPTION_RS_PROFILE = "rsProfile";
export const OPTION_RS_ECC = "rsEcc";
export const OPTION_BCH_PROFILE = "bchProfile";

/**
 * Apply or check, encode or decode -- one axis under two sets of words.
 *
 * The words differ because the operations do. "Apply" a parity bit and you get the data back with a
 * bit added; "encode" a frame and you get something that is not data at all but a picture of a wire.
 * A single pair of labels covering both would have to be vague about one of them.
 */
export const DIRECTIONS = ["apply", "check"] as const;
export type Direction = (typeof DIRECTIONS)[number];

/**
 * The four parity modes a UART offers, and two of them detect nothing.
 *
 * Mark and space are constants -- always 1, always 0 -- so they carry no information about the data.
 * They are here because real equipment uses that slot as a ninth data bit or an address/data flag,
 * and a tool that could not reproduce a mark-parity frame would be unable to talk to it. `P002` says
 * what they are rather than the catalogue pretending they are parity schemes.
 */
export const PARITY_MODES = ["even", "odd", "mark", "space"] as const;
export type ParityModeId = (typeof PARITY_MODES)[number];

/** As above, plus the case a UART frame has and a parity bit cannot: no parity bit at all. */
export const FRAME_PARITY_MODES = ["none", ...PARITY_MODES] as const;
export type FrameParityId = (typeof FRAME_PARITY_MODES)[number];

/** One bit per unit, or one bit for the lot. */
export const SCOPES = ["byte", "message"] as const;
export type Scope = (typeof SCOPES)[number];

/**
 * Where the computed bit goes, which is a real question rather than a rendering preference.
 *
 * `high-bit` is what a 7-bit-plus-parity byte actually looks like in a register, and it is the form
 * you compare against a capture. `packed` is the bit string, one bit per input byte, which is what
 * you want when the parity bits travel separately -- a parity plane, or a column of a memory array.
 * `byte-each` spends eight bits saying one, and is the only one of the three you can read off the
 * screen without counting.
 */
export const PLACEMENTS = ["high-bit", "packed", "byte-each"] as const;
export type Placement = (typeof PLACEMENTS)[number];

export const STOP_BITS = ["1", "1.5", "2"] as const;
export type StopBitsId = (typeof STOP_BITS)[number];

export const BIT_ORDERS = ["lsb", "msb"] as const;
export type BitOrderId = (typeof BIT_ORDERS)[number];

/** Hamming(7,4) and its extended form. The number of data bits is four either way. */
/**
 * The Hamming sizes offered, as `<codeword>-<data>` bits.
 *
 * Two widths, each with and without the extended overall parity bit. There is no (31,26): 26 data
 * bits per codeword is past the point where anyone reads the result, and nothing standardises it.
 */
export const HAMMING_CODES = ["7-4", "8-4", "15-11", "16-11"] as const;
export type HammingCodeId = (typeof HAMMING_CODES)[number];

/** `availableOn` tags, so a control only appears where it means something. */
export const TAG_APPLY = "apply";
export const TAG_CHECK = "check";
/** Set while the scope is per-byte, which is the only scope with a data width or a placement. */
export const TAG_PER_BYTE = "per-byte";
/** Set while a frame actually has a parity bit, which is what reveals the parity mode's consequences. */
export const TAG_FRAMED = "framed";

export function readDirection(options: OptionValues): Direction {
  return optEnumOr(options, OPTION_DIRECTION, DIRECTIONS, "apply");
}

export function readParityMode(options: OptionValues): ParityModeId {
  return optEnumOr(options, OPTION_PARITY, PARITY_MODES, "even");
}

export function readFrameParity(options: OptionValues): FrameParityId {
  return optEnumOr(options, OPTION_PARITY, FRAME_PARITY_MODES, "none");
}

export function readScope(options: OptionValues): Scope {
  return optEnumOr(options, OPTION_SCOPE, SCOPES, "byte");
}

export function readPlacement(options: OptionValues): Placement {
  return optEnumOr(options, OPTION_PLACEMENT, PLACEMENTS, "byte-each");
}

export function readHammingCode(options: OptionValues): HammingCodeId {
  return optEnumOr(options, OPTION_HAMMING_CODE, HAMMING_CODES, "8-4");
}

export function readBitOrder(options: OptionValues): BitOrderId {
  return optEnumOr(options, OPTION_BIT_ORDER, BIT_ORDERS, "lsb");
}

/**
 * 1, 1.5 or 2, as a number.
 *
 * An `enum` rather than a number option because 1.5 is a legal value and 1.7 is not, and a numeric
 * field would have to refuse the values in between with a message instead of not offering them. Note
 * the parse: an `enum` stores a *string*, so reading this with `optNumber` would return undefined and
 * silently fall back -- the mistake that left AEGIS's tag-length control inert with a green suite.
 */
export function readStopBits(options: OptionValues): 1 | 1.5 | 2 {
  const id = optEnumOr(options, OPTION_STOP_BITS, STOP_BITS, "1");
  return id === "1.5" ? 1.5 : id === "2" ? 2 : 1;
}

/** 5 to 9. Nine exists for multidrop, where the ninth bit flags an address rather than data. */
export function readDataBits(options: OptionValues, fallback: number, max: number): number {
  return Math.min(Math.max(optNumber(options, OPTION_DATA_BITS) ?? fallback, 5), max);
}

/**
 * The line rate, for the one figure a frame diagram cannot show: how long it takes.
 *
 * Clamped rather than validated, on the same reasoning as every other count in this repo: 0 baud is
 * a slider mishap and not a request, and the upper bound is where a UART stops being a UART.
 */
export function readBaud(options: OptionValues): number {
  return Math.min(Math.max(optNumber(options, OPTION_BAUD) ?? 9600, 50), 20_000_000);
}

export function readSpaced(options: OptionValues): boolean {
  return optBool(options, OPTION_SPACED);
}

export function readInverted(options: OptionValues): boolean {
  return optBool(options, OPTION_INVERTED);
}

export function withDirection(options: OptionValues, direction: Direction): OptionValues {
  return setOption(options, OPTION_DIRECTION, direction);
}

/** Re-exported so the metadata's `defaults` can be typed without importing the options module. */
export type ParityDefaults = Readonly<Record<string, OptionValue>>;

/** Which Reed-Solomon field, by the standard that chose it. */
export const RS_PROFILE_IDS = ["qr", "datamatrix"] as const;
export type RsProfileId = (typeof RS_PROFILE_IDS)[number];

export function readRsProfile(options: OptionValues): RsProfileId {
  return optEnumOr(options, OPTION_RS_PROFILE, RS_PROFILE_IDS, "qr");
}

/** How many parity symbols to append. Half of this is the number of byte errors correctable. */
export function readRsEcc(options: OptionValues): number {
  const raw = optNumber(options, OPTION_RS_ECC);
  if (raw === undefined || !Number.isInteger(raw) || raw < 1) return DEFAULT_RS_ECC;
  return Math.min(raw, 254);
}

export const DEFAULT_RS_ECC = 10;

/** Which BCH code, by the field of a QR symbol it protects. */
export const BCH_PROFILE_IDS = ["qr-format", "qr-version"] as const;
export type BchProfileId = (typeof BCH_PROFILE_IDS)[number];

export function readBchProfile(options: OptionValues): BchProfileId {
  return optEnumOr(options, OPTION_BCH_PROFILE, BCH_PROFILE_IDS, "qr-format");
}
