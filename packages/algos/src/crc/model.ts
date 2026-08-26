/**
 * A CRC as the seven parameters that fully define it.
 *
 * This is Greg Cook's parametrised model from the RevEng CRC catalogue, and using it
 * is what turns "implement 60 CRC variants" into "implement one CRC and transcribe a
 * table". Every named CRC in the wild — MODBUS, CRC-32C, the one in gzip, the one in
 * a Bluetooth packet — is this same shift-and-xor loop with different constants.
 *
 * `check` is the load-bearing field. The catalogue publishes, for every entry, the
 * CRC of the nine ASCII bytes "123456789". So each entry carries its own known-answer
 * test: a mistyped polynomial or a flipped reflection flag cannot produce the right
 * check value by accident, which means a transcription error surfaces as a test
 * failure rather than as a confidently wrong answer. `tests/crc.test.ts` asserts it
 * for every entry, and that assertion is the reason it is safe to add entries in bulk.
 */
export interface CrcModel {
  /** Canonical name from the RevEng catalogue, e.g. "CRC-32/ISO-HDLC". */
  name: string;
  /** Register width in bits, 3 to 82 -- every width the RevEng catalogue defines. See `assertSupported`. */
  width: number;
  /** Generator polynomial, top bit implicit. */
  poly: bigint;
  /** Initial register value. */
  init: bigint;
  /** Reflect each input byte before feeding it in. */
  refIn: boolean;
  /** Reflect the final register before the xor. */
  refOut: boolean;
  /** Xored into the final value. */
  xorOut: bigint;
  /** CRC of the ASCII bytes "123456789", as published. This entry's self-test. */
  check: bigint;
  /**
   * The value a correct message *plus its own CRC* produces, as published.
   *
   * The other half of how a CRC is used, and the half a calculator usually leaves out. A sender
   * appends the CRC; a receiver runs the CRC over message-and-CRC together and compares against
   * this, which saves recomputing and re-comparing the check field. For most models it is zero,
   * which is exactly why the ones where it is not -- CRC-32/ISO-HDLC's 0xdebb20e3, CRC-16/IBM-SDLC's
   * 0xf0b8 -- are worth having on screen rather than assumed.
   *
   * Optional for the same reason `check` effectively is: a model whose parameters someone typed into
   * the custom form has no *published* residue, and inventing one would put a number on screen with
   * nothing behind it.
   */
  residue?: bigint;
  /** Common alternative names, so search finds "CRC-32C" and "Castagnoli". */
  aliases?: readonly string[];
}

/** The nine bytes every catalogue `check` value is the CRC of. */
export const CHECK_INPUT: Uint8Array = new TextEncoder().encode("123456789");

export function mask(width: number): bigint {
  return (1n << BigInt(width)) - 1n;
}

/**
 * Reflects the low `width` bits of `value`.
 *
 * Bit-at-a-time rather than a lookup: this runs once per model at table-build time
 * and once per digest, never per byte, so its cost is irrelevant and its obviousness
 * is worth more.
 */
export function reflect(value: bigint, width: number): bigint {
  let out = 0n;
  let v = value;
  for (let i = 0; i < width; i++) {
    out = (out << 1n) | (v & 1n);
    v >>= 1n;
  }
  return out;
}

const REFLECT_8: Uint8Array = /* @__PURE__ */ (() => {
  const table = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    let b = i;
    let r = 0;
    for (let bit = 0; bit < 8; bit++) {
      r = (r << 1) | (b & 1);
      b >>= 1;
    }
    table[i] = r;
  }
  return table;
})();

/** Reflects one byte. Hot path — called per input byte when `refIn` is set. */
export function reflectByte(byte: number): number {
  return REFLECT_8[byte]!;
}

/**
 * Widths 3 to 82, which is every width the RevEng catalogue defines.
 *
 * Below 8 the byte-indexed table has nowhere to live -- an eight-bit index does not fit in a
 * five-bit register -- so those widths go through a bit-at-a-time engine instead. This used to
 * refuse them outright, on the reasoning that a formulation which silently mishandles them is worse
 * than no support at all. That reasoning was right about the danger and wrong about the conclusion:
 * the fifteen models at widths 3 to 7 are real (CRC-5/USB, CRC-7/MMC, CRC-6/DARC), the RevEng
 * catalogue publishes a check value for every one, and a separate engine handles them correctly
 * rather than approximately.
 */
export function assertSupported(model: CrcModel): void {
  if (!Number.isInteger(model.width) || model.width < 3 || model.width > 82) {
    throw new Error(
      `${model.name}: unsupported CRC width ${model.width}. This implementation covers 3 to 82 bits.`,
    );
  }
  if (model.poly > mask(model.width)) {
    throw new Error(`${model.name}: polynomial does not fit in ${model.width} bits.`);
  }
  if (model.init > mask(model.width)) {
    throw new Error(`${model.name}: init value does not fit in ${model.width} bits.`);
  }
  if (model.xorOut > mask(model.width)) {
    throw new Error(`${model.name}: xorOut does not fit in ${model.width} bits.`);
  }
}
