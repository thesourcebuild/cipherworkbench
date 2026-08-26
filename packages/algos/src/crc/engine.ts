import { assertSupported, mask, reflect, reflectByte, type CrcModel } from "./model";

/**
 * Table-driven, incremental CRC.
 *
 * Two implementations behind one interface, split on width:
 *
 *  - width ≤ 32 uses `number` and `Uint32Array`, which the JIT keeps in machine
 *    registers. This covers every CRC anyone hashes a file with, and -- via
 *    `registerLayout` -- the widths below a byte as well.
 *  - width 33 to 82 uses `BigInt`, because a 64-bit register cannot survive in a
 *    double. Slower, and correct, which is the right way round for CRC-64.
 *
 * Both build their table from the same msb-first formulation and apply reflection at
 * the same two points, and `tests/crc.test.ts` checks both against the bit-at-a-time
 * reference in `./reference.ts` over random inputs for every model. A table-driven
 * CRC's characteristic bugs — table built in the wrong bit order, reflection applied
 * at the wrong end — produce output that looks like a CRC and matches nothing, so
 * that cross-check is not optional.
 */
export interface CrcEngine {
  readonly model: CrcModel;
  update(chunk: Uint8Array): void;
  /** The current value. Does not finalise — callers may keep updating afterwards. */
  digest(): bigint;
  /** Big-endian bytes, `ceil(width / 8)` of them. */
  digestBytes(): Uint8Array;
  reset(): void;
}

/**
 * How a model sits in a register, which is not always the model's own width.
 *
 * Below 8 bits a byte-indexed table looks impossible: the index is eight bits and the register is
 * fewer, so there is nothing to look up. The way out is older than any of this and is what embedded
 * CRC-7 and CRC-5 code has always done -- **left-justify** the polynomial and the initial value into
 * a byte, run the ordinary byte-wise algorithm, and shift the register back down at the end. A 5-bit
 * CRC is then computed as an 8-bit one whose polynomial happens to end in three zero bits, and the
 * table is a genuine 256-entry table of that 8-bit polynomial rather than an approximation of
 * anything.
 *
 * This replaced a bit-at-a-time engine and a `crcLookupTable` that threw. The reasoning for those
 * was that a byte table cannot exist under 8 bits, which is true only of an *unjustified* one -- and
 * it cost the five narrow CRC tools their Table panel for no reason.
 *
 * `justify` is zero at every width from 8 up, so nothing downstream needs to know which case it is
 * in. That is the point: one table builder, one byte-wise loop, and the sub-byte widths are not a
 * separate path through either.
 */
interface RegisterLayout {
  /** Register width in bits: the model's own, or 8 when the model is narrower. */
  regWidth: number;
  /** The polynomial and initial value, left-justified into the register. */
  poly: bigint;
  init: bigint;
  /** Bits to shift the finished register right by to recover the model's value. */
  justify: bigint;
}

export function registerLayout(model: CrcModel): RegisterLayout {
  if (model.width >= 8) {
    return { regWidth: model.width, poly: model.poly, init: model.init, justify: 0n };
  }
  const justify = BigInt(8 - model.width);
  return {
    regWidth: 8,
    poly: (model.poly << justify) & mask(8),
    init: (model.init << justify) & mask(8),
    justify,
  };
}

/**
 * Builds the 256-entry table for the msb-first algorithm.
 *
 * Kept in BigInt regardless of width — this runs once per model, and sharing one
 * obviously-correct builder between the two engines removes the possibility of the
 * fast path and the slow path disagreeing about the table itself.
 */
function buildTable(model: CrcModel): bigint[] {
  const { regWidth, poly } = registerLayout(model);
  const width = BigInt(regWidth);
  const m = mask(regWidth);
  const topBit = 1n << (width - 1n);
  const shift = width - 8n;

  const table: bigint[] = new Array<bigint>(256);
  for (let i = 0; i < 256; i++) {
    let crc = BigInt(i) << shift;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc & topBit) !== 0n ? ((crc << 1n) ^ poly) & m : (crc << 1n) & m;
    }
    table[i] = crc;
  }
  return table;
}

/** Which bit order a displayed table is written for. */
export type CrcTableOrientation = "normal" | "reflected";

/**
 * The 256-entry lookup table, for showing a reader what the algorithm is made of.
 *
 * The `normal` table is byte-for-byte the one the engines run on -- the same `buildTable`, not a
 * second copy of the formulation -- so what the app displays cannot drift from what it computes.
 *
 * The `reflected` table is what an lsb-first implementation uses, and it is *derived* rather than
 * built again: `T_ref[i] === reflect(T_norm[reflectByte(i)])` for all 256 entries, which
 * `tests/crc.test.ts` asserts across every catalogued model. Deriving it matters more than the few
 * lines it saves -- a hand-built second table is exactly the kind of thing that comes out
 * self-consistent and disagrees with the engine it is supposed to describe.
 *
 * Both orientations are offered because both appear in real source: zlib ships a reflected CRC-32
 * table, the Ethernet and MPEG references ship normal ones, and someone copying a table out of here
 * needs the one their loop expects.
 */
export function crcLookupTable(
  model: CrcModel,
  orientation: CrcTableOrientation = "normal",
): readonly bigint[] {
  assertSupported(model);
  /**
   * Every supported width, 3 to 82.
   *
   * Below 8 the entries are byte-wide values over the *left-justified* polynomial -- see
   * `registerLayout` -- so a consumer has to shift the finished register down by `8 - width`. That
   * is a shift, not an approximation: it is the table the engine below runs on, and it reproduces
   * every one of those models' published check values. The panel says so on the table itself,
   * because someone copying the grid out and skipping the shift gets a wrong answer with no error.
   */
  const { regWidth } = registerLayout(model);
  const normal = buildTable(model);
  if (orientation === "normal") return normal;
  // Reflected at the *register* width, which is the width the tabulated polynomial lives at.
  return normal.map((_, i) => reflect(normal[reflectByte(i)]!, regWidth));
}

function toBytes(value: bigint, width: number): Uint8Array {
  const byteLength = Math.ceil(width / 8);
  const out = new Uint8Array(byteLength);
  let v = value;
  for (let i = byteLength - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Widths 3 to 32.
 *
 * Everything in here is in terms of the *register*, not the model: `registerLayout` widens anything
 * under 8 bits to a byte and left-justifies its constants, so this loop is the same loop for
 * CRC-5/USB and CRC-32. Only `digest` has to remember the difference, and only to shift the padding
 * back off.
 */
class NarrowCrcEngine implements CrcEngine {
  private readonly table: Uint32Array;
  private readonly mask: number;
  private readonly shift: number;
  private readonly justify: number;
  /** The justified init, kept so `reset` does not recompute the layout. */
  private readonly initial: number;
  private crc: number;

  constructor(readonly model: CrcModel) {
    const layout = registerLayout(model);
    this.table = Uint32Array.from(buildTable(model), (v) => Number(v));
    // `2 ** width - 1` rather than `(1 << width) - 1`: at width 32 the shift
    // overflows into the sign bit and yields -1.
    this.mask = layout.regWidth === 32 ? 0xffffffff : 2 ** layout.regWidth - 1;
    this.shift = layout.regWidth - 8;
    this.justify = Number(layout.justify);
    this.initial = Number(layout.init);
    this.crc = this.initial;
  }

  update(chunk: Uint8Array): void {
    const { table, mask: m, shift } = this;
    const refIn = this.model.refIn;
    let crc = this.crc;

    for (const rawByte of chunk) {
      const byte = refIn ? reflectByte(rawByte) : rawByte;
      // `>>> 0` after the shift keeps a width-32 register unsigned; without it the
      // index goes negative the moment the top bit is set.
      const index = (((crc >>> shift) ^ byte) & 0xff) >>> 0;
      crc = (((crc << 8) >>> 0) ^ table[index]!) & m;
      // `& m` on a 32-bit mask can still leave a signed value; normalise.
      crc = crc >>> 0;
    }

    this.crc = crc;
  }

  digest(): bigint {
    // Out of the register first. For a sub-byte model the low `justify` bits are padding, and
    // reflecting or xoring before dropping them would fold padding into the answer.
    const raw = BigInt(this.crc >>> 0) >> BigInt(this.justify);
    const value = this.model.refOut ? reflect(raw, this.model.width) : raw;
    return (value ^ this.model.xorOut) & mask(this.model.width);
  }

  digestBytes(): Uint8Array {
    return toBytes(this.digest(), this.model.width);
  }

  reset(): void {
    this.crc = this.initial;
  }
}

class WideCrcEngine implements CrcEngine {
  private readonly table: readonly bigint[];
  private readonly mask: bigint;
  private readonly shift: bigint;
  private crc: bigint;

  constructor(readonly model: CrcModel) {
    this.table = buildTable(model);
    this.mask = mask(model.width);
    this.shift = BigInt(model.width - 8);
    this.crc = model.init;
  }

  update(chunk: Uint8Array): void {
    const { table, mask: m, shift } = this;
    const refIn = this.model.refIn;
    let crc = this.crc;

    for (const rawByte of chunk) {
      const byte = BigInt(refIn ? reflectByte(rawByte) : rawByte);
      const index = Number(((crc >> shift) ^ byte) & 0xffn);
      crc = ((crc << 8n) ^ table[index]!) & m;
    }

    this.crc = crc;
  }

  digest(): bigint {
    const value = this.model.refOut ? reflect(this.crc, this.model.width) : this.crc;
    return (value ^ this.model.xorOut) & this.mask;
  }

  digestBytes(): Uint8Array {
    return toBytes(this.digest(), this.model.width);
  }

  reset(): void {
    this.crc = this.model.init;
  }
}

export function createCrc(model: CrcModel): CrcEngine {
  assertSupported(model);
  // Two engines, split on what a double can hold. The widths under 8 go through the narrow one on a
  // left-justified register -- see `registerLayout` -- rather than through a third implementation.
  return model.width <= 32 ? new NarrowCrcEngine(model) : new WideCrcEngine(model);
}

/** One-shot convenience. The app always uses `createCrc` so it can stream. */
export function crc(model: CrcModel, data: Uint8Array): bigint {
  const engine = createCrc(model);
  engine.update(data);
  return engine.digest();
}

export function crcBytes(model: CrcModel, data: Uint8Array): Uint8Array {
  const engine = createCrc(model);
  engine.update(data);
  return engine.digestBytes();
}

/** Hex, zero-padded to the model's width. `CRC-32/ISO-HDLC` of "123456789" is "cbf43926". */
export function crcHex(model: CrcModel, data: Uint8Array): string {
  return crc(model, data)
    .toString(16)
    .padStart(Math.ceil(model.width / 4), "0");
}
