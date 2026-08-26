/**
 * CBOR, RFC 8949. The one member of the encoding family no library here provides.
 *
 * Written rather than taken from npm for the reason recorded in WHY-NOT-A-LIBRARY.md: every
 * candidate either targets Node streams, ships a WASM blob (which the desktop CSP forbids), or
 * pulls in a schema layer this app has no use for. What is needed is small: read the RFC's five
 * argument encodings, dispatch on eight major types, and write the preferred serialisation back.
 *
 * Three things to preserve.
 *
 * **The vector table is the specification here.** RFC 8949 Appendix A gives around eighty
 * input/output pairs, and `tests/algos-cbor.test.ts` walks them all. They are what catch the parts
 * of CBOR that look optional and are not: a half-precision float, an indefinite-length string built
 * from chunks, the difference between `f97e00` and `fa7fc00000` for NaN. Do not thin that list.
 *
 * **Encoding is deterministic and decoding is permissive.** RFC 8949 section 4.2 asks for the
 * shortest argument that fits, definite lengths, and the shortest float that round-trips; this writer
 * always does all three, so the same value always produces the same bytes and two encodings can be
 * compared byte for byte. The reader accepts everything the RFC permits -- non-shortest arguments,
 * indefinite lengths, tags it does not understand -- because it is reading someone else's bytes and
 * refusing them would be answering a question the user did not ask.
 *
 * **Every failure is a message, not an exception.** `decodeCbor` throws `CborError` with an offset,
 * because a tool that says "unexpected break at byte 14" is usable and one that says "invalid CBOR"
 * is not.
 */

/** A decoded CBOR item. Maps come back as entry lists, since CBOR keys are not limited to strings. */
export type CborValue =
  | null
  | undefined
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | CborValue[]
  | CborMap
  | CborTagged;

/**
 * A map, as ordered entries rather than an object.
 *
 * CBOR permits any item as a key -- integers are common in constrained protocols, and COSE uses
 * nothing else. Decoding into a JS object would silently stringify those keys and lose the ordering
 * that deterministic encoding depends on.
 */
export interface CborMap {
  readonly cborMap: readonly [CborValue, CborValue][];
}

export interface CborTagged {
  readonly tag: number | bigint;
  readonly value: CborValue;
}

export class CborError extends Error {
  constructor(
    message: string,
    /** Byte offset the reader had reached. Included in the message the tool shows. */
    readonly offset: number,
  ) {
    super(`${message} (at byte ${offset})`);
    this.name = "CborError";
  }
}

export const isCborMap = (value: CborValue): value is CborMap =>
  typeof value === "object" && value !== null && "cborMap" in value;

export const isCborTagged = (value: CborValue): value is CborTagged =>
  typeof value === "object" && value !== null && "tag" in value && "value" in value;

/** Nesting cap. Deep CBOR is a stack-exhaustion vector, and no legitimate document is near this. */
const MAX_DEPTH = 128;

// ── writing ─────────────────────────────────────────────────────────────────

class Writer {
  private parts: number[] = [];

  byte(value: number): void {
    this.parts.push(value & 0xff);
  }

  bytes(values: Uint8Array): void {
    for (const value of values) this.parts.push(value);
  }

  /**
   * A major type and its argument, in the shortest form that fits.
   *
   * This single function is most of what "deterministic encoding" means in RFC 8949 section 4.2.1:
   * 23 is one byte, 24 is two, and an encoder that always used eight would be valid CBOR that never
   * matches anyone else's bytes.
   */
  head(major: number, argument: number | bigint): void {
    const value = typeof argument === "bigint" ? argument : BigInt(argument);
    const type = major << 5;
    if (value < 24n) this.byte(type | Number(value));
    else if (value < 0x100n) {
      this.byte(type | 24);
      this.byte(Number(value));
    } else if (value < 0x10000n) {
      this.byte(type | 25);
      this.uint(value, 2);
    } else if (value < 0x100000000n) {
      this.byte(type | 26);
      this.uint(value, 4);
    } else if (value < 0x10000000000000000n) {
      this.byte(type | 27);
      this.uint(value, 8);
    } else {
      throw new CborError("Integer is too large for CBOR (over 64 bits)", this.parts.length);
    }
  }

  private uint(value: bigint, width: number): void {
    for (let shift = (width - 1) * 8; shift >= 0; shift -= 8) {
      this.byte(Number((value >> BigInt(shift)) & 0xffn));
    }
  }

  finish(): Uint8Array {
    return new Uint8Array(this.parts);
  }
}

/**
 * The shortest float encoding that round-trips exactly: half, single, or double.
 *
 * Required by preferred serialisation, and not optional in practice either -- half precision is what
 * the RFC's own examples use for 1.5 and 65504.0, so an encoder that always wrote doubles would
 * disagree with the specification's vector table on its first float.
 */
function writeFloat(writer: Writer, value: number): void {
  const buffer = new DataView(new ArrayBuffer(8));

  const half = toHalf(value);
  if (half !== undefined) {
    writer.byte(0xe0 | 25);
    buffer.setUint16(0, half);
    writer.byte(buffer.getUint8(0));
    writer.byte(buffer.getUint8(1));
    return;
  }

  buffer.setFloat32(0, value);
  if (buffer.getFloat32(0) === value || Number.isNaN(value)) {
    writer.byte(0xe0 | 26);
    for (let i = 0; i < 4; i++) writer.byte(buffer.getUint8(i));
    return;
  }

  buffer.setFloat64(0, value);
  writer.byte(0xe0 | 27);
  for (let i = 0; i < 8; i++) writer.byte(buffer.getUint8(i));
}

/**
 * `value` as IEEE 754 binary16, or undefined when that would lose precision.
 *
 * Done by hand because JS has no Float16Array in the versions this targets. NaN is deliberately not
 * routed here: the RFC's vector for NaN is `f97e00`, but a NaN payload does not survive a
 * round-trip comparison, so it is handled as the special case it is.
 */
function toHalf(value: number): number | undefined {
  if (Number.isNaN(value)) return 0x7e00;
  if (value === Infinity) return 0x7c00;
  if (value === -Infinity) return 0xfc00;
  if (value === 0) return Object.is(value, -0) ? 0x8000 : 0x0000;

  const buffer = new DataView(new ArrayBuffer(4));
  buffer.setFloat32(0, value);
  if (buffer.getFloat32(0) !== value) return undefined;

  const bits = buffer.getUint32(0);
  const sign = (bits >>> 16) & 0x8000;
  const exponent = (bits >>> 23) & 0xff;
  const mantissa = bits & 0x7fffff;

  // Normal range for binary16 is exponent -14..15 after unbiasing binary32's 127.
  if (exponent >= 113 && exponent <= 142) {
    if (mantissa & 0x1fff) return undefined; // needs more mantissa bits than half has
    return sign | ((exponent - 112) << 10) | (mantissa >>> 13);
  }
  // Subnormal half: representable only if the value is an exact multiple of 2^-24.
  if (exponent >= 103 && exponent < 113) {
    if (mantissa & 0x1fff) return undefined;
    const shift = 126 - exponent;
    const full = mantissa | 0x800000;
    if (full & ((1 << shift) - 1)) return undefined;
    return sign | (full >>> shift);
  }
  return undefined;
}

/** Encodes one item in RFC 8949's preferred serialisation. */
export function encodeCbor(value: CborValue): Uint8Array {
  const writer = new Writer();
  write(writer, value, 0);
  return writer.finish();
}

function write(writer: Writer, value: CborValue, depth: number): void {
  if (depth > MAX_DEPTH) throw new CborError("Nesting is too deep to encode", 0);

  if (value === null) return writer.byte(0xf6);
  if (value === undefined) return writer.byte(0xf7);
  if (value === true) return writer.byte(0xf5);
  if (value === false) return writer.byte(0xf4);

  if (typeof value === "number") {
    /**
     * `isSafeInteger`, not `isInteger`, and the difference is a bug this caught.
     *
     * `Number.isInteger(1e300)` is true -- it is a double with nothing after the point -- so an
     * integer test alone sent 1e300 and FLT_MAX down the integer path, where they overflow the
     * 64-bit argument CBOR allows and threw. Anything outside the safe range is a value only a float
     * can hold exactly, which makes the float encoding the preferred one for it as well as the only
     * possible one. Pass a `bigint` for an integer beyond 2^53.
     */
    if (Number.isSafeInteger(value) && !Object.is(value, -0)) {
      return value >= 0 ? writer.head(0, value) : writer.head(1, -value - 1);
    }
    return writeFloat(writer, value);
  }

  if (typeof value === "bigint") {
    return value >= 0n ? writer.head(0, value) : writer.head(1, -value - 1n);
  }

  if (typeof value === "string") {
    const utf8 = new TextEncoder().encode(value);
    writer.head(3, utf8.length);
    return writer.bytes(utf8);
  }

  if (value instanceof Uint8Array) {
    writer.head(2, value.length);
    return writer.bytes(value);
  }

  if (Array.isArray(value)) {
    writer.head(4, value.length);
    for (const item of value) write(writer, item, depth + 1);
    return;
  }

  if (isCborTagged(value)) {
    writer.head(6, value.tag);
    return write(writer, value.value, depth + 1);
  }

  if (isCborMap(value)) {
    writer.head(5, value.cborMap.length);
    for (const [key, item] of value.cborMap) {
      write(writer, key, depth + 1);
      write(writer, item, depth + 1);
    }
    return;
  }

  throw new CborError(`Cannot encode a ${typeof value} as CBOR`, 0);
}

// ── reading ─────────────────────────────────────────────────────────────────

class Reader {
  offset = 0;

  constructor(private readonly data: Uint8Array) {}

  get done(): boolean {
    return this.offset >= this.data.length;
  }

  byte(): number {
    if (this.done) throw new CborError("Input ended in the middle of an item", this.offset);
    return this.data[this.offset++]!;
  }

  take(length: number): Uint8Array {
    if (this.offset + length > this.data.length) {
      throw new CborError(
        `Item claims ${length} bytes and only ${this.data.length - this.offset} remain`,
        this.offset,
      );
    }
    const slice = this.data.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  view(length: number): DataView {
    const slice = this.take(length);
    return new DataView(slice.buffer, slice.byteOffset, slice.byteLength);
  }
}

/** Sentinel for the 0xFF break byte, which is a structural marker rather than a value. */
const BREAK = Symbol("cbor-break");
/** Sentinel for an indefinite-length argument. */
const INDEFINITE = Symbol("cbor-indefinite");

function readArgument(reader: Reader, additional: number): bigint | typeof INDEFINITE {
  if (additional < 24) return BigInt(additional);
  switch (additional) {
    case 24:
      return BigInt(reader.byte());
    case 25:
      return BigInt(reader.view(2).getUint16(0));
    case 26:
      return BigInt(reader.view(4).getUint32(0));
    case 27:
      return reader.view(8).getBigUint64(0);
    case 31:
      return INDEFINITE;
    default:
      throw new CborError(
        `Reserved additional information ${additional} (28, 29 and 30 are not assigned)`,
        reader.offset - 1,
      );
  }
}

/** A bigint back to a number when it fits exactly, so ordinary integers stay ordinary. */
const narrow = (value: bigint): number | bigint =>
  value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER)
    ? Number(value)
    : value;

function fromHalf(bits: number): number {
  const sign = bits & 0x8000 ? -1 : 1;
  const exponent = (bits >> 10) & 0x1f;
  const mantissa = bits & 0x3ff;
  if (exponent === 0) return sign * mantissa * 2 ** -24;
  if (exponent === 31) return mantissa === 0 ? sign * Infinity : NaN;
  return sign * (mantissa + 1024) * 2 ** (exponent - 25);
}

function readItem(reader: Reader, depth: number): CborValue | typeof BREAK {
  if (depth > MAX_DEPTH) {
    throw new CborError(`Nesting deeper than ${MAX_DEPTH} items`, reader.offset);
  }

  const initial = reader.byte();
  const major = initial >> 5;
  const additional = initial & 0x1f;

  if (initial === 0xff) return BREAK;

  switch (major) {
    case 0: {
      const argument = readArgument(reader, additional);
      if (argument === INDEFINITE) {
        throw new CborError("An integer cannot have an indefinite length", reader.offset);
      }
      return narrow(argument);
    }
    case 1: {
      const argument = readArgument(reader, additional);
      if (argument === INDEFINITE) {
        throw new CborError("An integer cannot have an indefinite length", reader.offset);
      }
      return narrow(-1n - argument);
    }
    case 2:
    case 3: {
      const argument = readArgument(reader, additional);
      if (argument === INDEFINITE) return readChunked(reader, major, depth);
      const bytes = reader.take(Number(argument));
      // A copy, not the subarray: the slice aliases the caller's buffer, and a decoded value that
      // changes when the input is reused is a memorably confusing bug.
      return major === 2
        ? new Uint8Array(bytes)
        : new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    }
    case 4: {
      const argument = readArgument(reader, additional);
      const items: CborValue[] = [];
      if (argument === INDEFINITE) {
        for (;;) {
          const item = readItem(reader, depth + 1);
          if (item === BREAK) break;
          items.push(item);
        }
        return items;
      }
      for (let i = 0n; i < argument; i++) {
        const item = readItem(reader, depth + 1);
        if (item === BREAK)
          throw new CborError("Unexpected break inside an array", reader.offset);
        items.push(item);
      }
      return items;
    }
    case 5: {
      const argument = readArgument(reader, additional);
      const entries: [CborValue, CborValue][] = [];
      const readPair = (): boolean => {
        const key = readItem(reader, depth + 1);
        if (key === BREAK) return false;
        const value = readItem(reader, depth + 1);
        if (value === BREAK) {
          throw new CborError("Map ended after a key with no value", reader.offset);
        }
        entries.push([key, value]);
        return true;
      };
      if (argument === INDEFINITE) {
        while (readPair());
        return { cborMap: entries };
      }
      for (let i = 0n; i < argument; i++) {
        if (!readPair()) throw new CborError("Unexpected break inside a map", reader.offset);
      }
      return { cborMap: entries };
    }
    case 6: {
      const argument = readArgument(reader, additional);
      if (argument === INDEFINITE) {
        throw new CborError("A tag cannot have an indefinite length", reader.offset);
      }
      const value = readItem(reader, depth + 1);
      if (value === BREAK) throw new CborError("Tag has no content", reader.offset);
      return { tag: narrow(argument), value };
    }
    default: {
      switch (additional) {
        case 20:
          return false;
        case 21:
          return true;
        case 22:
          return null;
        case 23:
          return undefined;
        case 24: {
          const simple = reader.byte();
          if (simple < 32) {
            throw new CborError(
              `Simple value ${simple} must use the one-byte form`,
              reader.offset - 1,
            );
          }
          return { tag: -1, value: simple };
        }
        case 25:
          return fromHalf(reader.view(2).getUint16(0));
        case 26:
          return reader.view(4).getFloat32(0);
        case 27:
          return reader.view(8).getFloat64(0);
        case 31:
          return BREAK;
        default:
          // Simple values 0..19 have no assigned meaning; reported rather than invented.
          return { tag: -1, value: additional };
      }
    }
  }
}

/**
 * An indefinite-length byte or text string: chunks of the same major type until a break.
 *
 * The RFC requires the chunks to share the outer type, and enforcing that is what turns a
 * malformed stream into a message instead of a string with binary spliced into it.
 */
function readChunked(reader: Reader, major: number, depth: number): Uint8Array | string {
  const chunks: Uint8Array[] = [];
  for (;;) {
    const start = reader.offset;
    const item = readItem(reader, depth + 1);
    if (item === BREAK) break;
    if (major === 2 && item instanceof Uint8Array) {
      chunks.push(item);
      continue;
    }
    if (major === 3 && typeof item === "string") {
      chunks.push(new TextEncoder().encode(item));
      continue;
    }
    throw new CborError(
      `Indefinite-length ${major === 2 ? "byte" : "text"} string contains a chunk of another type`,
      start,
    );
  }
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.length;
  }
  return major === 2 ? joined : new TextDecoder("utf-8", { fatal: false }).decode(joined);
}

export interface DecodeCborResult {
  value: CborValue;
  /** Bytes after the top-level item. Non-zero is usually a paste that picked up something extra. */
  trailing: number;
}

/**
 * Decodes one top-level item and reports what was left over.
 *
 * Trailing bytes are returned rather than thrown, because CBOR sequences (RFC 8742) are a real
 * format and a diagnostic tool should show the first item plus a note rather than refuse.
 */
export function decodeCbor(bytes: Uint8Array): DecodeCborResult {
  const reader = new Reader(bytes);
  const value = readItem(reader, 0);
  if (value === BREAK) throw new CborError("Input begins with a break byte", 0);
  return { value, trailing: bytes.length - reader.offset };
}
