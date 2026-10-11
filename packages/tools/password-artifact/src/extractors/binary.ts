import type { ToolFileSource } from "@ocs/engine";

const HEX = "0123456789abcdef";
const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function checkedAdd(a: number, b: number, label = "offset"): number {
  if (
    !Number.isSafeInteger(a) ||
    !Number.isSafeInteger(b) ||
    a < 0 ||
    b < 0 ||
    a > Number.MAX_SAFE_INTEGER - b
  ) {
    throw new RangeError(`${label} overflows the safe integer range.`);
  }
  return a + b;
}

export function checkedMultiply(a: number, b: number, label = "length"): number {
  if (
    !Number.isSafeInteger(a) ||
    !Number.isSafeInteger(b) ||
    a < 0 ||
    b < 0 ||
    (a !== 0 && b > Math.floor(Number.MAX_SAFE_INTEGER / a))
  ) {
    throw new RangeError(`${label} overflows the safe integer range.`);
  }
  return a * b;
}

export function requireRange(
  size: number,
  offset: number,
  length: number,
  label: string,
): void {
  const end = checkedAdd(offset, length, `${label} range`);
  if (end > size)
    throw new Error(`${label} is truncated or points beyond the end of the file.`);
}

export async function readExact(
  source: ToolFileSource,
  offset: number,
  length: number,
  label: string,
): Promise<Uint8Array> {
  requireRange(source.metadata.size, offset, length, label);
  if (length > source.maxReadBytes) {
    throw new Error(
      `${label} requires a ${length}-byte read, exceeding the ${source.maxReadBytes}-byte bounded-read limit.`,
    );
  }
  const bytes = await source.read(offset, length);
  if (bytes.length !== length) throw new Error(`${label} returned a short read.`);
  return bytes;
}

export async function readChunked(
  source: ToolFileSource,
  offset: number,
  length: number,
  maximum: number,
  label: string,
): Promise<Uint8Array> {
  requireRange(source.metadata.size, offset, length, label);
  if (length > maximum) {
    throw new Error(
      `${label} is ${length} bytes; this extractor supports at most ${maximum} bytes.`,
    );
  }
  const output = new Uint8Array(length);
  let written = 0;
  while (written < length) {
    const count = Math.min(length - written, source.maxReadBytes);
    output.set(await readExact(source, checkedAdd(offset, written), count, label), written);
    written += count;
  }
  return output;
}

export function memoryFileSource(
  bytes: Uint8Array,
  name: string,
  maxReadBytes = Math.max(1, bytes.length),
): ToolFileSource {
  return {
    metadata: { name, size: bytes.length },
    maxReadBytes,
    async read(offset, length) {
      requireRange(bytes.length, offset, length, "Memory file read");
      return bytes.slice(offset, offset + length);
    },
  };
}

export function sourceName(source: ToolFileSource): string {
  const name = source.metadata.name;
  if (!name || /[\0\r\n]/.test(name))
    throw new Error("The source filename is empty or unsafe.");
  return name;
}

export function basename(name: string): string {
  return name.split(/[\\/]/).at(-1) || name;
}

/** Keep untrusted names in one John record without changing ordinary upstream output. */
export function johnName(name: string, label = "filename"): string {
  if (!name || /[\0\r\n]/.test(name)) throw new Error(`The ${label} is empty or unsafe.`);
  return name.replace(/:/g, " ");
}

export function decodeUtf8(bytes: Uint8Array, label: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8.`);
  }
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => checkedAdd(sum, chunk.length), 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let index = 0; index < a.length; index++) {
    if (a[index] !== b[index]) return false;
  }
  return true;
}

export function ascii(bytes: Uint8Array, label: string): string {
  for (const byte of bytes) {
    if (byte > 0x7f) throw new Error(`${label} is not ASCII.`);
  }
  return new TextDecoder("ascii").decode(bytes);
}

export function nulTerminatedAscii(bytes: Uint8Array, label: string): string {
  const nul = bytes.indexOf(0);
  if (nul < 0) throw new Error(`${label} is not NUL-terminated.`);
  for (let index = nul; index < bytes.length; index++) {
    if (bytes[index] !== 0)
      throw new Error(`${label} has non-zero bytes after its terminator.`);
  }
  return ascii(bytes.subarray(0, nul), label);
}

export function hex(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) output += HEX.charAt(byte >>> 4) + HEX.charAt(byte & 15);
  return output;
}

export function base64(bytes: Uint8Array): string {
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const a = bytes[index]!;
    const hasB = index + 1 < bytes.length;
    const hasC = index + 2 < bytes.length;
    const b = hasB ? bytes[index + 1]! : 0;
    const c = hasC ? bytes[index + 2]! : 0;
    output += BASE64[a >>> 2];
    output += BASE64[((a & 3) << 4) | (b >>> 4)];
    output += hasB ? BASE64[((b & 15) << 2) | (c >>> 6)] : "=";
    output += hasC ? BASE64[c & 63] : "=";
  }
  return output;
}

export function decodeBase64(value: string, label: string): Uint8Array {
  const clean = value.replace(/[\t\r\n ]/g, "");
  if (clean.length === 0 || clean.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
    throw new Error(`${label} is not canonical Base64.`);
  }
  const padding = clean.endsWith("==") ? 2 : clean.endsWith("=") ? 1 : 0;
  if (clean.slice(0, -padding || undefined).includes("=")) {
    throw new Error(`${label} has misplaced Base64 padding.`);
  }
  const output = new Uint8Array((clean.length / 4) * 3 - padding);
  let written = 0;
  for (let index = 0; index < clean.length; index += 4) {
    const values = [0, 1, 2, 3].map((delta) => {
      const character = clean[index + delta]!;
      return character === "=" ? 0 : BASE64.indexOf(character);
    });
    const packed = (values[0]! << 18) | (values[1]! << 12) | (values[2]! << 6) | values[3]!;
    if (written < output.length) output[written++] = packed >>> 16;
    if (written < output.length) output[written++] = packed >>> 8;
    if (written < output.length) output[written++] = packed;
  }
  if (base64(output) !== clean) throw new Error(`${label} is not canonical Base64.`);
  return output;
}

export function readUint16Le(bytes: Uint8Array, offset: number, label: string): number {
  requireRange(bytes.length, offset, 2, label);
  return bytes[offset]! | (bytes[offset + 1]! << 8);
}

export function readUint16Be(bytes: Uint8Array, offset: number, label: string): number {
  requireRange(bytes.length, offset, 2, label);
  return (bytes[offset]! << 8) | bytes[offset + 1]!;
}

export function readUint32Le(bytes: Uint8Array, offset: number, label: string): number {
  requireRange(bytes.length, offset, 4, label);
  return (
    bytes[offset]! +
    bytes[offset + 1]! * 0x100 +
    bytes[offset + 2]! * 0x10000 +
    bytes[offset + 3]! * 0x1000000
  );
}

export function readUint32Be(bytes: Uint8Array, offset: number, label: string): number {
  requireRange(bytes.length, offset, 4, label);
  return (
    bytes[offset]! * 0x1000000 +
    bytes[offset + 1]! * 0x10000 +
    bytes[offset + 2]! * 0x100 +
    bytes[offset + 3]!
  );
}

export function readUint64Le(bytes: Uint8Array, offset: number, label: string): number {
  const low = readUint32Le(bytes, offset, label);
  const high = readUint32Le(bytes, checkedAdd(offset, 4), label);
  const value = high * 0x100000000 + low;
  if (!Number.isSafeInteger(value))
    throw new Error(`${label} exceeds JavaScript's safe integer range.`);
  return value;
}

export function readUint64Be(bytes: Uint8Array, offset: number, label: string): number {
  const high = readUint32Be(bytes, offset, label);
  const low = readUint32Be(bytes, checkedAdd(offset, 4), label);
  const value = high * 0x100000000 + low;
  if (!Number.isSafeInteger(value))
    throw new Error(`${label} exceeds JavaScript's safe integer range.`);
  return value;
}

export class CheckedReader {
  private offset = 0;

  constructor(
    private readonly bytes: Uint8Array,
    private readonly label: string,
  ) {}

  get position(): number {
    return this.offset;
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  take(length: number, field: string): Uint8Array {
    requireRange(this.bytes.length, this.offset, length, `${this.label} ${field}`);
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  u8(field: string): number {
    return this.take(1, field)[0]!;
  }

  u16le(field: string): number {
    const value = readUint16Le(this.bytes, this.offset, `${this.label} ${field}`);
    this.offset += 2;
    return value;
  }

  u32le(field: string): number {
    const value = readUint32Le(this.bytes, this.offset, `${this.label} ${field}`);
    this.offset += 4;
    return value;
  }

  u32be(field: string): number {
    const value = readUint32Be(this.bytes, this.offset, `${this.label} ${field}`);
    this.offset += 4;
    return value;
  }

  u64le(field: string): number {
    const value = readUint64Le(this.bytes, this.offset, `${this.label} ${field}`);
    this.offset += 8;
    return value;
  }

  sshString(field: string): Uint8Array {
    const length = this.u32be(`${field} length`);
    return this.take(length, field);
  }

  finish(): void {
    if (this.remaining !== 0)
      throw new Error(`${this.label} has ${this.remaining} unexpected trailing bytes.`);
  }
}
