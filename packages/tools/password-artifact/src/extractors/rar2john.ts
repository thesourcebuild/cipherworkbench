import type { ToolFileSource } from "@ocs/engine";
import {
  basename,
  checkedAdd,
  decodeUtf8,
  hex,
  johnName,
  readChunked,
  readExact,
  readUint16Le,
  readUint32Le,
  sourceName,
} from "./binary";

const RAR3_MAGIC = Uint8Array.of(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00);
const RAR5_MAGIC = Uint8Array.of(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00);
const MAX_INLINE = 64 * 1024 * 1024;
const MAX_HEADERS = 100_000;

function equalAt(bytes: Uint8Array, expected: Uint8Array): boolean {
  return expected.every((byte, index) => bytes[index] === byte);
}

function archiveNames(source: ToolFileSource): { base: string; full: string } {
  const full = johnName(sourceName(source));
  return { base: johnName(basename(full)), full };
}

interface Rar3Candidate {
  name: string;
  salt: Uint8Array;
  crc: Uint8Array;
  packed: number;
  unpacked: number;
  method: number;
  data: Uint8Array;
}

function betterRar3(current: Rar3Candidate | undefined, candidate: Rar3Candidate): boolean {
  if (!current) return true;
  const currentMinimum = current.method > 0x30 ? 4 : 1;
  const candidateMinimum = candidate.method > 0x30 ? 4 : 1;
  if (
    (current.packed < candidate.packed && current.unpacked >= currentMinimum) ||
    (current.unpacked > candidate.unpacked && candidate.unpacked < candidateMinimum)
  )
    return false;
  if (current.packed === candidate.packed) {
    if (current.unpacked > candidate.unpacked && candidate.unpacked < 8) return false;
    if (current.unpacked <= candidate.unpacked && current.unpacked >= 8) return false;
  }
  return true;
}

async function extractRar3(source: ToolFileSource): Promise<string> {
  if (source.metadata.size < 20) throw new Error("RAR3 archive header is truncated.");
  const archiveHeader = await readExact(source, 7, 13, "RAR3 archive header");
  if (archiveHeader[2] !== 0x73) throw new Error("RAR3 main archive header type is invalid.");
  const archiveFlags = readUint16Le(archiveHeader, 3, "RAR3 archive flags");
  const headerSize = readUint16Le(archiveHeader, 5, "RAR3 archive header size");
  if (headerSize < 13) throw new Error("RAR3 archive header size is invalid.");
  if ((archiveFlags & 1) !== 0) throw new Error("Multipart RAR3 archives are unsupported.");
  const { base, full } = archiveNames(source);
  if ((archiveFlags & 0x80) !== 0) {
    if (source.metadata.size < 24)
      throw new Error("RAR3 encrypted-header trailer is truncated.");
    const trailer = await readExact(
      source,
      source.metadata.size - 24,
      24,
      "RAR3 encrypted-header trailer",
    );
    return `${base}:$RAR3$*0*${hex(trailer.subarray(0, 8))}*${hex(trailer.subarray(8))}:0::::${full}\n`;
  }

  let offset = checkedAdd(7, headerSize, "RAR3 first file-header offset");
  let best: Rar3Candidate | undefined;
  const names: string[] = [];
  for (let count = 0; offset < source.metadata.size && count < MAX_HEADERS; count++) {
    if (source.metadata.size - offset < 7) break;
    const common = await readExact(source, offset, 7, "RAR3 block header");
    const type = common[2]!;
    const flags = readUint16Le(common, 3, "RAR3 block flags");
    const size = readUint16Le(common, 5, "RAR3 block size");
    if (size < 7) throw new Error("RAR3 block header size is invalid.");
    if (type === 0x7b) break;
    if (type !== 0x74) {
      let dataSize = 0;
      if ((flags & 0x8000) !== 0) {
        if (size < 11) throw new Error("RAR3 long block header is truncated.");
        const longHeader = await readExact(source, offset, 11, "RAR3 long block header");
        dataSize = readUint32Le(longHeader, 7, "RAR3 long block data size");
      }
      offset = checkedAdd(
        offset,
        checkedAdd(size, dataSize, "RAR3 long block span"),
        "RAR3 next block offset",
      );
      if (offset > source.metadata.size) throw new Error("RAR3 block data is truncated.");
      continue;
    }
    if ((flags & 0x8000) === 0) throw new Error("RAR3 file header has no data-size flag.");
    if (size < 32) throw new Error("RAR3 file header is truncated.");
    const fixed = await readExact(source, offset, 32, "RAR3 file header");
    let packed = readUint32Le(fixed, 7, "RAR3 packed size");
    let unpacked = readUint32Le(fixed, 11, "RAR3 unpacked size");
    let cursor = offset + 32;
    if ((flags & 0x100) !== 0) {
      const high = await readExact(source, cursor, 8, "RAR3 large-file sizes");
      packed += readUint32Le(high, 0, "RAR3 high packed size") * 0x100000000;
      unpacked += readUint32Le(high, 4, "RAR3 high unpacked size") * 0x100000000;
      if (!Number.isSafeInteger(packed) || !Number.isSafeInteger(unpacked))
        throw new Error("RAR3 file size exceeds the safe integer range.");
      cursor += 8;
    }
    const nameLength = readUint16Le(fixed, 26, "RAR3 filename length");
    if (nameLength === 0 || cursor + nameLength > offset + size)
      throw new Error("RAR3 filename is truncated.");
    const nameBytes = await readExact(source, cursor, nameLength, "RAR3 filename");
    if ((flags & 0x200) !== 0)
      throw new Error("RAR3 encoded Unicode filenames are unsupported safely.");
    const name = johnName(decodeUtf8(nameBytes, "RAR3 filename"), "RAR3 filename");
    names.push(name);
    cursor += nameLength;
    let salt: Uint8Array = new Uint8Array(8);
    if ((flags & 0x400) !== 0) {
      if (cursor + 8 > offset + size) throw new Error("RAR3 salt is truncated.");
      salt = await readExact(source, cursor, 8, "RAR3 salt");
      cursor += 8;
    }
    const dataOffset = checkedAdd(offset, size, "RAR3 packed-data offset");
    const nextOffset = checkedAdd(dataOffset, packed, "RAR3 next block offset");
    if (nextOffset > source.metadata.size) throw new Error("RAR3 packed data is truncated.");
    const encrypted = (flags & 0x04) !== 0;
    const solid = (flags & 0x10) !== 0;
    const directory = (flags & 0xe0) >>> 5 === 7;
    if (encrypted && !solid && !directory) {
      const version = fixed[24]!;
      const method = fixed[25]!;
      if (version < 29)
        throw new Error(`RAR3 entry ${name} uses unsupported pre-2.9 encryption.`);
      if (packed > MAX_INLINE)
        throw new Error(
          `RAR3 entry ${name} exceeds the ${MAX_INLINE}-byte browser-safe inline limit.`,
        );
      const candidate: Rar3Candidate = {
        name,
        salt,
        crc: fixed.slice(16, 20),
        packed,
        unpacked,
        method,
        data: await readChunked(source, dataOffset, packed, MAX_INLINE, `RAR3 entry ${name}`),
      };
      if (betterRar3(best, candidate)) best = candidate;
    }
    offset = nextOffset;
  }
  if (!best) throw new Error("RAR3 archive contains no supported encrypted file candidate.");
  const gecos = names.length === 0 ? best.name : `${names.join(" ")} `;
  return `${base}:$RAR3$*1*${hex(best.salt)}*${hex(best.crc)}*${best.packed}*${best.unpacked}*1*${hex(best.data)}*${best.method.toString(16).padStart(2, "0")}:1::${gecos}\n`;
}

class Rar5Reader {
  position: number;
  private limit: number;
  constructor(
    private readonly source: ToolFileSource,
    position: number,
    limit = source.metadata.size,
  ) {
    this.position = position;
    this.limit = limit;
  }
  setLimit(limit: number): void {
    if (limit < this.position || limit > this.source.metadata.size)
      throw new Error("RAR5 declared header boundary is invalid.");
    this.limit = limit;
  }
  async bytes(length: number, label: string): Promise<Uint8Array> {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.limit - this.position)
      throw new Error(`${label} exceeds its declared RAR5 field boundary.`);
    const value = await readExact(this.source, this.position, length, label);
    this.position += length;
    return value;
  }
  async u8(label: string): Promise<number> {
    return (await this.bytes(1, label))[0]!;
  }
  async vint(label: string): Promise<number> {
    let value = 0;
    let factor = 1;
    for (let index = 0; index < 10; index++) {
      const byte = await this.u8(label);
      const part = byte & 0x7f;
      if (part !== 0 && factor > Math.floor(Number.MAX_SAFE_INTEGER / part))
        throw new Error(`${label} exceeds the safe integer range.`);
      value += part * factor;
      if (!Number.isSafeInteger(value))
        throw new Error(`${label} exceeds the safe integer range.`);
      if ((byte & 0x80) === 0) return value;
      factor *= 128;
    }
    throw new Error(`${label} uses an overlong variable integer.`);
  }
}

async function rar5Line(
  source: ToolFileSource,
  salt: Uint8Array,
  iterations: number,
  iv: Uint8Array,
  check: Uint8Array,
): Promise<string> {
  const { base } = archiveNames(source);
  return `${base}:$rar5$16$${hex(salt)}$${iterations}$${hex(iv)}$8$${hex(check)}\n`;
}

async function validPasswordCheck(check: Uint8Array, checksum: Uint8Array): Promise<boolean> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", Uint8Array.from(check).buffer),
  );
  return checksum.every((byte, index) => digest[index] === byte);
}

async function extractRar5(source: ToolFileSource): Promise<string> {
  let offset = 8;
  let encryptedHeaders: { salt: Uint8Array; iterations: number; check: Uint8Array } | undefined;
  for (let count = 0; offset < source.metadata.size && count < MAX_HEADERS; count++) {
    if (encryptedHeaders) {
      const iv = await readExact(source, offset, 16, "RAR5 encrypted-header IV");
      return rar5Line(
        source,
        encryptedHeaders.salt,
        encryptedHeaders.iterations,
        iv,
        encryptedHeaders.check,
      );
    }
    const reader = new Rar5Reader(source, offset);
    await reader.bytes(4, "RAR5 header CRC");
    const blockSize = await reader.vint("RAR5 block size");
    const afterSize = reader.position;
    const headSize = checkedAdd(4 + (afterSize - (offset + 4)), blockSize, "RAR5 header size");
    const headerEnd = checkedAdd(offset, headSize, "RAR5 header end");
    reader.setLimit(headerEnd);
    const headerType = await reader.u8("RAR5 header type");
    const flags = await reader.vint("RAR5 header flags");
    const extraSize = (flags & 1) !== 0 ? await reader.vint("RAR5 extra-data size") : 0;
    const dataSize = (flags & 2) !== 0 ? await reader.vint("RAR5 data size") : 0;
    const nextOffset = checkedAdd(
      offset,
      checkedAdd(headSize, dataSize, "RAR5 block span"),
      "RAR5 next block offset",
    );
    if (nextOffset > source.metadata.size)
      throw new Error("RAR5 block points beyond the end of the file.");
    if (headerType === 4) {
      const version = await reader.vint("RAR5 crypt version");
      if (version !== 0) throw new Error(`Unsupported RAR5 crypt version ${version}.`);
      const cryptFlags = await reader.vint("RAR5 crypt flags");
      const iterations = await reader.u8("RAR5 KDF exponent");
      if (iterations > 24) throw new Error("RAR5 KDF exponent is unsupported.");
      const salt = await reader.bytes(16, "RAR5 salt");
      if ((cryptFlags & 1) === 0)
        throw new Error(
          "RAR5 encrypted headers without a password check are unsupported upstream.",
        );
      const check = await reader.bytes(8, "RAR5 password check");
      const checksum = await reader.bytes(4, "RAR5 password-check checksum");
      if (!(await validPasswordCheck(check, checksum)))
        throw new Error("RAR5 password-check checksum is corrupt.");
      encryptedHeaders = { salt, iterations, check };
    } else if (headerType === 1) {
      const archiveFlags = await reader.vint("RAR5 archive flags");
      if ((archiveFlags & 1) !== 0) throw new Error("Multipart RAR5 archives are unsupported.");
      if ((archiveFlags & 2) !== 0) await reader.vint("RAR5 volume number");
    } else if (headerType === 2 || headerType === 3) {
      const fileFlags = await reader.vint("RAR5 file flags");
      await reader.vint("RAR5 unpacked size");
      await reader.vint("RAR5 file attributes");
      if ((fileFlags & 2) !== 0) await reader.bytes(4, "RAR5 modification time");
      if ((fileFlags & 4) !== 0) await reader.bytes(4, "RAR5 file CRC");
      await reader.vint("RAR5 compression info");
      await reader.vint("RAR5 host OS");
      const nameSize = await reader.vint("RAR5 filename size");
      await reader.bytes(nameSize, "RAR5 filename");
      const extraStart = offset + headSize - extraSize;
      if (extraSize > 0) {
        const extraEnd = checkedAdd(extraStart, extraSize, "RAR5 extra-data end");
        if (extraStart < reader.position)
          throw new Error("RAR5 extra-data size overlaps the fixed file header.");
        const extra = new Rar5Reader(source, extraStart, extraEnd);
        while (extra.position < extraEnd) {
          const fieldSize = await extra.vint("RAR5 extra-field size");
          const fieldStart = extra.position;
          const fieldEnd = checkedAdd(fieldStart, fieldSize, "RAR5 extra-field end");
          if (fieldEnd > extraEnd) throw new Error("RAR5 extra field is truncated.");
          const fieldType = await extra.vint("RAR5 extra-field type");
          if (fieldType === 1) {
            const version = await extra.vint("RAR5 file crypt version");
            if (version !== 0)
              throw new Error(`Unsupported RAR5 file crypt version ${version}.`);
            const cryptFlags = await extra.vint("RAR5 file crypt flags");
            if ((cryptFlags & 1) === 0)
              throw new Error(
                "RAR5 encrypted files without a password check are unsupported upstream.",
              );
            const iterations = await extra.u8("RAR5 file KDF exponent");
            if (iterations >= 24) throw new Error("RAR5 file KDF exponent is unsupported.");
            const salt = await extra.bytes(16, "RAR5 file salt");
            const iv = await extra.bytes(16, "RAR5 file IV");
            const check = await extra.bytes(8, "RAR5 file password check");
            return rar5Line(source, salt, iterations, iv, check);
          }
          extra.position = fieldEnd;
        }
      }
    } else if (headerType === 5) break;
    offset = nextOffset;
  }
  throw new Error("RAR5 archive contains no supported encrypted header or file entry.");
}

/** John jumbo rar2john compatibility for RAR3 -p/-hp and RAR5 password-check records. */
export async function extractRar(source: ToolFileSource): Promise<string> {
  if (source.metadata.size < 8) throw new Error("RAR signature is truncated.");
  const magic = await readExact(source, 0, 8, "RAR signature");
  if (equalAt(magic, RAR5_MAGIC)) return extractRar5(source);
  if (equalAt(magic, RAR3_MAGIC)) return extractRar3(source);
  if (magic[0] === 0x52 && magic[1] === 0x45 && magic[2] === 0x7e && magic[3] === 0x5e) {
    throw new Error("Pre-1.50 RAR archives are unsupported.");
  }
  throw new Error(
    "RAR3/RAR5 signature is invalid; SFX archives are not supported by the browser extractor.",
  );
}
