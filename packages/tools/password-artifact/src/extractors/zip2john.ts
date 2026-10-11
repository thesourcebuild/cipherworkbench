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
  readUint64Le,
  sourceName,
} from "./binary";

const EOCD_WINDOW = 22 + 0xffff;
const MAX_ENTRIES = 100_000;
const MAX_INLINE = 64 * 1024 * 1024;
const MAX_LEGACY_CANDIDATES = 8;

interface ZipEntry {
  name: string;
  version: number;
  flags: number;
  method: number;
  modifiedTime: number;
  crc: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
  aes?: { version: number; strength: number; method: number };
}

function signature(bytes: Uint8Array, offset: number, value: number): boolean {
  return (
    offset >= 0 &&
    offset + 4 <= bytes.length &&
    readUint32Le(bytes, offset, "ZIP signature") === value
  );
}

function parseZip64Extra(
  extra: Uint8Array,
  entry: Pick<ZipEntry, "compressedSize" | "uncompressedSize" | "localOffset">,
): void {
  let offset = 0;
  while (offset < extra.length) {
    if (extra.length - offset < 4) throw new Error("ZIP extra field header is truncated.");
    const id = readUint16Le(extra, offset, "ZIP extra field ID");
    const size = readUint16Le(extra, offset + 2, "ZIP extra field size");
    offset += 4;
    if (offset + size > extra.length) throw new Error("ZIP extra field is truncated.");
    if (id === 0x0001) {
      let cursor = offset;
      const take64 = (label: string): number => {
        if (cursor + 8 > offset + size) throw new Error(`ZIP64 ${label} is truncated.`);
        const value = readUint64Le(extra, cursor, `ZIP64 ${label}`);
        cursor += 8;
        return value;
      };
      if (entry.uncompressedSize === 0xffffffff)
        entry.uncompressedSize = take64("uncompressed size");
      if (entry.compressedSize === 0xffffffff) entry.compressedSize = take64("compressed size");
      if (entry.localOffset === 0xffffffff) entry.localOffset = take64("local-header offset");
    }
    offset += size;
  }
}

function parseAesExtra(extra: Uint8Array): ZipEntry["aes"] {
  let offset = 0;
  while (offset < extra.length) {
    if (extra.length - offset < 4) throw new Error("ZIP extra field header is truncated.");
    const id = readUint16Le(extra, offset, "ZIP extra field ID");
    const size = readUint16Le(extra, offset + 2, "ZIP extra field size");
    offset += 4;
    if (offset + size > extra.length) throw new Error("ZIP extra field is truncated.");
    if (id === 0x9901) {
      if (size !== 7) throw new Error("ZIP AES extra field must contain exactly 7 bytes.");
      const version = readUint16Le(extra, offset, "ZIP AES vendor version");
      const vendor = readUint16Le(extra, offset + 2, "ZIP AES vendor ID");
      const strength = extra[offset + 4]!;
      const method = readUint16Le(extra, offset + 5, "ZIP AES compression method");
      if (
        (version !== 1 && version !== 2) ||
        vendor !== 0x4541 ||
        strength < 1 ||
        strength > 3
      ) {
        throw new Error(
          "ZIP AES metadata has an unsupported vendor version, vendor, or strength.",
        );
      }
      return { version, strength, method };
    }
    offset += size;
  }
  return undefined;
}

function decodeEntryName(bytes: Uint8Array, flags: number): string {
  if ((flags & 0x800) === 0 && bytes.some((byte) => byte > 0x7f)) {
    throw new Error(
      "ZIP entry names using a legacy code page are unsupported; use UTF-8 names.",
    );
  }
  return johnName(decodeUtf8(bytes, "ZIP entry name"), "ZIP entry name");
}

async function locateCentralDirectory(
  source: ToolFileSource,
): Promise<{ offset: number; count: number }> {
  if (source.metadata.size < 22)
    throw new Error("ZIP end-of-central-directory record is truncated.");
  const length = Math.min(source.metadata.size, EOCD_WINDOW);
  const start = source.metadata.size - length;
  const tail = await readChunked(source, start, length, EOCD_WINDOW, "ZIP trailer");
  let eocd = -1;
  for (let offset = tail.length - 22; offset >= 0; offset--) {
    if (!signature(tail, offset, 0x06054b50)) continue;
    const commentLength = readUint16Le(tail, offset + 20, "ZIP comment length");
    if (offset + 22 + commentLength === tail.length) {
      eocd = offset;
      break;
    }
  }
  if (eocd < 0)
    throw new Error("ZIP end-of-central-directory record was not found or is corrupt.");
  const disk = readUint16Le(tail, eocd + 4, "ZIP disk number");
  const centralDisk = readUint16Le(tail, eocd + 6, "ZIP central-directory disk");
  if (disk !== 0 || centralDisk !== 0)
    throw new Error("Multipart ZIP archives are unsupported.");
  let count = readUint16Le(tail, eocd + 10, "ZIP entry count");
  let offset = readUint32Le(tail, eocd + 16, "ZIP central-directory offset");
  if (count === 0xffff || offset === 0xffffffff) {
    const locatorAbsolute = start + eocd - 20;
    const locator = await readExact(source, locatorAbsolute, 20, "ZIP64 locator");
    if (!signature(locator, 0, 0x07064b50)) throw new Error("ZIP64 locator is missing.");
    if (readUint32Le(locator, 4, "ZIP64 locator disk") !== 0) {
      throw new Error("Multipart ZIP64 archives are unsupported.");
    }
    const recordOffset = readUint64Le(locator, 8, "ZIP64 end record offset");
    const record = await readExact(source, recordOffset, 56, "ZIP64 end record");
    if (!signature(record, 0, 0x06064b50))
      throw new Error("ZIP64 end record signature is invalid.");
    if (
      readUint32Le(record, 16, "ZIP64 disk number") !== 0 ||
      readUint32Le(record, 20, "ZIP64 central-directory disk") !== 0
    ) {
      throw new Error("Multipart ZIP64 archives are unsupported.");
    }
    count = readUint64Le(record, 32, "ZIP64 entry count");
    offset = readUint64Le(record, 48, "ZIP64 central-directory offset");
  }
  if (count === 0 || count > MAX_ENTRIES)
    throw new Error(`ZIP entry count ${count} is unsupported.`);
  return { offset, count };
}

async function readEntries(source: ToolFileSource): Promise<ZipEntry[]> {
  const central = await locateCentralDirectory(source);
  const entries: ZipEntry[] = [];
  let offset = central.offset;
  for (let index = 0; index < central.count; index++) {
    const fixed = await readExact(source, offset, 46, `ZIP central entry ${index + 1}`);
    if (!signature(fixed, 0, 0x02014b50))
      throw new Error(`ZIP central entry ${index + 1} has invalid magic.`);
    const nameLength = readUint16Le(fixed, 28, "ZIP name length");
    const extraLength = readUint16Le(fixed, 30, "ZIP extra length");
    const commentLength = readUint16Le(fixed, 32, "ZIP entry comment length");
    const variable = await readChunked(
      source,
      offset + 46,
      nameLength + extraLength,
      0x1fffe,
      `ZIP central entry ${index + 1} fields`,
    );
    const flags = readUint16Le(fixed, 8, "ZIP flags");
    const extra = variable.subarray(nameLength);
    const entry: ZipEntry = {
      name: decodeEntryName(variable.subarray(0, nameLength), flags),
      version: readUint16Le(fixed, 6, "ZIP version") & 0xff,
      flags,
      method: readUint16Le(fixed, 10, "ZIP compression method"),
      modifiedTime: readUint16Le(fixed, 12, "ZIP modification time"),
      crc: readUint32Le(fixed, 16, "ZIP CRC"),
      compressedSize: readUint32Le(fixed, 20, "ZIP compressed size"),
      uncompressedSize: readUint32Le(fixed, 24, "ZIP uncompressed size"),
      localOffset: readUint32Le(fixed, 42, "ZIP local-header offset"),
      aes: parseAesExtra(extra),
    };
    parseZip64Extra(extra, entry);
    entries.push(entry);
    offset = checkedAdd(
      offset,
      46 + nameLength + extraLength + commentLength,
      "ZIP central entry",
    );
  }
  return entries;
}

async function localDataOffset(
  source: ToolFileSource,
  entry: ZipEntry,
): Promise<{ data: number; offex: number }> {
  const local = await readExact(
    source,
    entry.localOffset,
    30,
    `ZIP local header for ${entry.name}`,
  );
  if (!signature(local, 0, 0x04034b50))
    throw new Error(`ZIP local header for ${entry.name} has invalid magic.`);
  const nameLength = readUint16Le(local, 26, "ZIP local name length");
  const extraLength = readUint16Le(local, 28, "ZIP local extra length");
  const offex = 30 + nameLength + extraLength;
  return { data: checkedAdd(entry.localOffset, offex, "ZIP entry data offset"), offex };
}

async function aesLine(source: ToolFileSource, entry: ZipEntry): Promise<string> {
  if (!entry.aes) throw new Error("Internal ZIP AES metadata error.");
  const { data } = await localDataOffset(source, entry);
  const saltLength = 4 + 4 * entry.aes.strength;
  const overhead = saltLength + 2 + 10;
  if (entry.compressedSize <= overhead)
    throw new Error(`ZIP AES entry ${entry.name} is truncated.`);
  const realLength = entry.compressedSize - overhead;
  if (realLength > MAX_INLINE)
    throw new Error(
      `ZIP AES entry ${entry.name} exceeds the ${MAX_INLINE}-byte browser-safe inline limit.`,
    );
  const bytes = await readChunked(
    source,
    data,
    entry.compressedSize,
    MAX_INLINE + overhead,
    `ZIP AES entry ${entry.name}`,
  );
  const salt = bytes.subarray(0, saltLength);
  const verifier = bytes.subarray(saltLength, saltLength + 2);
  const encrypted = bytes.subarray(saltLength + 2, saltLength + 2 + realLength);
  const auth = bytes.subarray(bytes.length - 10);
  const full = johnName(sourceName(source));
  const archive = johnName(basename(full));
  return `${archive}/${entry.name}:$zip2$*0*${entry.aes.strength.toString(16)}*0*${hex(salt)}*${hex(verifier)}*${realLength.toString(16)}*${hex(encrypted)}*${hex(auth)}*$/zip2$:${entry.name}:${archive}:${full}\n`;
}

interface LegacyCandidate extends ZipEntry {
  data: Uint8Array;
  offex: number;
  checksum: string;
}

async function legacyCandidate(
  source: ToolFileSource,
  entry: ZipEntry,
): Promise<LegacyCandidate> {
  if (entry.compressedSize > MAX_INLINE)
    throw new Error(
      `ZIP entry ${entry.name} exceeds the ${MAX_INLINE}-byte browser-safe inline limit.`,
    );
  const local = await localDataOffset(source, entry);
  const data = await readChunked(
    source,
    local.data,
    entry.compressedSize,
    MAX_INLINE,
    `ZIP entry ${entry.name}`,
  );
  const check = (entry.flags & 8) !== 0 ? entry.modifiedTime : entry.crc >>> 16;
  const checksum = `${((check >>> 8) & 0xff).toString(16).padStart(2, "0")}${(check & 0xff).toString(16).padStart(2, "0")}`;
  return { ...entry, data, offex: local.offex, checksum };
}

function legacyLine(source: ToolFileSource, candidates: LegacyCandidate[]): string {
  candidates.sort((a, b) => a.compressedSize - b.compressedSize);
  const selected = candidates.slice(0, MAX_LEGACY_CANDIDATES);
  const archive = johnName(basename(sourceName(source)));
  const full = johnName(sourceName(source));
  const checkBytes = selected.some((entry) => entry.version >= 20) ? 1 : 2;
  const names = selected.map((entry) => entry.name).join(", ");
  const login = selected.length === 1 ? `${archive}/${selected[0]!.name}` : archive;
  let descriptor = `${login}:$pkzip$${selected.length.toString(16)}*${checkBytes.toString(16)}*`;
  for (let index = 1; index < selected.length; index++) {
    const entry = selected[index]!;
    const length = Math.min(36, entry.data.length);
    descriptor += `1*0*${entry.method.toString(16)}*${length.toString(16)}*${entry.checksum}*${hex(entry.data.subarray(0, length))}*`;
  }
  const first = selected[0]!;
  descriptor += `2*0*${first.compressedSize.toString(16)}*${first.uncompressedSize.toString(16)}*${first.crc.toString(16)}*${first.localOffset.toString(16)}*${first.offex.toString(16)}*${first.method.toString(16)}*${first.compressedSize.toString(16)}*${first.checksum}*${hex(first.data)}*`;
  descriptor +=
    selected.length > 1
      ? `$/pkzip$::${archive}:${names}:${full}\n`
      : `$/pkzip$:${names}:${archive}::${full}\n`;
  return descriptor;
}

/** John jumbo zip2john compatibility for ZIP/ZIP64 AES and traditional ZipCrypto entries. */
export async function extractZip(source: ToolFileSource): Promise<string> {
  const entries = await readEntries(source);
  const lines: string[] = [];
  const legacy: LegacyCandidate[] = [];
  let unsupported: string | undefined;
  for (const entry of entries) {
    if ((entry.flags & 1) === 0) continue;
    if (entry.method === 99) {
      if (!entry.aes)
        throw new Error(`ZIP AES entry ${entry.name} has no valid AES extra field.`);
      lines.push(await aesLine(source, entry));
      continue;
    }
    if (
      (entry.flags & 0x40) !== 0 ||
      entry.version === 51 ||
      entry.version === 52 ||
      entry.version >= 61
    ) {
      unsupported = `ZIP entry ${entry.name} uses unsupported PKWARE strong encryption.`;
      continue;
    }
    if (![10, 20, 45].includes(entry.version) || (entry.method !== 0 && entry.method !== 8)) {
      unsupported = `ZIP entry ${entry.name} uses unsupported traditional encryption version or compression method.`;
      continue;
    }
    if (entry.uncompressedSize < 4) continue;
    legacy.push(await legacyCandidate(source, entry));
  }
  if (legacy.length > 0) lines.push(legacyLine(source, legacy));
  if (lines.length === 0)
    throw new Error(unsupported ?? "ZIP archive contains no supported encrypted entries.");
  return lines.join("");
}
