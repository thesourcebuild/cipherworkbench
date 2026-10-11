import type { ToolFileSource } from "@ocs/engine";
import {
  CheckedReader,
  basename,
  decodeBase64,
  decodeUtf8,
  hex,
  johnName,
  readExact,
  readUint16Le,
  readUint32Le,
  readUint64Le,
  sourceName,
} from "./binary";

const CFB_MAGIC = Uint8Array.of(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1);
const END = 0xfffffffe;
const FREE = 0xffffffff;
const MAX_STREAM = 64 * 1024 * 1024;
const MAX_SECTORS = 1_000_000;

interface DirectoryEntry {
  name: string;
  type: number;
  start: number;
  size: number;
}

class CompoundFile {
  private readonly sectorSize: number;
  private readonly miniSectorSize: number;
  private readonly cutoff: number;
  private readonly fat: number[];
  private readonly miniFat: number[];
  private readonly directory: DirectoryEntry[];
  private readonly miniStream: Uint8Array;

  private constructor(
    private readonly source: ToolFileSource,
    sectorSize: number,
    miniSectorSize: number,
    cutoff: number,
    fat: number[],
    miniFat: number[],
    directory: DirectoryEntry[],
    miniStream: Uint8Array,
  ) {
    this.sectorSize = sectorSize;
    this.miniSectorSize = miniSectorSize;
    this.cutoff = cutoff;
    this.fat = fat;
    this.miniFat = miniFat;
    this.directory = directory;
    this.miniStream = miniStream;
  }

  private static sectorOffset(
    id: number,
    sectorSize: number,
    sourceSize: number,
    label: string,
  ): number {
    if (!Number.isSafeInteger(id) || id < 0 || id >= Math.ceil(sourceSize / sectorSize))
      throw new Error(`${label} sector ID ${id} is invalid.`);
    const offset = (id + 1) * sectorSize;
    if (!Number.isSafeInteger(offset))
      throw new Error(`${label} sector offset overflows the safe integer range.`);
    return offset;
  }

  private static chain(ids: number[], start: number, label: string): number[] {
    if (start === END || start === FREE) return [];
    const output: number[] = [];
    const seen = new Set<number>();
    let current = start;
    while (current !== END) {
      if (
        !Number.isSafeInteger(current) ||
        current < 0 ||
        current >= ids.length ||
        seen.has(current)
      )
        throw new Error(`${label} sector chain is corrupt or cyclic.`);
      seen.add(current);
      output.push(current);
      if (output.length > MAX_SECTORS) throw new Error(`${label} sector chain is too long.`);
      current = ids[current]!;
      if (current === FREE) throw new Error(`${label} sector chain ends in a free sector.`);
    }
    return output;
  }

  private static async regularBytes(
    source: ToolFileSource,
    sectorSize: number,
    fat: number[],
    start: number,
    size: number,
    label: string,
  ): Promise<Uint8Array> {
    if (size > MAX_STREAM)
      throw new Error(`${label} exceeds the ${MAX_STREAM}-byte stream limit.`);
    const chain = CompoundFile.chain(fat, start, label);
    if (chain.length * sectorSize < size)
      throw new Error(`${label} sector chain is truncated.`);
    const output = new Uint8Array(size);
    let written = 0;
    for (const id of chain) {
      if (written >= size) break;
      const count = Math.min(sectorSize, size - written);
      const bytes = await readExact(
        source,
        CompoundFile.sectorOffset(id, sectorSize, source.metadata.size, label),
        count,
        label,
      );
      output.set(bytes, written);
      written += count;
    }
    return output;
  }

  static async open(source: ToolFileSource): Promise<CompoundFile> {
    if (source.metadata.size < 512)
      throw new Error("Office compound-file header is truncated.");
    const header = await readExact(source, 0, 512, "Office compound-file header");
    if (!CFB_MAGIC.every((byte, index) => header[index] === byte))
      throw new Error("Office compound-file signature is invalid.");
    const major = readUint16Le(header, 26, "CFB major version");
    if (major !== 3 && major !== 4)
      throw new Error(`Unsupported Office compound-file major version ${major}.`);
    if (readUint16Le(header, 28, "CFB byte order") !== 0xfffe)
      throw new Error("Office compound-file byte order is invalid.");
    const sectorSize = 2 ** readUint16Le(header, 30, "CFB sector shift");
    const miniSectorSize = 2 ** readUint16Le(header, 32, "CFB mini-sector shift");
    if (
      (major === 3 && sectorSize !== 512) ||
      (major === 4 && sectorSize !== 4096) ||
      miniSectorSize !== 64
    )
      throw new Error("Office compound-file sector sizes are unsupported.");
    const fatCount = readUint32Le(header, 44, "CFB FAT sector count");
    if (fatCount === 0 || fatCount > MAX_SECTORS)
      throw new Error("Office compound-file FAT size is invalid.");
    const difat: number[] = [];
    for (let offset = 76; offset < 512; offset += 4) {
      const id = readUint32Le(header, offset, "CFB DIFAT entry");
      if (id !== FREE) difat.push(id);
    }
    let difatSector = readUint32Le(header, 68, "CFB first DIFAT sector");
    const difatCount = readUint32Le(header, 72, "CFB DIFAT sector count");
    const seenDifat = new Set<number>();
    for (let index = 0; index < difatCount; index++) {
      if (difatSector === END || seenDifat.has(difatSector))
        throw new Error("Office compound-file DIFAT chain is truncated or cyclic.");
      seenDifat.add(difatSector);
      const sector = await readExact(
        source,
        CompoundFile.sectorOffset(difatSector, sectorSize, source.metadata.size, "CFB DIFAT"),
        sectorSize,
        "CFB DIFAT sector",
      );
      for (let offset = 0; offset < sectorSize - 4; offset += 4) {
        const id = readUint32Le(sector, offset, "CFB DIFAT entry");
        if (id !== FREE) difat.push(id);
      }
      difatSector = readUint32Le(sector, sectorSize - 4, "CFB next DIFAT sector");
    }
    if (difat.length < fatCount)
      throw new Error("Office compound-file DIFAT does not list every FAT sector.");
    const fat: number[] = [];
    for (const id of difat.slice(0, fatCount)) {
      const sector = await readExact(
        source,
        CompoundFile.sectorOffset(id, sectorSize, source.metadata.size, "CFB FAT"),
        sectorSize,
        "CFB FAT sector",
      );
      for (let offset = 0; offset < sector.length; offset += 4)
        fat.push(readUint32Le(sector, offset, "CFB FAT entry"));
    }
    const directoryStart = readUint32Le(header, 48, "CFB directory start");
    const directoryBytes = await CompoundFile.regularBytes(
      source,
      sectorSize,
      fat,
      directoryStart,
      Math.min(
        MAX_STREAM,
        CompoundFile.chain(fat, directoryStart, "CFB directory").length * sectorSize,
      ),
      "CFB directory",
    );
    const directory: DirectoryEntry[] = [];
    for (let offset = 0; offset + 128 <= directoryBytes.length; offset += 128) {
      const nameLength = readUint16Le(directoryBytes, offset + 64, "CFB directory name length");
      const type = directoryBytes[offset + 66]!;
      if (type === 0) continue;
      if (nameLength < 2 || nameLength > 64 || nameLength % 2 !== 0)
        throw new Error("Office compound-file directory name is corrupt.");
      let name = "";
      for (let cursor = offset; cursor < offset + nameLength - 2; cursor += 2)
        name += String.fromCharCode(readUint16Le(directoryBytes, cursor, "CFB directory name"));
      const size = readUint64Le(directoryBytes, offset + 120, "CFB stream size");
      directory.push({
        name,
        type,
        start: readUint32Le(directoryBytes, offset + 116, "CFB stream start"),
        size: major === 3 ? size >>> 0 : size,
      });
    }
    const root = directory.find((entry) => entry.type === 5);
    if (!root) throw new Error("Office compound file has no root storage.");
    const miniFatStart = readUint32Le(header, 60, "CFB MiniFAT start");
    const miniFatCount = readUint32Le(header, 64, "CFB MiniFAT sector count");
    const miniFatBytes =
      miniFatCount === 0
        ? new Uint8Array()
        : await CompoundFile.regularBytes(
            source,
            sectorSize,
            fat,
            miniFatStart,
            miniFatCount * sectorSize,
            "CFB MiniFAT",
          );
    const miniFat: number[] = [];
    for (let offset = 0; offset < miniFatBytes.length; offset += 4)
      miniFat.push(readUint32Le(miniFatBytes, offset, "CFB MiniFAT entry"));
    const miniStream =
      root.size === 0
        ? new Uint8Array()
        : await CompoundFile.regularBytes(
            source,
            sectorSize,
            fat,
            root.start,
            root.size,
            "CFB mini stream",
          );
    return new CompoundFile(
      source,
      sectorSize,
      miniSectorSize,
      readUint32Le(header, 56, "CFB mini-stream cutoff"),
      fat,
      miniFat,
      directory,
      miniStream,
    );
  }

  has(name: string): boolean {
    return this.directory.some((entry) => entry.type === 2 && entry.name === name);
  }

  names(): string[] {
    return this.directory.filter((entry) => entry.type === 2).map((entry) => entry.name);
  }

  async stream(name: string): Promise<Uint8Array> {
    const matches = this.directory.filter((entry) => entry.type === 2 && entry.name === name);
    if (matches.length !== 1)
      throw new Error(`Office compound-file stream ${name} is missing or ambiguous.`);
    const entry = matches[0]!;
    if (entry.size > MAX_STREAM)
      throw new Error(`Office stream ${name} exceeds the ${MAX_STREAM}-byte limit.`);
    if (entry.size >= this.cutoff)
      return CompoundFile.regularBytes(
        this.source,
        this.sectorSize,
        this.fat,
        entry.start,
        entry.size,
        `Office stream ${name}`,
      );
    const chain = CompoundFile.chain(this.miniFat, entry.start, `Office mini stream ${name}`);
    if (chain.length * this.miniSectorSize < entry.size)
      throw new Error(`Office mini stream ${name} is truncated.`);
    const output = new Uint8Array(entry.size);
    let written = 0;
    for (const id of chain) {
      const offset = id * this.miniSectorSize;
      const count = Math.min(this.miniSectorSize, entry.size - written);
      if (offset + count > this.miniStream.length)
        throw new Error(`Office mini stream ${name} points beyond the root mini stream.`);
      output.set(this.miniStream.subarray(offset, offset + count), written);
      written += count;
      if (written === entry.size) break;
    }
    return output;
  }
}

function officeName(source: ToolFileSource): string {
  return johnName(basename(sourceName(source)));
}

function cryptoApi(
  bytes: Uint8Array,
  start: number,
  label: string,
  keyTypes: Readonly<Record<number, number>>,
): { type: number; salt: Uint8Array; verifier: Uint8Array; hash: Uint8Array; end: number } {
  const reader = new CheckedReader(bytes.subarray(start), label);
  reader.u16le("major version");
  reader.u16le("minor version");
  reader.u32le("encryption flags");
  let headerLength = reader.u32le("encryption header length");
  if (headerLength < 32 || headerLength > reader.remaining)
    throw new Error(`${label} encryption header length is invalid.`);
  reader.u32le("header flags");
  headerLength -= 4;
  const sizeExtra = reader.u32le("extra size");
  headerLength -= 4;
  const algorithm = reader.u32le("cipher algorithm");
  headerLength -= 4;
  const hashAlgorithm = reader.u32le("hash algorithm");
  headerLength -= 4;
  const keySize = reader.u32le("key size");
  headerLength -= 4;
  reader.u32le("provider type");
  headerLength -= 4;
  reader.u32le("reserved field");
  headerLength -= 4;
  reader.u32le("reserved field");
  headerLength -= 4;
  if (sizeExtra !== 0 || headerLength < 0)
    throw new Error(`${label} CryptoAPI header is corrupt.`);
  reader.take(headerLength, "provider name");
  const type = keyTypes[keySize];
  if (type === undefined)
    throw new Error(`${label} uses unsupported ${keySize}-bit encryption.`);
  if (algorithm !== 0x6801 || hashAlgorithm !== 0x8004)
    throw new Error(`${label} uses unsupported CryptoAPI algorithms.`);
  const saltSize = reader.u32le("salt size");
  if (saltSize !== 16) throw new Error(`${label} salt size must be 16 bytes.`);
  const salt = reader.take(16, "salt");
  const verifier = reader.take(16, "encrypted verifier");
  const hashSize = reader.u32le("verifier hash size");
  if (hashSize !== 20) throw new Error(`${label} verifier hash size must be 20 bytes.`);
  const hash = reader.take(20, "encrypted verifier hash");
  return { type, salt, verifier, hash, end: start + reader.position };
}

function oldOfficeLine(
  name: string,
  type: number,
  salt: Uint8Array,
  verifier: Uint8Array,
  hashValue: Uint8Array,
  extra = "",
): string {
  return `${name}:$oldoffice$${type}*${hex(salt)}*${hex(verifier)}*${hex(hashValue)}${extra}\n`;
}

function legacyStandard(bytes: Uint8Array, offset: number, name: string, type: number): string {
  if (offset + 48 > bytes.length) throw new Error("Legacy Office RC4 verifier is truncated.");
  return oldOfficeLine(
    name,
    type,
    bytes.subarray(offset, offset + 16),
    bytes.subarray(offset + 16, offset + 32),
    bytes.subarray(offset + 32, offset + 48),
  );
}

function extractWorkbook(bytes: Uint8Array, name: string): string {
  let offset = 0;
  while (offset < bytes.length) {
    if (offset + 4 > bytes.length) throw new Error("Excel BIFF record header is truncated.");
    const type = readUint16Le(bytes, offset, "Excel BIFF record type");
    const length = readUint16Le(bytes, offset + 2, "Excel BIFF record length");
    offset += 4;
    if (offset + length > bytes.length) throw new Error("Excel BIFF record is truncated.");
    if (type === 0x2f) {
      const data = bytes.subarray(offset, offset + length);
      if (length === 4 || (data[0] === 0 && data[1] === 0))
        throw new Error("Excel XOR obfuscation is not a password hash supported by John.");
      if (hex(data.subarray(0, 6)) === "010001000100") return legacyStandard(data, 6, name, 0);
      if (data[0] === 1 && data[1] === 0 && data[3] === 0 && [2, 3, 4].includes(data[2]!)) {
        // BIFF FILEPASS starts with a two-byte encryption marker before the version pair.
        const parsed = cryptoApi(data, 2, "Excel CryptoAPI", { 40: 3, 128: 4 });
        const extra = parsed.type === 3 ? `*${hex(bytes.subarray(1024, 1056))}` : "";
        if (parsed.type === 3 && bytes.length < 1056)
          throw new Error("Excel 40-bit CryptoAPI second verifier block is truncated.");
        return oldOfficeLine(
          name,
          parsed.type,
          parsed.salt,
          parsed.verifier,
          parsed.hash,
          extra,
        );
      }
      throw new Error("Excel FILEPASS encryption form is unsupported.");
    }
    offset += length;
  }
  throw new Error("Excel workbook has no FILEPASS encryption record.");
}

function extractWord(word: Uint8Array, table: Uint8Array, name: string): string {
  if (word.length < 16 || readUint16Le(word, 0, "Word identifier") !== 0xa5ec)
    throw new Error("WordDocument stream header is invalid or truncated.");
  const flags = word[11]!;
  if ((flags & 1) === 0) throw new Error("Word document is not encrypted.");
  if ((flags & 0x80) !== 0) throw new Error("Word XOR obfuscation is not supported by John.");
  if (table.length < 4) throw new Error("Word encryption table is truncated.");
  const major = readUint16Le(table, 0, "Word encryption major version");
  const minor = readUint16Le(table, 2, "Word encryption minor version");
  if (major === 1 || minor === 1) return legacyStandard(table, 4, name, 1);
  if (major >= 2 && minor === 2) {
    const parsed = cryptoApi(table, 0, "Word CryptoAPI", { 40: 3, 56: 5, 128: 4 });
    const extra = parsed.type === 3 ? `*${hex(table.subarray(512, 544))}` : "";
    if (parsed.type === 3 && table.length < 544)
      throw new Error("Word 40-bit CryptoAPI second verifier block is truncated.");
    return oldOfficeLine(name, parsed.type, parsed.salt, parsed.verifier, parsed.hash, extra);
  }
  throw new Error(`Unsupported Word encryption version ${major}.${minor}.`);
}

function xmlAttribute(tag: string, name: string): string {
  const match = new RegExp(`(?:^|\\s)${name}\\s*=\\s*["']([^"']+)["']`).exec(tag);
  if (!match) throw new Error(`Office agile encryption XML is missing ${name}.`);
  return match[1]!;
}

function extractEncryptionInfo(bytes: Uint8Array, name: string): string {
  if (bytes.length < 8) throw new Error("Office EncryptionInfo stream is truncated.");
  const major = readUint16Le(bytes, 0, "Office encryption major version");
  const minor = readUint16Le(bytes, 2, "Office encryption minor version");
  const flags = readUint32Le(bytes, 4, "Office encryption flags");
  if ((flags & 0x10) !== 0)
    throw new Error("Office external cryptographic providers are unsupported.");
  if (major === 4 && minor === 4) {
    if (flags !== 0x40) throw new Error("Office agile encryption flags are inconsistent.");
    const xml = decodeUtf8(bytes.subarray(8), "Office agile encryption XML");
    const passwordKeys = [...xml.matchAll(/<[^>]*encryptedKey\b[^>]*>/gi)]
      .map((match) => match[0])
      .filter((tag) => /(?:^|\s)spinCount\s*=/.test(tag));
    if (passwordKeys.length !== 1) {
      throw new Error(
        "Office agile encryption XML must contain exactly one password encryptedKey element.",
      );
    }
    const tag = passwordKeys[0]!;
    const hashAlgorithm = xmlAttribute(tag, "hashAlgorithm");
    const version =
      hashAlgorithm === "SHA1" ? 2010 : hashAlgorithm === "SHA512" ? 2013 : undefined;
    if (!version)
      throw new Error(`Office agile hash algorithm ${hashAlgorithm} is unsupported.`);
    if (!xmlAttribute(tag, "cipherAlgorithm").includes("AES"))
      throw new Error("Office agile encryption uses an unsupported cipher.");
    const spin = Number(xmlAttribute(tag, "spinCount"));
    const keyBits = Number(xmlAttribute(tag, "keyBits"));
    const saltSize = Number(xmlAttribute(tag, "saltSize"));
    if (
      ![spin, keyBits, saltSize].every(Number.isSafeInteger) ||
      spin <= 0 ||
      ![128, 192, 256].includes(keyBits) ||
      saltSize <= 0
    )
      throw new Error("Office agile numeric encryption metadata is invalid.");
    const salt = decodeBase64(xmlAttribute(tag, "saltValue"), "Office agile salt");
    const verifier = decodeBase64(
      xmlAttribute(tag, "encryptedVerifierHashInput"),
      "Office agile verifier",
    );
    const verifierHash = decodeBase64(
      xmlAttribute(tag, "encryptedVerifierHashValue"),
      "Office agile verifier hash",
    ).subarray(0, 32);
    if (salt.length !== saltSize)
      throw new Error("Office agile salt length does not match saltSize.");
    return `${name}:$office$*${version}*${spin}*${keyBits}*${saltSize}*${hex(salt)}*${hex(verifier)}*${hex(verifierHash)}\n`;
  }
  const reader = new CheckedReader(bytes.subarray(8), "Office 2007 EncryptionInfo");
  let headerLength = reader.u32le("header length");
  if (headerLength < 32 || headerLength > reader.remaining)
    throw new Error("Office 2007 encryption header length is invalid.");
  reader.u32le("header flags");
  headerLength -= 4;
  if (reader.u32le("extra size") !== 0)
    throw new Error("Office 2007 encryption extra size is unsupported.");
  headerLength -= 4;
  const algorithm = reader.u32le("cipher algorithm");
  headerLength -= 4;
  const hashAlgorithm = reader.u32le("hash algorithm");
  headerLength -= 4;
  const keySize = reader.u32le("key size");
  headerLength -= 4;
  reader.u32le("provider type");
  headerLength -= 4;
  reader.u32le("reserved field");
  headerLength -= 4;
  reader.u32le("reserved field");
  headerLength -= 4;
  if (
    ![0x660e, 0x660f, 0x6610].includes(algorithm) ||
    hashAlgorithm !== 0x8004 ||
    ![128, 192, 256].includes(keySize) ||
    headerLength < 0
  )
    throw new Error("Office 2007 standard encryption algorithms are unsupported or corrupt.");
  reader.take(headerLength, "provider name");
  const saltSize = reader.u32le("salt size");
  if (saltSize !== 16) throw new Error("Office 2007 salt size must be 16 bytes.");
  const salt = reader.take(16, "salt");
  const verifier = reader.take(16, "encrypted verifier");
  const hashSize = reader.u32le("verifier hash size");
  if (hashSize === 0 || hashSize > reader.remaining)
    throw new Error("Office 2007 verifier hash size is invalid.");
  const verifierHash = reader.take(hashSize, "encrypted verifier hash").subarray(0, 32);
  return `${name}:$office$*2007*${hashSize}*${keySize}*${saltSize}*${hex(salt)}*${hex(verifier)}*${hex(verifierHash)}\n`;
}

/** Office 95-2003 RC4/CryptoAPI and OOXML standard/agile encryption descriptors. */
export async function extractOffice(source: ToolFileSource): Promise<string> {
  const compound = await CompoundFile.open(source);
  if (compound.names().some((name) => name.startsWith("\u0005"))) {
    throw new Error(
      "Office files with summary-property streams are unsupported because canonical metadata fields cannot be omitted safely.",
    );
  }
  const name = officeName(source);
  if (compound.has("EncryptionInfo"))
    return extractEncryptionInfo(await compound.stream("EncryptionInfo"), name);
  if (compound.has("Workbook")) return extractWorkbook(await compound.stream("Workbook"), name);
  if (compound.has("Book")) return extractWorkbook(await compound.stream("Book"), name);
  if (compound.has("WordDocument")) {
    const word = await compound.stream("WordDocument");
    if (word.length < 12) throw new Error("WordDocument stream is truncated.");
    const tableName = (word[11]! & 2) !== 0 ? "1Table" : "0Table";
    return extractWord(word, await compound.stream(tableName), name);
  }
  if (compound.has("PowerPoint Document"))
    throw new Error(
      "Legacy encrypted PowerPoint persistence directories are not registered as supported.",
    );
  throw new Error("Office compound file has no supported encrypted Office stream.");
}
