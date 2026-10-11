import type { ToolFileSource } from "@ocs/engine";
import {
  basename,
  bytesEqual,
  CheckedReader,
  checkedAdd,
  hex,
  johnName,
  readExact,
  readUint16Le,
  readUint32Le,
  sourceName,
} from "./binary";

const SIGNATURE = Uint8Array.of(0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5);
const END_MARKER = Uint8Array.of(0x0d, 0x0a, 0x0d, 0x0a);
const MAX_HEADER_BYTES = 1024 * 1024;

const CIPHERS = new Map<string, number>([
  ["31c1f2e6bf714350be5805216afc5aff", 0],
  ["ad68f29f576f4bb9a36ad47af965346c", 1],
  ["d6038a2b8b6f4cb5a524339a31dbb59a", 2],
]);
const KDF_AES = "c9d9f39a628a4460bf740d08c18a4fea";
const KDF_ARGON2D = "ef636ddf8c29444b91f7a9a403e30a0c";
const KDF_ARGON2ID = "9e298b1956db4773b23dfc3ec6f0a1e6";

interface KdbxFields {
  cipher?: Uint8Array;
  masterSeed?: Uint8Array;
  transformSeed?: Uint8Array;
  transformRounds?: number;
  encryptionIv?: Uint8Array;
  streamStart?: Uint8Array;
  kdfParameters?: Uint8Array;
}

interface KdfParameters {
  uuid: string;
  rounds: number;
  memory: number;
  version: number;
  parallelism: number;
  seed: Uint8Array;
}

function concat(chunks: readonly Uint8Array[], length: number): Uint8Array {
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function requireLength(
  value: Uint8Array | undefined,
  length: number,
  label: string,
): Uint8Array {
  if (!value || value.length !== length)
    throw new Error(`KDBX ${label} must be exactly ${length} bytes.`);
  return value;
}

function parseVariantDictionary(bytes: Uint8Array): KdfParameters {
  const reader = new CheckedReader(bytes, "KDBX KDF parameters");
  const versionBytes = reader.take(2, "dictionary version");
  const version = readUint16Le(versionBytes, 0, "KDBX variant dictionary version");
  if (version !== 0x0100) {
    throw new Error(
      `Unsupported KDBX variant dictionary version 0x${version.toString(16).padStart(4, "0")}.`,
    );
  }
  const entries = new Map<string, { type: number; value: Uint8Array }>();
  while (true) {
    const type = reader.u8("value type");
    if (type === 0) break;
    const keyLength = reader.u32le("key length");
    const key = new TextDecoder("utf-8", { fatal: true }).decode(reader.take(keyLength, "key"));
    const valueLength = reader.u32le(`${key} value length`);
    const value = reader.take(valueLength, `${key} value`);
    if (![0x04, 0x05, 0x08, 0x0c, 0x0d, 0x18, 0x42].includes(type)) {
      throw new Error(`Unsupported KDBX variant dictionary type 0x${type.toString(16)}.`);
    }
    if (entries.has(key))
      throw new Error(`KDBX KDF parameters contain duplicate ${key} entries.`);
    entries.set(key, { type, value });
  }
  reader.finish();

  const byteArray = (key: string, length: number): Uint8Array => {
    const entry = entries.get(key);
    if (!entry || entry.type !== 0x42 || entry.value.length !== length) {
      throw new Error(`KDBX KDF parameter ${key} must be a ${length}-byte array.`);
    }
    return entry.value;
  };
  const uint32 = (key: string): number => {
    const entry = entries.get(key);
    if (!entry || entry.type !== 0x04 || entry.value.length !== 4) {
      throw new Error(`KDBX KDF parameter ${key} must be UInt32.`);
    }
    return readUint32Le(entry.value, 0, `KDBX KDF ${key}`);
  };
  const uint64 = (key: string): number => {
    const entry = entries.get(key);
    if (!entry || entry.type !== 0x05 || entry.value.length !== 8) {
      throw new Error(`KDBX KDF parameter ${key} must be UInt64.`);
    }
    const value = new CheckedReader(entry.value, `KDBX KDF ${key}`).u64le(key);
    return value;
  };

  const uuidBytes = byteArray("$UUID", 16);
  const uuid = hex(uuidBytes);
  if (uuid !== KDF_AES && uuid !== KDF_ARGON2D && uuid !== KDF_ARGON2ID) {
    throw new Error(`Unsupported KDBX KDF UUID ${uuid}.`);
  }
  const rounds = uuid === KDF_AES ? uint64("R") : uint64("I");
  if (rounds === 0 || rounds > 0xffffffff) {
    throw new Error("KDBX KDF rounds must fit John's 32-bit descriptor field and be non-zero.");
  }
  const seed = byteArray("S", 32);
  if (uuid === KDF_AES) {
    return { uuid, rounds, memory: 0, version: 0, parallelism: 0, seed };
  }
  const memory = uint64("M");
  const argonVersion = uint32("V");
  const parallelism = uint32("P");
  if (memory === 0 || parallelism === 0)
    throw new Error("KDBX Argon2 memory and parallelism must be non-zero.");
  if (argonVersion !== 0x10 && argonVersion !== 0x13) {
    throw new Error(`Unsupported KDBX Argon2 version 0x${argonVersion.toString(16)}.`);
  }
  return { uuid, rounds, memory, version: argonVersion, parallelism, seed };
}

function databaseName(source: ToolFileSource): string {
  return johnName(basename(sourceName(source)).replace(/(?:\.kdbx)+$/, ""));
}

/** Matches src/keepass2john.c for KDBX 3.0/3.1 and KDBX 4.0/4.1 without a keyfile. */
export async function extractKdbx(source: ToolFileSource): Promise<string> {
  const fixed = await readExact(source, 0, 12, "KDBX fixed header");
  if (!bytesEqual(fixed.subarray(0, 8), SIGNATURE)) {
    throw new Error("Not a KDBX database: the KeePass 2 signature is invalid.");
  }
  const fileVersion = readUint32Le(fixed, 8, "KDBX file version");
  if (
    fileVersion !== 0x00030000 &&
    fileVersion !== 0x00030001 &&
    fileVersion !== 0x00040000 &&
    fileVersion !== 0x00040001
  ) {
    throw new Error(
      `Unsupported KDBX file version 0x${fileVersion.toString(16).padStart(8, "0")}.`,
    );
  }
  const major = fileVersion >>> 16;
  const lengthBytes = major === 3 ? 2 : 4;
  const chunks: Uint8Array[] = [fixed];
  const fields: KdbxFields = {};
  const seen = new Set<number>();
  let offset = 12;
  while (true) {
    if (offset > MAX_HEADER_BYTES)
      throw new Error("KDBX header exceeds the 1 MiB supported limit.");
    const fieldHeader = await readExact(
      source,
      offset,
      1 + lengthBytes,
      "KDBX header field prefix",
    );
    chunks.push(fieldHeader);
    offset = checkedAdd(offset, fieldHeader.length, "KDBX header offset");
    const id = fieldHeader[0]!;
    if (id > 12) throw new Error(`Unsupported KDBX header field ID ${id}.`);
    if (seen.has(id)) throw new Error(`KDBX header contains duplicate field ID ${id}.`);
    seen.add(id);
    const size =
      lengthBytes === 2
        ? readUint16Le(fieldHeader, 1, "KDBX header field length")
        : readUint32Le(fieldHeader, 1, "KDBX header field length");
    if (id !== 0 && size === 0) throw new Error(`KDBX header field ID ${id} has zero length.`);
    if (checkedAdd(offset, size, "KDBX header field end") > MAX_HEADER_BYTES) {
      throw new Error("KDBX header exceeds the 1 MiB supported limit.");
    }
    const value = await readExact(source, offset, size, `KDBX header field ${id}`);
    chunks.push(value);
    offset += size;
    switch (id) {
      case 0:
        if (!bytesEqual(value, END_MARKER))
          throw new Error("KDBX end-of-header marker is invalid.");
        break;
      case 2:
        fields.cipher = value;
        break;
      case 4:
        fields.masterSeed = value;
        break;
      case 5:
        fields.transformSeed = value;
        break;
      case 6: {
        if (value.length !== 8) throw new Error("KDBX transform rounds field must be UInt64.");
        fields.transformRounds = new CheckedReader(value, "KDBX transform rounds").u64le(
          "rounds",
        );
        break;
      }
      case 7:
        fields.encryptionIv = value;
        break;
      case 9:
        fields.streamStart = value;
        break;
      case 11:
        fields.kdfParameters = value;
        break;
    }
    if (id === 0) break;
  }

  const header = concat(chunks, offset);
  const cipher = requireLength(fields.cipher, 16, "cipher UUID");
  const algorithm = CIPHERS.get(hex(cipher));
  if (algorithm === undefined) throw new Error(`Unsupported KDBX cipher UUID ${hex(cipher)}.`);
  const masterSeed = requireLength(fields.masterSeed, 32, "master seed");
  const name = databaseName(source);
  if (major === 3) {
    if (fields.kdfParameters) throw new Error("KDBX3 header contains KDBX4 KDF parameters.");
    const rounds = fields.transformRounds;
    if (!rounds || rounds > 0xffffffff) {
      throw new Error(
        "KDBX3 transform rounds must fit John's 32-bit descriptor field and be non-zero.",
      );
    }
    const transformSeed = requireLength(fields.transformSeed, 32, "transform seed");
    const ivLength = algorithm === 2 ? 12 : 16;
    const iv = requireLength(fields.encryptionIv, ivLength, "encryption IV");
    const streamStart = requireLength(fields.streamStart, 32, "stream start bytes");
    const encrypted = await readExact(source, offset, 32, "KDBX3 first encrypted block");
    return `${name}:$keepass$*2*${rounds}*${algorithm}*${hex(masterSeed)}*${hex(transformSeed)}*${hex(iv)}*${hex(streamStart)}*${hex(encrypted)}\n`;
  }

  if (fields.transformSeed || fields.transformRounds !== undefined || fields.streamStart) {
    throw new Error("KDBX4 header contains obsolete KDBX3 transform fields.");
  }
  requireLength(fields.encryptionIv, algorithm === 2 ? 12 : 16, "encryption IV");
  const kdf = parseVariantDictionary(fields.kdfParameters ?? new Uint8Array());
  const trailer = await readExact(source, offset, 64, "KDBX4 header hash and HMAC");
  const expectedHash = trailer.subarray(0, 32);
  const actualHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", Uint8Array.from(header).buffer),
  );
  if (!bytesEqual(actualHash, expectedHash))
    throw new Error("KDBX4 header SHA-256 hash mismatch; the database is corrupt.");
  const headerHmac = trailer.subarray(32);
  return `${name}:$keepass$*4*${kdf.rounds}*${kdf.uuid.slice(0, 8)}*${kdf.memory}*${kdf.version}*${kdf.parallelism}*${hex(masterSeed)}*${hex(kdf.seed)}*${hex(header)}*${hex(headerHmac)}\n`;
}
