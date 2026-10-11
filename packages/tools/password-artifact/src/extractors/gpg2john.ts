import type { ToolFileSource } from "@ocs/engine";
import {
  basename,
  decodeBase64,
  decodeUtf8,
  hex,
  johnName,
  readChunked,
  sourceName,
} from "./binary";

const MAX_GPG_BYTES = 16 * 1024 * 1024;
const MAX_PACKET_BYTES = 90_000;
const IV_LENGTHS = [0, 8, 8, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16] as const;

interface S2k {
  spec: number;
  hash: number;
  salt: Uint8Array;
  count: number;
}

interface PublicKey {
  version: number;
  algorithm: number;
  keyBits: number;
  publicMpis: Array<{ bits: number; bytes: Uint8Array }>;
  position: number;
}

interface SecretDescriptor {
  descriptor: string;
  user?: string;
}

function crc24(bytes: Uint8Array): number {
  let crc = 0xb704ce;
  for (const byte of bytes) {
    crc ^= byte << 16;
    for (let bit = 0; bit < 8; bit++)
      crc = (crc << 1) ^ ((crc & 0x1000000) !== 0 ? 0x1864cfb : 0);
  }
  return crc & 0xffffff;
}

function armor(bytes: Uint8Array): Uint8Array {
  if ((bytes[0]! & 0x80) !== 0) return bytes;
  const text = decodeUtf8(bytes, "OpenPGP armor");
  const matches = [...text.matchAll(/-----BEGIN PGP (?:PRIVATE KEY BLOCK|MESSAGE)-----/g)];
  if (matches.length !== 1)
    throw new Error("OpenPGP input must contain exactly one armored private key or message.");
  const match = matches[0]!;
  const begin = match.index! + match[0].length;
  const armorType = match[0].includes("PRIVATE KEY BLOCK") ? "PRIVATE KEY BLOCK" : "MESSAGE";
  const endMatch = new RegExp(`-----END PGP ${armorType}-----`).exec(text.slice(begin));
  if (!endMatch) throw new Error("OpenPGP armor footer is missing.");
  const body = text.slice(begin, begin + endMatch.index).replace(/\r/g, "");
  const split = body.indexOf("\n\n");
  if (split < 0) throw new Error("OpenPGP armor has no header/body separator.");
  const lines = body
    .slice(split + 2)
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const checksumLine = lines.find((line) => line.startsWith("="));
  const encoded = lines.filter((line) => !line.startsWith("=")).join("");
  const decoded = decodeBase64(encoded, "OpenPGP armored payload");
  if (checksumLine) {
    const checksum = decodeBase64(checksumLine.slice(1), "OpenPGP armor checksum");
    if (checksum.length !== 3) throw new Error("OpenPGP armor checksum length is invalid.");
    const expected = crc24(decoded);
    if (
      checksum[0] !== expected >>> 16 ||
      checksum[1] !== ((expected >>> 8) & 0xff) ||
      checksum[2] !== (expected & 0xff)
    ) {
      throw new Error("OpenPGP armor checksum mismatch.");
    }
  }
  return decoded;
}

class PacketReader {
  position = 0;
  constructor(
    readonly bytes: Uint8Array,
    readonly label: string,
  ) {}
  get remaining(): number {
    return this.bytes.length - this.position;
  }
  u8(field: string): number {
    if (this.position >= this.bytes.length)
      throw new Error(`${this.label} ${field} is truncated.`);
    return this.bytes[this.position++]!;
  }
  take(length: number, field: string): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.remaining)
      throw new Error(`${this.label} ${field} is truncated or invalid.`);
    const value = this.bytes.subarray(this.position, this.position + length);
    this.position += length;
    return value;
  }
  u16be(field: string): number {
    return this.u8(field) * 256 + this.u8(field);
  }
  u32be(field: string): number {
    return (
      this.u8(field) * 0x1000000 +
      this.u8(field) * 0x10000 +
      this.u8(field) * 0x100 +
      this.u8(field)
    );
  }
  mpi(field: string): { bits: number; bytes: Uint8Array } {
    const bits = this.u16be(`${field} bit length`);
    if (bits === 0 || bits > 131_072)
      throw new Error(`${this.label} ${field} bit length ${bits} is unsupported.`);
    return { bits, bytes: this.take(Math.ceil(bits / 8), field) };
  }
}

function newLength(reader: PacketReader, first: number): { length: number; partial: boolean } {
  if (first < 192) return { length: first, partial: false };
  if (first < 224)
    return { length: ((first - 192) << 8) + reader.u8("packet length") + 192, partial: false };
  if (first === 255) return { length: reader.u32be("packet length"), partial: false };
  return { length: 2 ** (first & 0x1f), partial: true };
}

function packetBody(reader: PacketReader): { tag: number; body: Uint8Array } {
  const header = reader.u8("packet header");
  if ((header & 0x80) === 0) throw new Error("OpenPGP packet header has no tag bit.");
  if ((header & 0x40) !== 0) {
    const tag = header & 0x3f;
    let descriptor = newLength(reader, reader.u8("packet length"));
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      total += descriptor.length;
      if (total > MAX_GPG_BYTES)
        throw new Error("OpenPGP partial packet exceeds the supported size.");
      chunks.push(reader.take(descriptor.length, "packet body"));
      if (!descriptor.partial) break;
      descriptor = newLength(reader, reader.u8("partial packet length"));
    }
    const body = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.length;
    }
    return { tag, body };
  }
  const tag = (header & 0x3f) >>> 2;
  const lengthType = header & 3;
  let length: number;
  if (lengthType === 0) length = reader.u8("packet length");
  else if (lengthType === 1) length = reader.u16be("packet length");
  else if (lengthType === 2) length = reader.u32be("packet length");
  else length = reader.remaining;
  return { tag, body: reader.take(length, "packet body") };
}

function parseS2k(reader: PacketReader): S2k {
  const spec = reader.u8("S2K type");
  if (spec !== 0 && spec !== 1 && spec !== 3)
    throw new Error(`Unsupported OpenPGP S2K type ${spec}.`);
  const hash = reader.u8("S2K hash algorithm");
  if (![1, 2, 3, 8, 9, 10, 11].includes(hash))
    throw new Error(`Unsupported OpenPGP S2K hash algorithm ${hash}.`);
  const salt = spec === 0 ? new Uint8Array(8) : reader.take(8, "S2K salt");
  const coded = spec === 3 ? reader.u8("S2K iteration count") : 0;
  const count = spec === 3 ? (16 + (coded & 15)) * 2 ** ((coded >>> 4) + 6) : 0;
  return { spec, hash, salt, count };
}

function publicKey(reader: PacketReader): PublicKey {
  const version = reader.u8("key version");
  if (version !== 2 && version !== 3 && version !== 4)
    throw new Error(`Unsupported OpenPGP secret-key version ${version}.`);
  reader.take(4, "key creation time");
  if (version < 4) reader.take(2, "key validity");
  const algorithm = reader.u8("public-key algorithm");
  const publicMpis: Array<{ bits: number; bytes: Uint8Array }> = [];
  if ([1, 2, 3].includes(algorithm)) {
    publicMpis.push(reader.mpi("RSA modulus"), reader.mpi("RSA exponent"));
  } else if (algorithm === 16 || algorithm === 20) {
    publicMpis.push(reader.mpi("ElGamal p"), reader.mpi("ElGamal g"), reader.mpi("ElGamal y"));
  } else if (algorithm === 17) {
    publicMpis.push(
      reader.mpi("DSA p"),
      reader.mpi("DSA q"),
      reader.mpi("DSA g"),
      reader.mpi("DSA y"),
    );
  } else {
    throw new Error(`Unsupported OpenPGP public-key algorithm ${algorithm}.`);
  }
  return {
    version,
    algorithm,
    keyBits: publicMpis[0]!.bits,
    publicMpis,
    position: reader.position,
  };
}

function secretKeyDescriptor(body: Uint8Array): string | undefined {
  const reader = new PacketReader(body, "OpenPGP secret-key packet");
  const key = publicKey(reader);
  const usage = reader.u8("secret-key S2K usage");
  if (usage === 0) return undefined;
  let cipher: number;
  let s2k: S2k;
  if (usage === 254 || usage === 255) {
    cipher = reader.u8("secret-key cipher");
    s2k = parseS2k(reader);
  } else {
    cipher = usage;
    s2k = { spec: 0, hash: 0, salt: new Uint8Array(8), count: 0 };
  }
  const ivLength = IV_LENGTHS[cipher];
  if (ivLength === undefined || ivLength === 0)
    throw new Error(`Unsupported OpenPGP secret-key cipher ${cipher}.`);
  const iv = reader.take(ivLength, "secret-key IV");
  const encrypted = reader.take(reader.remaining, "encrypted secret-key material");
  if (encrypted.length === 0 || encrypted.length > MAX_PACKET_BYTES)
    throw new Error("OpenPGP encrypted secret-key material has an unsupported length.");
  let descriptor = `$gpg$*${key.algorithm}*${encrypted.length}*${key.keyBits}*${hex(encrypted)}*${s2k.spec}*${usage}*${s2k.hash}*${cipher}*${iv.length}*${hex(iv)}*${s2k.count}*${hex(s2k.salt)}`;
  if (usage === 255) {
    const values =
      key.algorithm === 17
        ? key.publicMpis
        : key.algorithm === 16 || key.algorithm === 20
          ? key.publicMpis
          : key.publicMpis.slice(0, 1);
    for (const value of values) descriptor += `*${value.bytes.length}*${hex(value.bytes)}`;
  }
  return descriptor;
}

function symmetricDescriptor(
  body: Uint8Array,
  tag: 9 | 18,
  state: { cipher: number; s2k: S2k },
): string {
  const encrypted = tag === 18 ? body.subarray(1) : body;
  if (tag === 18 && body[0] !== 1)
    throw new Error(`Unsupported OpenPGP integrity-protected packet version ${body[0]}.`);
  if (encrypted.length === 0 || encrypted.length > MAX_PACKET_BYTES)
    throw new Error("OpenPGP encrypted message material has an unsupported length.");
  return `$gpg$*0*${encrypted.length}*${hex(encrypted)}*${state.s2k.spec}*${tag}*${state.s2k.hash}*${state.cipher}*${state.s2k.count}*${hex(state.s2k.salt)}\n`;
}

function fallbackUser(source: ToolFileSource): string {
  return johnName(basename(sourceName(source)).replace(/\.(?:gpg|pgp)$/i, ""));
}

function loginFromUser(value: string): string {
  return johnName(
    value.split("(", 1)[0]!.split("<", 1)[0]!.trim() || value.trim(),
    "OpenPGP user ID",
  );
}

/** John jumbo gpg2john compatibility for encrypted v2-v4 secret keys and SKESK messages. */
export async function extractGpg(source: ToolFileSource): Promise<string> {
  const input = await readChunked(
    source,
    0,
    source.metadata.size,
    MAX_GPG_BYTES,
    "OpenPGP file",
  );
  const bytes = armor(input);
  const reader = new PacketReader(bytes, "OpenPGP input");
  let secret: SecretDescriptor | undefined;
  let primaryKeys = 0;
  let symmetric: { cipher: number; s2k: S2k } | undefined;
  while (reader.remaining > 0) {
    const packet = packetBody(reader);
    if (packet.tag === 3) {
      const body = new PacketReader(packet.body, "OpenPGP SKESK packet");
      const version = body.u8("version");
      if (version !== 4) throw new Error(`Unsupported OpenPGP SKESK version ${version}.`);
      const cipher = body.u8("cipher");
      if (IV_LENGTHS[cipher] === undefined)
        throw new Error(`Unsupported OpenPGP message cipher ${cipher}.`);
      const s2k = parseS2k(body);
      symmetric = { cipher, s2k };
    } else if (packet.tag === 5) {
      primaryKeys++;
      if (primaryKeys > 1)
        throw new Error("OpenPGP input contains multiple primary secret-key packets.");
      const descriptor = secretKeyDescriptor(packet.body);
      if (descriptor) secret = { descriptor };
    } else if (packet.tag === 7) {
      continue;
    } else if (packet.tag === 13 && secret) {
      secret.user = decodeUtf8(packet.body, "OpenPGP user ID");
    } else if ((packet.tag === 9 || packet.tag === 18) && symmetric) {
      return symmetricDescriptor(packet.body, packet.tag, symmetric);
    }
  }
  if (!secret)
    throw new Error(
      "OpenPGP input contains no supported encrypted primary secret key or symmetric encrypted material.",
    );
  const user = secret.user?.trim() || fallbackUser(source);
  const login = loginFromUser(user);
  return `${login}:${secret.descriptor}:::${johnName(user, "OpenPGP user ID")}::${johnName(sourceName(source))}\n`;
}
