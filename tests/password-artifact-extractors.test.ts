import { describe, expect, it } from "vitest";
import type { ToolFileSource } from "@ocs/engine";
import { passwordArtifactToolDefinition } from "@ocs/password-artifact/definition";

const UPSTREAM_COMMIT = "5184bc0b8c105f8c5978b112e723d65b2de3e63e";
const CFB_END = 0xfffffffe;

function concat(...chunks: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function sequence(length: number, start = 0): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function fromHex(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new Error("Odd fixture hex length");
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function u16le(value: number): Uint8Array {
  return Uint8Array.of(value, value >>> 8);
}

function u16be(value: number): Uint8Array {
  return Uint8Array.of(value >>> 8, value);
}

function u32le(value: number): Uint8Array {
  return Uint8Array.of(value, value >>> 8, value >>> 16, value >>> 24);
}

function u32be(value: number): Uint8Array {
  return Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);
}

function u64le(value: number): Uint8Array {
  return concat(u32le(value >>> 0), u32le(Math.floor(value / 0x100000000)));
}

function u64be(value: number): Uint8Array {
  return concat(u32be(Math.floor(value / 0x100000000)), u32be(value >>> 0));
}

function put(target: Uint8Array, offset: number, bytes: Uint8Array): void {
  target.set(bytes, offset);
}

function ascii(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function sshString(bytes: Uint8Array): Uint8Array {
  return concat(u32be(bytes.length), bytes);
}

interface TrackedSource extends ToolFileSource {
  reads: Array<{ offset: number; length: number }>;
}

function trackedSource(
  bytes: Uint8Array,
  name: string,
  reportedSize = bytes.length,
): TrackedSource {
  const reads: Array<{ offset: number; length: number }> = [];
  return {
    metadata: { name, size: reportedSize },
    maxReadBytes: 1024 * 1024,
    reads,
    async read(offset, length) {
      reads.push({ offset, length });
      const output = new Uint8Array(length);
      if (offset < bytes.length)
        output.set(bytes.subarray(offset, Math.min(bytes.length, offset + length)));
      return output;
    },
  };
}

async function runExtractor(
  id: string,
  source: ToolFileSource,
  options: Record<string, string | number | boolean | string[]> = {},
): Promise<string> {
  const tool = passwordArtifactToolDefinition(id);
  const spec = { ...tool.createSpec(), options: { ...tool.createSpec().options, ...options } };
  const result = await tool.computeFile!(spec, source);
  if (result.error) throw new Error(result.error);
  return result.text!;
}

function openSshFixture(cipherName = "aes256-ctr"): {
  pem: Uint8Array;
  blob: Uint8Array;
  salt: Uint8Array;
  offset: number;
} {
  const magic = concat(ascii("openssh-key-v1"), Uint8Array.of(0));
  const salt = sequence(16, 0x10);
  const kdf = concat(sshString(salt), u32be(23));
  const publicKey = sshString(ascii("ssh-ed25519"));
  const encrypted = sequence(16, 0xa0);
  const beforeEncrypted = concat(
    magic,
    sshString(ascii(cipherName)),
    sshString(ascii("bcrypt")),
    sshString(kdf),
    u32be(1),
    sshString(publicKey),
  );
  const blob = concat(beforeEncrypted, sshString(encrypted));
  const body = Buffer.from(blob)
    .toString("base64")
    .match(/.{1,70}/g)!
    .join("\n");
  const pem = ascii(
    `-----BEGIN OPENSSH PRIVATE KEY-----\n${body}\n-----END OPENSSH PRIVATE KEY-----\n`,
  );
  return { pem, blob, salt, offset: beforeEncrypted.length + 4 };
}

function legacySshFixture(): { pem: Uint8Array; der: Uint8Array; iv: Uint8Array } {
  const der = sequence(32, 0x30);
  const iv = sequence(16, 0x80);
  const body = Buffer.from(der).toString("base64");
  return {
    der,
    iv,
    pem: ascii(
      `-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,${hex(iv).toUpperCase()}\n\n${body}\n-----END RSA PRIVATE KEY-----\n`,
    ),
  };
}

function luksFixture(): { bytes: Uint8Array; material: Uint8Array } {
  const bytes = new Uint8Array(1536);
  put(bytes, 0, Uint8Array.of(0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe));
  put(bytes, 6, u16be(1));
  put(bytes, 8, ascii("aes\0"));
  put(bytes, 40, ascii("cbc-essiv:sha256\0"));
  put(bytes, 72, ascii("sha1\0"));
  put(bytes, 104, u32be(8));
  put(bytes, 108, u32be(32));
  put(bytes, 112, sequence(20, 0x20));
  put(bytes, 132, sequence(32, 0x40));
  put(bytes, 164, u32be(1000));
  put(bytes, 168, ascii("11111111-2222-3333-4444-555555555555\0"));
  put(bytes, 208, u32be(0x00ac71f3));
  put(bytes, 212, u32be(2000));
  put(bytes, 216, sequence(32, 0x60));
  put(bytes, 248, u32be(2));
  put(bytes, 252, u32be(2));
  const material = sequence(512, 0x80);
  put(bytes, 1024, material);
  return { bytes, material };
}

function dmgV1Fixture(): Uint8Array {
  const bytes = new Uint8Array(1276);
  put(bytes, 48, u32be(1000));
  put(bytes, 52, u32be(4));
  put(bytes, 56, Uint8Array.of(1, 2, 3, 4));
  put(bytes, 136, u32be(8));
  put(bytes, 140, sequence(8, 0x10));
  put(bytes, 436, u32be(12));
  put(bytes, 440, sequence(12, 0x30));
  put(bytes, bytes.length - 8, ascii("cdsaencr"));
  return bytes;
}

function dmgV2Fixture(): {
  bytes: Uint8Array;
  salt: Uint8Array;
  iv: Uint8Array;
  blob: Uint8Array;
  data: Uint8Array;
} {
  const bytes = new Uint8Array(512 + 8192);
  put(bytes, 0, ascii("encrcdsa"));
  put(bytes, 8, u32be(2));
  put(bytes, 56, u64be(8192));
  put(bytes, 64, u64be(512));
  put(bytes, 72, u32be(1));
  put(bytes, 76, u32be(1));
  put(bytes, 84, u32be(128));
  put(bytes, 92, u32be(107));
  put(bytes, 136, u32be(1500));
  const salt = Uint8Array.of(1, 2, 3, 4);
  put(bytes, 140, u32be(salt.length));
  put(bytes, 144, salt);
  const iv = sequence(32, 0x40);
  put(bytes, 176, u32be(32));
  put(bytes, 180, iv);
  const blob = Uint8Array.of(0xaa, 0xbb, 0xcc);
  put(bytes, 228, u32be(blob.length));
  put(bytes, 232, blob);
  const data = sequence(8192, 0x70);
  put(bytes, 512, data);
  return { bytes, salt, iv, blob, data };
}

function fveEntry(entryType: number, valueType: number, data: Uint8Array): Uint8Array {
  return concat(u16le(8 + data.length), u16le(entryType), u16le(valueType), u16le(1), data);
}

function bitLockerFixture(protection: 0x2000 | 0x800): {
  bytes: Uint8Array;
  salt: Uint8Array;
  nonce: Uint8Array;
  encrypted: Uint8Array;
} {
  const salt = sequence(16, 0x10);
  const nonce = sequence(12, 0x30);
  const encrypted = sequence(20, 0x50);
  const nestedCcm = fveEntry(0, 5, concat(sequence(12, 1), sequence(17, 2)));
  const stretch = fveEntry(0, 3, concat(u32le(0x8000), salt, nestedCcm));
  const ccm = fveEntry(0, 5, concat(nonce, encrypted));
  const vmkPrefix = new Uint8Array(28);
  put(vmkPrefix, 26, u16le(protection));
  const vmk = fveEntry(2, 8, concat(vmkPrefix, stretch, ccm));
  const metadata = new Uint8Array(112 + vmk.length);
  put(metadata, 64, u32le(metadata.length));
  put(metadata, 112, vmk);

  const bytes = new Uint8Array(0x200 + metadata.length);
  put(bytes, 3, ascii("-FVE-FS-"));
  put(bytes, 11, u16le(512));
  put(bytes, 0xa0, fromHex("3bd66749292ed84a8399f6a339e3d001"));
  put(bytes, 0xb0, u64le(0x200));
  put(bytes, 0x200, metadata);
  return { bytes, salt, nonce, encrypted };
}

function kdbxField(id: number, value: Uint8Array, major: 3 | 4): Uint8Array {
  return concat(
    Uint8Array.of(id),
    major === 3 ? u16le(value.length) : u32le(value.length),
    value,
  );
}

function kdbx3Fixture(fileVersion = 0x00030001): {
  bytes: Uint8Array;
  master: Uint8Array;
  transform: Uint8Array;
  iv: Uint8Array;
  start: Uint8Array;
  encrypted: Uint8Array;
} {
  const master = sequence(32, 0x10);
  const transform = sequence(32, 0x30);
  const iv = sequence(16, 0x50);
  const start = sequence(32, 0x70);
  const encrypted = sequence(32, 0x90);
  const header = concat(
    fromHex("03d9a29a67fb4bb5"),
    u32le(fileVersion),
    kdbxField(2, fromHex("31c1f2e6bf714350be5805216afc5aff"), 3),
    kdbxField(4, master, 3),
    kdbxField(5, transform, 3),
    kdbxField(6, u64le(6000), 3),
    kdbxField(7, iv, 3),
    kdbxField(9, start, 3),
    kdbxField(0, fromHex("0d0a0d0a"), 3),
  );
  return { bytes: concat(header, encrypted), master, transform, iv, start, encrypted };
}

function variantEntry(type: number, key: string, value: Uint8Array): Uint8Array {
  const keyBytes = ascii(key);
  return concat(
    Uint8Array.of(type),
    u32le(keyBytes.length),
    keyBytes,
    u32le(value.length),
    value,
  );
}

async function kdbx4Fixture(fileVersion = 0x00040001): Promise<{
  bytes: Uint8Array;
  header: Uint8Array;
  master: Uint8Array;
  seed: Uint8Array;
  hmac: Uint8Array;
}> {
  const master = sequence(32, 0x20);
  const seed = sequence(32, 0x60);
  const dictionary = concat(
    u16le(0x0100),
    variantEntry(0x42, "$UUID", fromHex("ef636ddf8c29444b91f7a9a403e30a0c")),
    variantEntry(0x05, "I", u64le(3)),
    variantEntry(0x05, "M", u64le(4_194_304)),
    variantEntry(0x04, "P", u32le(2)),
    variantEntry(0x42, "S", seed),
    variantEntry(0x04, "V", u32le(0x13)),
    Uint8Array.of(0),
  );
  const header = concat(
    fromHex("03d9a29a67fb4bb5"),
    u32le(fileVersion),
    kdbxField(2, fromHex("31c1f2e6bf714350be5805216afc5aff"), 4),
    kdbxField(4, master, 4),
    kdbxField(7, sequence(16, 0x40), 4),
    kdbxField(11, dictionary, 4),
    kdbxField(0, fromHex("0d0a0d0a"), 4),
  );
  const hash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", Uint8Array.from(header).buffer),
  );
  const hmac = sequence(32, 0xa0);
  return { bytes: concat(header, hash, hmac), header, master, seed, hmac };
}

function zipAesFixture(zip64 = false): {
  bytes: Uint8Array;
  salt: Uint8Array;
  verifier: Uint8Array;
  encrypted: Uint8Array;
  auth: Uint8Array;
} {
  const name = ascii("secret.txt");
  const aesExtra = concat(
    u16le(0x9901),
    u16le(7),
    u16le(2),
    ascii("AE"),
    Uint8Array.of(1),
    u16le(8),
  );
  const salt = sequence(8, 0x10);
  const verifier = Uint8Array.of(0xaa, 0xbb);
  const encrypted = sequence(16, 0x30);
  const auth = sequence(10, 0x50);
  const data = concat(salt, verifier, encrypted, auth);
  const local = concat(
    u32le(0x04034b50),
    u16le(zip64 ? 45 : 20),
    u16le(1),
    u16le(99),
    u16le(0),
    u16le(0),
    u32le(0),
    u32le(zip64 ? 0xffffffff : data.length),
    u32le(zip64 ? 0xffffffff : 20),
    u16le(name.length),
    u16le(zip64 ? aesExtra.length + 20 : aesExtra.length),
    name,
    ...(zip64
      ? [concat(u16le(1), u16le(16), u64le(20), u64le(data.length)), aesExtra]
      : [aesExtra]),
    data,
  );
  const centralExtra = zip64
    ? concat(u16le(1), u16le(24), u64le(20), u64le(data.length), u64le(0), aesExtra)
    : aesExtra;
  const central = concat(
    u32le(0x02014b50),
    u16le(45),
    u16le(zip64 ? 45 : 20),
    u16le(1),
    u16le(99),
    u16le(0),
    u16le(0),
    u32le(0),
    u32le(zip64 ? 0xffffffff : data.length),
    u32le(zip64 ? 0xffffffff : 20),
    u16le(name.length),
    u16le(centralExtra.length),
    u16le(0),
    u16le(0),
    u16le(0),
    u32le(0),
    u32le(zip64 ? 0xffffffff : 0),
    name,
    centralExtra,
  );
  if (!zip64) {
    const eocd = concat(
      u32le(0x06054b50),
      u16le(0),
      u16le(0),
      u16le(1),
      u16le(1),
      u32le(central.length),
      u32le(local.length),
      u16le(0),
    );
    return { bytes: concat(local, central, eocd), salt, verifier, encrypted, auth };
  }
  const zip64EndOffset = local.length + central.length;
  const zip64End = concat(
    u32le(0x06064b50),
    u64le(44),
    u16le(45),
    u16le(45),
    u32le(0),
    u32le(0),
    u64le(1),
    u64le(1),
    u64le(central.length),
    u64le(local.length),
  );
  const locator = concat(u32le(0x07064b50), u32le(0), u64le(zip64EndOffset), u32le(1));
  const eocd = concat(
    u32le(0x06054b50),
    u16le(0),
    u16le(0),
    u16le(0xffff),
    u16le(0xffff),
    u32le(0xffffffff),
    u32le(0xffffffff),
    u16le(0),
  );
  return {
    bytes: concat(local, central, zip64End, locator, eocd),
    salt,
    verifier,
    encrypted,
    auth,
  };
}

function zipLegacyFixture(): { bytes: Uint8Array; data: Uint8Array } {
  const name = ascii("legacy.txt");
  const data = sequence(16, 0x20);
  const crc = 0x12345678;
  const local = concat(
    u32le(0x04034b50),
    u16le(20),
    u16le(1),
    u16le(0),
    u16le(0),
    u16le(0),
    u32le(crc),
    u32le(data.length),
    u32le(4),
    u16le(name.length),
    u16le(0),
    name,
    data,
  );
  const central = concat(
    u32le(0x02014b50),
    u16le(20),
    u16le(20),
    u16le(1),
    u16le(0),
    u16le(0),
    u16le(0),
    u32le(crc),
    u32le(data.length),
    u32le(4),
    u16le(name.length),
    u16le(0),
    u16le(0),
    u16le(0),
    u16le(0),
    u32le(0),
    u32le(0),
    name,
  );
  const eocd = concat(
    u32le(0x06054b50),
    u16le(0),
    u16le(0),
    u16le(1),
    u16le(1),
    u32le(central.length),
    u32le(local.length),
    u16le(0),
  );
  return { bytes: concat(local, central, eocd), data };
}

function pdfFixture(revision: 2 | 4 | 6): Uint8Array {
  const id = "01020304";
  const algorithm = revision === 2 ? 1 : revision === 4 ? 4 : 5;
  const keyLength = revision === 2 ? 40 : revision === 4 ? 128 : 256;
  const fieldLength = revision === 6 ? 48 : 32;
  const common = `/Filter /Standard /V ${algorithm} /R ${revision} /Length ${keyLength} /P -4 /O <${"20".repeat(fieldLength)}> /U <${"10".repeat(fieldLength)}>`;
  const cryptFilter =
    revision === 4 ? " /CF << /StdCF << /CFM /AESV2 /Length 16 >> >> /StmF /StdCF" : "";
  const modern =
    revision === 6
      ? ` /OE <${"30".repeat(32)}> /UE <${"40".repeat(32)}> /EncryptMetadata false`
      : "";
  return ascii(
    `%PDF-1.7\n5 0 obj\n<< ${common}${cryptFilter}${modern} >>\nendobj\ntrailer\n<< /Size 6 /Encrypt 5 0 R /ID [<${id}><${id}>] >>\n%%EOF\n`,
  );
}

function rar3HpFixture(): Uint8Array {
  const main = new Uint8Array(13);
  main[2] = 0x73;
  put(main, 3, u16le(0x80));
  put(main, 5, u16le(13));
  return concat(fromHex("526172211a0700"), main, sequence(24, 0x20));
}

function sevenNumber(value: number): Uint8Array {
  if (value >= 0x80) throw new Error("Fixture only supports short 7z numbers");
  return Uint8Array.of(value);
}

function sevenZipFixture(compressed = false): Uint8Array {
  const data = sequence(16, 0x60);
  const crc = 0x12345678;
  const properties = Uint8Array.of(0xd3, 0, 0xaa, 0xbb);
  const folder = compressed
    ? concat(
        sevenNumber(2),
        Uint8Array.of(0x24),
        fromHex("06f10701"),
        sevenNumber(properties.length),
        properties,
        Uint8Array.of(0x23),
        fromHex("030101"),
        sevenNumber(5),
        fromHex("5d00008000"),
        sevenNumber(1),
        sevenNumber(0),
      )
    : concat(
        sevenNumber(1),
        Uint8Array.of(0x24),
        fromHex("06f10701"),
        sevenNumber(properties.length),
        properties,
      );
  const next = concat(
    sevenNumber(0x17),
    sevenNumber(6),
    sevenNumber(0),
    sevenNumber(1),
    sevenNumber(9),
    sevenNumber(data.length),
    sevenNumber(0),
    sevenNumber(7),
    sevenNumber(11),
    sevenNumber(1),
    Uint8Array.of(0),
    folder,
    sevenNumber(12),
    sevenNumber(data.length),
    ...(compressed ? [sevenNumber(10)] : []),
    sevenNumber(10),
    Uint8Array.of(1),
    u32le(crc),
    sevenNumber(0),
    sevenNumber(0),
  );
  const signature = concat(
    fromHex("377abcaf271c"),
    Uint8Array.of(0, 4),
    u32le(0),
    u64le(data.length),
    u64le(next.length),
    u32le(0),
  );
  return concat(signature, data, next);
}

function mpi(bytes: Uint8Array): Uint8Array {
  return concat(u16be(bytes.length * 8), bytes);
}

function gpgSecretFixture(): {
  bytes: Uint8Array;
  encrypted: Uint8Array;
  salt: Uint8Array;
  iv: Uint8Array;
} {
  const salt = sequence(8, 0x10);
  const iv = sequence(16, 0x30);
  const encrypted = sequence(16, 0x50);
  const body = concat(
    Uint8Array.of(4),
    u32be(0),
    Uint8Array.of(1),
    mpi(Uint8Array.of(0x81)),
    mpi(Uint8Array.of(3)),
    Uint8Array.of(254, 7, 3, 2),
    salt,
    Uint8Array.of(96),
    iv,
    encrypted,
  );
  const user = ascii("Alice <alice@example.test>");
  return {
    bytes: concat(
      Uint8Array.of(0xc5, body.length),
      body,
      Uint8Array.of(0xcd, user.length),
      user,
    ),
    encrypted,
    salt,
    iv,
  };
}

function utf16Name(value: string): Uint8Array {
  const output = new Uint8Array((value.length + 1) * 2);
  for (let index = 0; index < value.length; index++)
    put(output, index * 2, u16le(value.charCodeAt(index)));
  return output;
}

function cfbDirectoryEntry(
  name: string,
  type: number,
  start: number,
  size: number,
): Uint8Array {
  const entry = new Uint8Array(128);
  const encoded = utf16Name(name);
  put(entry, 0, encoded);
  put(entry, 64, u16le(encoded.length));
  entry[66] = type;
  put(entry, 68, u32le(0xffffffff));
  put(entry, 72, u32le(0xffffffff));
  put(entry, 76, u32le(0xffffffff));
  put(entry, 116, u32le(start));
  put(entry, 120, u64le(size));
  return entry;
}

function compoundFixture(streamName: string, content: Uint8Array): Uint8Array {
  if (content.length > 4096) throw new Error("CFB fixture stream is too large");
  const stream = new Uint8Array(4096);
  put(stream, 0, content);
  const header = new Uint8Array(512);
  put(header, 0, fromHex("d0cf11e0a1b11ae1"));
  put(header, 24, u16le(0x3e));
  put(header, 26, u16le(3));
  put(header, 28, u16le(0xfffe));
  put(header, 30, u16le(9));
  put(header, 32, u16le(6));
  put(header, 44, u32le(1));
  put(header, 48, u32le(1));
  put(header, 56, u32le(4096));
  put(header, 60, u32le(CFB_END));
  put(header, 68, u32le(CFB_END));
  for (let offset = 76; offset < 512; offset += 4) put(header, offset, u32le(0xffffffff));
  put(header, 76, u32le(0));
  const fat = new Uint8Array(512);
  for (let offset = 0; offset < 512; offset += 4) put(fat, offset, u32le(0xffffffff));
  put(fat, 0, u32le(0xfffffffd));
  put(fat, 4, u32le(CFB_END));
  for (let sector = 2; sector < 9; sector++) put(fat, sector * 4, u32le(sector + 1));
  put(fat, 9 * 4, u32le(CFB_END));
  const directory = new Uint8Array(512);
  put(directory, 0, cfbDirectoryEntry("Root Entry", 5, CFB_END, 0));
  put(directory, 128, cfbDirectoryEntry(streamName, 2, 2, stream.length));
  return concat(header, fat, directory, stream);
}

function officeAgileFixture(): {
  bytes: Uint8Array;
  salt: Uint8Array;
  verifier: Uint8Array;
  hash: Uint8Array;
} {
  const salt = sequence(16, 0x10);
  const verifier = sequence(16, 0x30);
  const hash = sequence(64, 0x50);
  const b64 = (value: Uint8Array) => Buffer.from(value).toString("base64");
  const xml = `<encryption><keyEncryptors><keyEncryptor><c:encryptedKey encryptedKeyValue="certificate-recipient"/></keyEncryptor><keyEncryptor><p:encryptedKey spinCount="100000" saltSize="16" blockSize="16" keyBits="256" hashAlgorithm="SHA512" cipherAlgorithm="AES" saltValue="${b64(salt)}" encryptedVerifierHashInput="${b64(verifier)}" encryptedVerifierHashValue="${b64(hash)}"/></keyEncryptor></keyEncryptors></encryption>`;
  const info = concat(u16le(4), u16le(4), u32le(0x40), ascii(xml));
  return { bytes: compoundFixture("EncryptionInfo", info), salt, verifier, hash };
}

function officeLegacyFixture(): {
  bytes: Uint8Array;
  salt: Uint8Array;
  verifier: Uint8Array;
  hash: Uint8Array;
} {
  const salt = sequence(16, 0x11);
  const verifier = sequence(16, 0x31);
  const hash = sequence(16, 0x51);
  const filePass = concat(fromHex("010001000100"), salt, verifier, hash);
  const workbook = concat(u16le(0x2f), u16le(filePass.length), filePass);
  return { bytes: compoundFixture("Workbook", workbook), salt, verifier, hash };
}

function officeExcelCryptoApiFixture(): {
  bytes: Uint8Array;
  salt: Uint8Array;
  verifier: Uint8Array;
  hash: Uint8Array;
} {
  const salt = sequence(16, 0x12);
  const verifier = sequence(16, 0x32);
  const hash = sequence(20, 0x52);
  const filePass = concat(
    u16le(1),
    u16le(2),
    u16le(2),
    u32le(0),
    u32le(32),
    u32le(0),
    u32le(0),
    u32le(0x6801),
    u32le(0x8004),
    u32le(128),
    u32le(1),
    u32le(0),
    u32le(0),
    u32le(16),
    salt,
    verifier,
    u32le(hash.length),
    hash,
  );
  const workbook = concat(u16le(0x2f), u16le(filePass.length), filePass);
  return { bytes: compoundFixture("Workbook", workbook), salt, verifier, hash };
}

async function rar5Fixture(): Promise<{
  bytes: Uint8Array;
  salt: Uint8Array;
  check: Uint8Array;
  iv: Uint8Array;
}> {
  const salt = sequence(16, 0x12);
  const check = sequence(8, 0x32);
  const iv = sequence(16, 0x52);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", Uint8Array.from(check).buffer),
  );
  const payload = concat(Uint8Array.of(4, 0, 0, 1, 15), salt, check, digest.subarray(0, 4));
  const cryptHeader = concat(u32le(0), Uint8Array.of(payload.length), payload);
  return { bytes: concat(fromHex("526172211a070100"), cryptHeader, iv), salt, check, iv };
}

function armorGpg(bytes: Uint8Array): Uint8Array {
  let crc = 0xb704ce;
  for (const byte of bytes) {
    crc ^= byte << 16;
    for (let bit = 0; bit < 8; bit++)
      crc = (crc << 1) ^ ((crc & 0x1000000) !== 0 ? 0x1864cfb : 0);
  }
  const check = Uint8Array.of((crc >>> 16) & 0xff, (crc >>> 8) & 0xff, crc & 0xff);
  return ascii(
    `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${Buffer.from(bytes).toString("base64")}\n=${Buffer.from(check).toString("base64")}\n-----END PGP PRIVATE KEY BLOCK-----\n`,
  );
}

describe(`John extractor compatibility fixtures (${UPSTREAM_COMMIT})`, () => {
  it("matches ssh2john for openssh-key-v1 and legacy encrypted PEM", async () => {
    const modern = openSshFixture();
    await expect(
      runExtractor("ssh2john", trackedSource(modern.pem, "id_ed25519")),
    ).resolves.toBe(
      `id_ed25519:$sshng$6$16$${hex(modern.salt)}$${modern.blob.length}$${hex(modern.blob)}$23$${modern.offset}\n`,
    );
    const legacy = legacySshFixture();
    await expect(
      runExtractor("ssh2john", trackedSource(legacy.pem, "id_rsa.pem")),
    ).resolves.toBe(
      `id_rsa.pem:$sshng$5$16$${hex(legacy.iv).toUpperCase()}$${legacy.der.length}$${hex(legacy.der)}\n`,
    );
  });

  it("matches truecrypt2john primary, hidden, and boot descriptors with source names", async () => {
    const bytes = sequence(65_536 + 512);
    const primary = bytes.subarray(0, 512);
    const hidden = bytes.subarray(65_536);
    const normal = await runExtractor(
      "truecrypt2john",
      trackedSource(bytes, "images/vault.tc"),
    );
    expect(normal).toBe(
      [
        `vault.tc:truecrypt_RIPEMD_160$${hex(primary)}:normal::::images/vault.tc`,
        `vault.tc:truecrypt_SHA_512$${hex(primary)}:normal::::images/vault.tc`,
        `vault.tc:truecrypt_WHIRLPOOL$${hex(primary)}:normal::::images/vault.tc`,
        `vault.tc:truecrypt_RIPEMD_160$${hex(hidden)}:hidden::::images/vault.tc`,
        `vault.tc:truecrypt_SHA_512$${hex(hidden)}:hidden::::images/vault.tc`,
        `vault.tc:truecrypt_WHIRLPOOL$${hex(hidden)}:hidden::::images/vault.tc`,
      ].join("\n") + "\n",
    );
    await expect(
      runExtractor("truecrypt2john", trackedSource(bytes, "system.tc"), { "boot-mode": true }),
    ).resolves.toBe(
      [
        `system.tc:truecrypt_RIPEMD_160_BOOT$${hex(primary)}:normal::::system.tc`,
        `system.tc:truecrypt_RIPEMD_160$${hex(hidden)}:hidden::::system.tc`,
        `system.tc:truecrypt_SHA_512$${hex(hidden)}:hidden::::system.tc`,
        `system.tc:truecrypt_WHIRLPOOL$${hex(hidden)}:hidden::::system.tc`,
      ].join("\n") + "\n",
    );
  });

  it("matches luks2john for the selected lowest-iteration LUKS1 keyslot", async () => {
    const fixture = luksFixture();
    const expected = `$luks$1$592$${hex(fixture.bytes.subarray(0, 592))}$512$${Buffer.from(fixture.material).toString("base64")}$${hex(fixture.bytes.subarray(112, 132))}\n`;
    await expect(
      runExtractor("luks2john", trackedSource(fixture.bytes, "volume.img")),
    ).resolves.toBe(expected);
  });

  it("matches dmg2john v1 and v2 descriptors", async () => {
    const v1 = dmgV1Fixture();
    await expect(
      runExtractor("dmg2john", trackedSource(v1, "folder:archive.dmg")),
    ).resolves.toBe(
      `folder archive.dmg:$dmg$1*4*01020304*8*${hex(sequence(8, 0x10))}*12*${hex(sequence(12, 0x30))}*1000::::folder archive.dmg\n`,
    );
    const v2 = dmgV2Fixture();
    await expect(
      runExtractor("dmg2john", trackedSource(v2.bytes, "archive.dmg")),
    ).resolves.toBe(
      `archive.dmg:$dmg$2*4*${hex(v2.salt)}*32*${hex(v2.iv)}*3*${hex(v2.blob)}*0*8192*${hex(v2.data)}*1*${hex(v2.data.subarray(0, 4096))}*1500::::archive.dmg\n`,
    );
  });

  it("matches bitlocker2john password and recovery descriptor versions", async () => {
    for (const [protection, versions] of [
      [0x2000, [0, 1]],
      [0x800, [2, 3]],
    ] as const) {
      const fixture = bitLockerFixture(protection);
      const expected =
        versions
          .map(
            (version) =>
              `$bitlocker$${version}$16$${hex(fixture.salt)}$1048576$12$${hex(fixture.nonce)}$${fixture.encrypted.length}$${hex(fixture.encrypted)}`,
          )
          .join("\n") + "\n";
      await expect(
        runExtractor("bitlocker2john", trackedSource(fixture.bytes, "bitlocker.img")),
      ).resolves.toBe(expected);
    }
  });

  it("matches keepass2john KDBX 3.0, 3.1, 4.0, and 4.1 descriptors", async () => {
    const v3 = kdbx3Fixture();
    await expect(
      runExtractor("kdbx2john", trackedSource(v3.bytes, "vault.kdbx")),
    ).resolves.toBe(
      `vault:$keepass$*2*6000*0*${hex(v3.master)}*${hex(v3.transform)}*${hex(v3.iv)}*${hex(v3.start)}*${hex(v3.encrypted)}\n`,
    );
    const v30 = kdbx3Fixture(0x00030000);
    await expect(
      runExtractor("kdbx2john", trackedSource(v30.bytes, "vault30.kdbx")),
    ).resolves.toBe(
      `vault30:$keepass$*2*6000*0*${hex(v30.master)}*${hex(v30.transform)}*${hex(v30.iv)}*${hex(v30.start)}*${hex(v30.encrypted)}\n`,
    );
    const v4 = await kdbx4Fixture();
    await expect(
      runExtractor("kdbx2john", trackedSource(v4.bytes, "vault4.kdbx")),
    ).resolves.toBe(
      `vault4:$keepass$*4*3*ef636ddf*4194304*19*2*${hex(v4.master)}*${hex(v4.seed)}*${hex(v4.header)}*${hex(v4.hmac)}\n`,
    );
    const v40 = await kdbx4Fixture(0x00040000);
    await expect(
      runExtractor("kdbx2john", trackedSource(v40.bytes, "vault40.kdbx")),
    ).resolves.toBe(
      `vault40:$keepass$*4*3*ef636ddf*4194304*19*2*${hex(v40.master)}*${hex(v40.seed)}*${hex(v40.header)}*${hex(v40.hmac)}\n`,
    );
  });

  it("matches zip2john WinZip AES descriptors for ZIP and ZIP64", async () => {
    for (const zip64 of [false, true]) {
      const fixture = zipAesFixture(zip64);
      await expect(
        runExtractor("zip2john", trackedSource(fixture.bytes, "folder/archive.zip")),
      ).resolves.toBe(
        `archive.zip/secret.txt:$zip2$*0*1*0*${hex(fixture.salt)}*${hex(fixture.verifier)}*10*${hex(fixture.encrypted)}*${hex(fixture.auth)}*$/zip2$:secret.txt:archive.zip:folder/archive.zip\n`,
      );
    }
  });

  it("matches zip2john traditional ZipCrypto descriptors", async () => {
    const fixture = zipLegacyFixture();
    await expect(
      runExtractor("zip2john", trackedSource(fixture.bytes, "legacy.zip")),
    ).resolves.toBe(
      `legacy.zip/legacy.txt:$pkzip$1*1*2*0*10*4*12345678*0*28*0*10*1234*${hex(fixture.data)}*$/pkzip$:legacy.txt:legacy.zip::legacy.zip\n`,
    );
  });

  it("matches office2john agile Office 2013 descriptors", async () => {
    const fixture = officeAgileFixture();
    await expect(
      runExtractor("office2john", trackedSource(fixture.bytes, "report.docx")),
    ).resolves.toBe(
      `report.docx:$office$*2013*100000*256*16*${hex(fixture.salt)}*${hex(fixture.verifier)}*${hex(fixture.hash.subarray(0, 32))}\n`,
    );
  });

  it("matches office2john legacy Excel standard RC4 descriptors", async () => {
    const fixture = officeLegacyFixture();
    await expect(
      runExtractor("office2john", trackedSource(fixture.bytes, "legacy.xls")),
    ).resolves.toBe(
      `legacy.xls:$oldoffice$0*${hex(fixture.salt)}*${hex(fixture.verifier)}*${hex(fixture.hash)}\n`,
    );
  });

  it("matches office2john Excel CryptoAPI descriptors after the FILEPASS marker", async () => {
    const fixture = officeExcelCryptoApiFixture();
    await expect(
      runExtractor("office2john", trackedSource(fixture.bytes, "cryptoapi.xls")),
    ).resolves.toBe(
      `cryptoapi.xls:$oldoffice$4*${hex(fixture.salt)}*${hex(fixture.verifier)}*${hex(fixture.hash)}\n`,
    );
  });

  it("matches pdf2john standard-handler revisions 2, 4, and 6", async () => {
    await expect(
      runExtractor("pdf2john", trackedSource(pdfFixture(2), "legacy.pdf")),
    ).resolves.toBe(
      `$pdf$1*2*40*-4*1*4*01020304*32*${"10".repeat(32)}*32*${"20".repeat(32)}\n`,
    );
    await expect(
      runExtractor("pdf2john", trackedSource(pdfFixture(4), "aes128.pdf")),
    ).resolves.toBe(
      `$pdf$4*4*128*-4*1*4*01020304*32*${"10".repeat(32)}*32*${"20".repeat(32)}\n`,
    );
    await expect(
      runExtractor("pdf2john", trackedSource(pdfFixture(6), "modern.pdf")),
    ).resolves.toBe(
      `$pdf$5*6*256*-4*0*4*01020304*48*${"10".repeat(48)}*48*${"20".repeat(48)}*32*${"40".repeat(32)}*32*${"30".repeat(32)}\n`,
    );
  });

  it("matches rar2john RAR3 encrypted-header descriptors", async () => {
    await expect(
      runExtractor("rar2john", trackedSource(rar3HpFixture(), "archives/secret.rar")),
    ).resolves.toBe(
      `secret.rar:$RAR3$*0*${hex(sequence(8, 0x20))}*${hex(sequence(16, 0x28))}:0::::archives/secret.rar\n`,
    );
  });

  it("matches rar2john RAR5 encrypted-header descriptors", async () => {
    const fixture = await rar5Fixture();
    await expect(
      runExtractor("rar2john", trackedSource(fixture.bytes, "secret5.rar")),
    ).resolves.toBe(
      `secret5.rar:$rar5$16$${hex(fixture.salt)}$15$${hex(fixture.iv)}$8$${hex(fixture.check)}\n`,
    );
  });

  it("matches 7z2john encrypted-header folder metadata", async () => {
    await expect(
      runExtractor("7z2john", trackedSource(sevenZipFixture(), "secret.7z")),
    ).resolves.toBe(
      `secret.7z:$7z$0$19$1$aa$1$bb${"00".repeat(15)}$305419896$16$16$${hex(sequence(16, 0x60))}\n`,
    );
    await expect(
      runExtractor("7z2john", trackedSource(sevenZipFixture(true), "compressed.7z")),
    ).resolves.toBe(
      `compressed.7z:$7z$1$19$1$aa$1$bb${"00".repeat(15)}$305419896$16$16$${hex(sequence(16, 0x60))}$10$5d00008000\n`,
    );
  });

  it("matches gpg2john binary encrypted secret-key descriptors", async () => {
    const fixture = gpgSecretFixture();
    await expect(
      runExtractor("gpg2john", trackedSource(fixture.bytes, "alice.gpg")),
    ).resolves.toBe(
      `Alice:$gpg$*1*16*8*${hex(fixture.encrypted)}*3*254*2*7*16*${hex(fixture.iv)}*65536*${hex(fixture.salt)}:::Alice <alice@example.test>::alice.gpg\n`,
    );
    await expect(
      runExtractor("gpg2john", trackedSource(armorGpg(fixture.bytes), "alice.asc")),
    ).resolves.toBe(
      `Alice:$gpg$*1*16*8*${hex(fixture.encrypted)}*3*254*2*7*16*${hex(fixture.iv)}*65536*${hex(fixture.salt)}:::Alice <alice@example.test>::alice.asc\n`,
    );
  });
});

describe("John extractor hardening", () => {
  it("rejects truncation for every extractor", async () => {
    for (const id of [
      "ssh2john",
      "truecrypt2john",
      "luks2john",
      "dmg2john",
      "bitlocker2john",
      "kdbx2john",
      "zip2john",
      "office2john",
      "pdf2john",
      "rar2john",
      "7z2john",
      "gpg2john",
    ]) {
      const tool = passwordArtifactToolDefinition(id);
      const result = await tool.computeFile!(
        tool.createSpec(),
        trackedSource(new Uint8Array(3), "short.bin"),
      );
      expect(result.error, id).toMatch(/truncated|private.key|PEM|magic|signature|header/i);
    }
  });

  it("rejects corrupted magic, versions, declared lengths, and overflow-style offsets", async () => {
    const luks = luksFixture().bytes;
    luks[7] = 2;
    await expect(runExtractor("luks2john", trackedSource(luks, "bad.luks"))).rejects.toThrow(
      /version 2/i,
    );

    const overflowingLuks = luksFixture().bytes;
    put(overflowingLuks, 108, u32be(0xffffffff));
    put(overflowingLuks, 252, u32be(0xffffffff));
    await expect(
      runExtractor("luks2john", trackedSource(overflowingLuks, "overflow.luks")),
    ).rejects.toThrow(/overflows/i);

    const dmg = dmgV2Fixture().bytes;
    put(dmg, 228, u32be(0xffffffff));
    await expect(runExtractor("dmg2john", trackedSource(dmg, "bad.dmg"))).rejects.toThrow(
      /blob length/i,
    );

    const unsafeDmgOffset = dmgV2Fixture().bytes;
    put(unsafeDmgOffset, 64, fromHex("0020000000000000"));
    await expect(
      runExtractor("dmg2john", trackedSource(unsafeDmgOffset, "overflow.dmg")),
    ).rejects.toThrow(/safe integer/i);

    const bitlocker = bitLockerFixture(0x2000).bytes;
    put(bitlocker, 0x200 + 64, u32le(0xffffffff));
    await expect(
      runExtractor("bitlocker2john", trackedSource(bitlocker, "bad.img")),
    ).rejects.toThrow(/at most|metadata/i);

    const kdbx = kdbx3Fixture().bytes;
    put(kdbx, 13, u16le(0xffff));
    await expect(runExtractor("kdbx2john", trackedSource(kdbx, "bad.kdbx"))).rejects.toThrow(
      /truncated|end|header/i,
    );

    const ssh = openSshFixture();
    const text = new TextDecoder()
      .decode(ssh.pem)
      .replace("b3BlbnNzaC1rZXktdjEA", "b3BlbnNzaC1rZXktdjEB");
    await expect(
      runExtractor("ssh2john", trackedSource(ascii(text), "bad.key")),
    ).rejects.toThrow(/magic|Base64/i);

    await expect(
      runExtractor("bitlocker2john", trackedSource(new Uint8Array(16), "overflow.img"), {
        "partition-offset": Number.MAX_SAFE_INTEGER,
      }),
    ).rejects.toThrow(/overflows/i);

    const zip = zipAesFixture().bytes;
    put(zip, zip.length - 6, u32le(0xffffffff));
    await expect(runExtractor("zip2john", trackedSource(zip, "overflow.zip"))).rejects.toThrow(
      /ZIP64|beyond|safe integer/i,
    );

    const seven = sevenZipFixture();
    put(seven, 12, fromHex("ffffffffffffff7f"));
    await expect(runExtractor("7z2john", trackedSource(seven, "overflow.7z"))).rejects.toThrow(
      /beyond|truncated|safe integer/i,
    );

    const rar = await rar5Fixture();
    rar.bytes[12] = 1;
    await expect(runExtractor("rar2john", trackedSource(rar.bytes, "bad.rar"))).rejects.toThrow(
      /boundary|truncated/i,
    );

    const gpg = gpgSecretFixture().bytes;
    gpg[1] = 0xbf;
    await expect(runExtractor("gpg2john", trackedSource(gpg, "bad.gpg"))).rejects.toThrow(
      /truncated|invalid/i,
    );
  });

  it("explicitly rejects unsupported container versions and encryption cases", async () => {
    const dmg = dmgV2Fixture().bytes;
    put(dmg, 8, u32be(3));
    await expect(runExtractor("dmg2john", trackedSource(dmg, "v3.dmg"))).rejects.toThrow(
      /version 3/i,
    );

    const kdbx = kdbx3Fixture().bytes;
    put(kdbx, 8, u32le(0x00020000));
    await expect(runExtractor("kdbx2john", trackedSource(kdbx, "v2.kdbx"))).rejects.toThrow(
      /version 0x00020000/i,
    );

    const ssh = openSshFixture("chacha20-poly1305@openssh.com");
    await expect(
      runExtractor("ssh2john", trackedSource(ssh.pem, "unsupported.key")),
    ).rejects.toThrow(/unsupported/i);

    const pdf = new TextEncoder().encode(
      "%PDF-1.7\n1 0 obj << /Filter /Adobe.PubSec >> endobj\ntrailer << /Encrypt 1 0 R /ID [<00><00>] >>",
    );
    await expect(runExtractor("pdf2john", trackedSource(pdf, "pubsec.pdf"))).rejects.toThrow(
      /non-Standard/i,
    );

    const volume = rar3HpFixture();
    put(volume, 10, u16le(0x81));
    await expect(runExtractor("rar2john", trackedSource(volume, "volume.rar"))).rejects.toThrow(
      /multipart/i,
    );
  });

  it("rejects a corrupt KDBX4 header hash", async () => {
    const fixture = await kdbx4Fixture();
    fixture.bytes[fixture.header.length] = fixture.bytes[fixture.header.length]! ^ 1;
    await expect(
      runExtractor("kdbx2john", trackedSource(fixture.bytes, "bad.kdbx")),
    ).rejects.toThrow(/hash mismatch/i);
  });

  it("sanitizes John field delimiters in source names", async () => {
    const ssh = openSshFixture();
    await expect(
      runExtractor("ssh2john", trackedSource(ssh.pem, "folder:key.pem")),
    ).resolves.toMatch(/^folder key\.pem:\$sshng\$/);

    const truecrypt = sequence(512);
    await expect(
      runExtractor("truecrypt2john", trackedSource(truecrypt, "folder:vault.tc")),
    ).resolves.toContain(":normal::::folder vault.tc\n");

    const kdbx = kdbx3Fixture();
    await expect(
      runExtractor("kdbx2john", trackedSource(kdbx.bytes, "vault:name.kdbx")),
    ).resolves.toMatch(/^vault name:\$keepass\$/);
  });

  it("uses bounded random access instead of reading whole large disk/container files", async () => {
    const gibibyte = 1024 ** 3;
    const cases: Array<[string, TrackedSource]> = [
      ["truecrypt2john", trackedSource(sequence(65_536 + 512), "large.tc", gibibyte)],
      ["luks2john", trackedSource(luksFixture().bytes, "large.luks", gibibyte)],
      ["dmg2john", trackedSource(dmgV2Fixture().bytes, "large.dmg", gibibyte)],
      ["bitlocker2john", trackedSource(bitLockerFixture(0x2000).bytes, "large.img", gibibyte)],
      ["kdbx2john", trackedSource(kdbx3Fixture().bytes, "large.kdbx", gibibyte)],
    ];
    for (const [id, source] of cases) {
      await expect(runExtractor(id, source)).resolves.toContain("$");
      const bytesRead = source.reads.reduce((sum, read) => sum + read.length, 0);
      expect(bytesRead, `${id} bytes read`).toBeLessThan(100_000);
      expect(
        Math.max(...source.reads.map((read) => read.length)),
        `${id} largest read`,
      ).toBeLessThanOrEqual(source.maxReadBytes);
    }
  });
});
