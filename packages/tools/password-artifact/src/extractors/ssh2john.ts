import type { ToolFileSource } from "@ocs/engine";
import {
  ascii,
  CheckedReader,
  decodeBase64,
  hex,
  johnName,
  readChunked,
  sourceName,
} from "./binary";

const MAX_SSH_FILE_BYTES = 4 * 1024 * 1024;
const OPENSSH_MAGIC = Uint8Array.of(
  0x6f,
  0x70,
  0x65,
  0x6e,
  0x73,
  0x73,
  0x68,
  0x2d,
  0x6b,
  0x65,
  0x79,
  0x2d,
  0x76,
  0x31,
  0,
);

type KeyType = "RSA" | "DSA" | "EC" | "OPENSSH";

interface PemBlock {
  type: KeyType;
  headers: Map<string, string>;
  data: Uint8Array;
}

const LEGACY_CIPHERS: Readonly<Record<string, { keySize: number; blockSize: number }>> = {
  "AES-128-CBC": { keySize: 16, blockSize: 16 },
  "DES-EDE3-CBC": { keySize: 24, blockSize: 8 },
  "AES-256-CBC": { keySize: 32, blockSize: 16 },
  "AES-192-CBC": { keySize: 24, blockSize: 16 },
  "DES-CBC": { keySize: 8, blockSize: 8 },
};

function parsePem(text: string): PemBlock[] {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const blocks: PemBlock[] = [];
  const beginPattern = /^-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----$/;
  for (let index = 0; index < lines.length; index++) {
    const match = beginPattern.exec(lines[index]!);
    if (!match) continue;
    const type = match[1] as KeyType;
    const headers = new Map<string, string>();
    index++;
    while (index < lines.length) {
      const line = lines[index]!;
      const header = /^([^:]+): (.*)$/.exec(line);
      if (!header) break;
      const key = header[1]!.toLowerCase();
      if (headers.has(key))
        throw new Error(`SSH PEM block has duplicate ${header[1]} headers.`);
      headers.set(key, header[2]!.trim());
      index++;
    }
    if (lines[index] === "") index++;
    const body: string[] = [];
    const end = `-----END ${type} PRIVATE KEY-----`;
    while (index < lines.length && lines[index] !== end) {
      const line = lines[index]!;
      if (!/^[A-Za-z0-9+/=]+$/.test(line))
        throw new Error(`SSH ${type} PEM body is malformed.`);
      body.push(line);
      index++;
    }
    if (index >= lines.length)
      throw new Error(`SSH ${type} PEM block has no matching end marker.`);
    blocks.push({ type, headers, data: decodeBase64(body.join(""), `SSH ${type} PEM body`) });
  }
  if (blocks.length === 0)
    throw new Error("No RSA, DSA, EC, or OpenSSH private-key PEM block was found.");
  return blocks;
}

function legacyMode(type: KeyType, cipherName: string, keySize: number): number {
  if (keySize === 24 && cipherName === "AES-192-CBC" && (type === "RSA" || type === "DSA"))
    return 4;
  if (keySize === 32 && cipherName === "AES-256-CBC") return 5;
  if (keySize === 24) return 0;
  if (keySize === 8) return 6;
  if (keySize === 16 && (type === "RSA" || type === "DSA")) return 1;
  if (keySize === 16 && type === "EC") return 3;
  throw new Error(`SSH ${type} key uses an unsupported ${cipherName} cipher combination.`);
}

function extractLegacy(block: PemBlock): string {
  if (!block.headers.has("proc-type"))
    throw new Error(`SSH ${block.type} private key is not encrypted.`);
  if (block.headers.get("proc-type") !== "4,ENCRYPTED") {
    throw new Error(`SSH ${block.type} private key has an unsupported Proc-Type header.`);
  }
  const dek = block.headers.get("dek-info");
  if (!dek) throw new Error(`SSH ${block.type} private key has no DEK-Info header.`);
  const parts = dek.split(",");
  if (parts.length !== 2) throw new Error(`SSH ${block.type} DEK-Info header is malformed.`);
  const cipherName = parts[0]!;
  const cipher = LEGACY_CIPHERS[cipherName];
  if (!cipher) throw new Error(`SSH private-key cipher ${cipherName} is unsupported.`);
  const saltHex = parts[1]!;
  if (!/^[0-9a-fA-F]+$/.test(saltHex) || saltHex.length !== cipher.blockSize * 2) {
    throw new Error(
      `SSH ${cipherName} IV must contain exactly ${cipher.blockSize} bytes of hex.`,
    );
  }
  if (block.data.length === 0 || block.data.length % cipher.blockSize !== 0) {
    throw new Error(`SSH ${cipherName} ciphertext length is not block-aligned.`);
  }
  const salt = saltHex;
  return `$sshng$${legacyMode(block.type, cipherName, cipher.keySize)}$${salt.length / 2}$${salt}$${block.data.length}$${hex(block.data)}`;
}

function extractOpenSsh(block: PemBlock): string {
  const reader = new CheckedReader(block.data, "OpenSSH private key");
  const magic = reader.take(OPENSSH_MAGIC.length, "magic");
  if (hex(magic) !== hex(OPENSSH_MAGIC))
    throw new Error("OpenSSH private key magic is invalid.");
  const cipherName = ascii(reader.sshString("cipher name"), "OpenSSH cipher name");
  if (cipherName === "none") throw new Error("OpenSSH private key is not encrypted.");
  if (cipherName !== "aes256-cbc" && cipherName !== "aes256-ctr") {
    throw new Error(`OpenSSH private-key cipher ${cipherName} is unsupported.`);
  }
  const kdfName = ascii(reader.sshString("KDF name"), "OpenSSH KDF name");
  if (kdfName !== "bcrypt")
    throw new Error(`OpenSSH private-key KDF ${kdfName} is unsupported.`);
  const kdf = new CheckedReader(reader.sshString("KDF options"), "OpenSSH bcrypt options");
  const saltBytes = kdf.sshString("salt");
  if (saltBytes.length !== 16) throw new Error("OpenSSH bcrypt salt must be exactly 16 bytes.");
  const encodedRounds = kdf.u32be("rounds");
  kdf.finish();
  const rounds = encodedRounds === 0 ? 16 : encodedRounds;
  const keyCount = reader.u32be("key count");
  if (keyCount !== 1)
    throw new Error(`OpenSSH private keys with ${keyCount} keys are unsupported.`);
  const publicKey = reader.sshString("public key");
  if (publicKey.length === 0) throw new Error("OpenSSH public-key blob is empty.");
  const encryptedLengthPosition = reader.position;
  const encrypted = reader.sshString("encrypted private key");
  if (encrypted.length === 0 || encrypted.length % 16 !== 0) {
    throw new Error("OpenSSH encrypted private-key blob is not AES block-aligned.");
  }
  reader.finish();
  const ciphertextOffset = encryptedLengthPosition + 4;
  const mode = cipherName === "aes256-cbc" ? 2 : 6;
  return `$sshng$${mode}$16$${hex(saltBytes)}$${block.data.length}$${hex(block.data)}$${rounds}$${ciphertextOffset}`;
}

/** Matches run/ssh2john.py for its encrypted legacy PEM and openssh-key-v1 cases. */
export async function extractSsh(source: ToolFileSource): Promise<string> {
  const bytes = await readChunked(
    source,
    0,
    source.metadata.size,
    MAX_SSH_FILE_BYTES,
    "SSH private key file",
  );
  const blocks = parsePem(ascii(bytes, "SSH private key file"));
  const name = johnName(sourceName(source));
  const lines = blocks.map((block, index) => {
    const suffix = blocks.length === 1 ? "" : `_${index + 1}`;
    const descriptor = block.type === "OPENSSH" ? extractOpenSsh(block) : extractLegacy(block);
    return `${name}${suffix}:${descriptor}`;
  });
  return `${lines.join("\n")}\n`;
}
