/**
 * age (Actually Good Encryption) -- modern file encryption container format.
 * Specification: https://age-encryption.org/v1
 *
 * Designed by Filippo Valsorda:
 *  - Small, explicit headers with recipient stanzas (X25519 and scrypt passphrase).
 *  - HKDF-SHA256 key schedule for wrap keys, header HMAC, and payload key.
 *  - ChaCha20-Poly1305 authenticated payload streaming in 64 KiB chunks with chunk counter nonces.
 *  - Bech32-encoded recipient keys (age1...) and identities (AGE-SECRET-KEY-1...).
 */

import { encodeBech32, decodeBech32 } from "./bech32";

export const AGE_VERSION_LINE = "age-encryption.org/v1";
export const AGE_CHUNK_SIZE = 65536; // 64 KiB
export const AGE_TAG_SIZE = 16;
export const AGE_FILE_KEY_SIZE = 16;
export const AGE_PAYLOAD_NONCE_SIZE = 16;
export const AGE_MAX_HEADER_SIZE = 2 * 1024 * 1024;
export const AGE_MAX_SCRYPT_LOG_N = 22;

const AGE_MAX_CHUNK_INDEX = (1n << 88n) - 1n;
const AGE_SCRYPT_LABEL = new TextEncoder().encode("age-encryption.org/v1/scrypt");

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_REV = new Uint8Array(256);
for (let i = 0; i < B64_CHARS.length; i++) B64_REV[B64_CHARS.charCodeAt(i)] = i;

export function encodeBase64Raw(bytes: Uint8Array): string {
  let res = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    res +=
      B64_CHARS[(n >> 18) & 63]! +
      B64_CHARS[(n >> 12) & 63]! +
      B64_CHARS[(n >> 6) & 63]! +
      B64_CHARS[n & 63]!;
  }
  if (i < bytes.length) {
    const b0 = bytes[i]!;
    if (i + 1 < bytes.length) {
      const b1 = bytes[i + 1]!;
      const n = (b0 << 16) | (b1 << 8);
      res +=
        B64_CHARS[(n >> 18) & 63]! + B64_CHARS[(n >> 12) & 63]! + B64_CHARS[(n >> 6) & 63]!;
    } else {
      const n = b0 << 16;
      res += B64_CHARS[(n >> 18) & 63]! + B64_CHARS[(n >> 12) & 63]!;
    }
  }
  return res;
}

export function decodeBase64Raw(str: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*$/.test(str) || str.length % 4 === 1) {
    throw new Error("Invalid raw base64 encoding.");
  }
  const out: number[] = [];
  let i = 0;
  for (; i + 3 < str.length; i += 4) {
    const n =
      (B64_REV[str.charCodeAt(i)]! << 18) |
      (B64_REV[str.charCodeAt(i + 1)]! << 12) |
      (B64_REV[str.charCodeAt(i + 2)]! << 6) |
      B64_REV[str.charCodeAt(i + 3)]!;
    out.push((n >> 16) & 255, (n >> 8) & 255, n & 255);
  }
  const rem = str.length - i;
  if (rem === 2) {
    const n = (B64_REV[str.charCodeAt(i)]! << 18) | (B64_REV[str.charCodeAt(i + 1)]! << 12);
    out.push((n >> 16) & 255);
  } else if (rem === 3) {
    const n =
      (B64_REV[str.charCodeAt(i)]! << 18) |
      (B64_REV[str.charCodeAt(i + 1)]! << 12) |
      (B64_REV[str.charCodeAt(i + 2)]! << 6);
    out.push((n >> 16) & 255, (n >> 8) & 255);
  }
  const decoded = new Uint8Array(out);
  if (encodeBase64Raw(decoded) !== str) {
    throw new Error("Invalid non-canonical raw base64 encoding.");
  }
  return decoded;
}

export interface AgeCrypto {
  chacha20poly1305Encrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
  ): Uint8Array;
  chacha20poly1305Decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
  ): Uint8Array;
  x25519GetPublicKey(privateKey: Uint8Array): Uint8Array;
  x25519SharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array;
  hkdfSha256(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: string | Uint8Array,
    length: number,
  ): Uint8Array;
  hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array;
  scrypt(password: string | Uint8Array, salt: Uint8Array, logN: number): Uint8Array;
}

export interface AgeKeyPair {
  recipient: string; // age1...
  identity: string; // AGE-SECRET-KEY-1...
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function parseAgeRecipient(recipientStr: string): Uint8Array {
  const clean = recipientStr.trim();
  if (clean.toLowerCase().startsWith("age1")) {
    const dec = decodeBech32(clean);
    if (dec.hrp !== "age" || dec.data.length !== 32) {
      throw new Error(`Invalid age recipient Bech32 string: expected 32 bytes for hrp 'age'.`);
    }
    return dec.data;
  }
  if (/^[0-9a-fA-F]{64}$/.test(clean)) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  throw new Error(`Unrecognized age recipient key format. Expected age1... Bech32 string.`);
}

export function parseAgeIdentity(identityStr: string): Uint8Array {
  const clean = identityStr.trim();
  if (clean.toUpperCase().startsWith("AGE-SECRET-KEY-1")) {
    const dec = decodeBech32(clean.toLowerCase());
    if (dec.hrp !== "age-secret-key-" || dec.data.length !== 32) {
      throw new Error(`Invalid age identity Bech32 string: expected 32 bytes.`);
    }
    return dec.data;
  }
  if (/^[0-9a-fA-F]{64}$/.test(clean)) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  throw new Error(`Unrecognized age identity format. Expected AGE-SECRET-KEY-1... string.`);
}

export function formatAgeRecipient(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error("Age public key must be 32 bytes.");
  return encodeBech32("age", publicKey);
}

export function formatAgeIdentity(privateKey: Uint8Array): string {
  if (privateKey.length !== 32) throw new Error("Age private key must be 32 bytes.");
  return encodeBech32("age-secret-key-", privateKey).toUpperCase();
}

export interface AgeEncryptOptions {
  recipients?: string[];
  passphrase?: string;
  fileKey?: Uint8Array;
  ephemeralKey?: Uint8Array;
  scryptSalt?: Uint8Array;
  scryptLogN?: number; // default 14
  payloadNonce?: Uint8Array;
}

export interface AgeDecryptOptions {
  identities?: string[];
  passphrase?: string;
}

export interface AgeIncrementalEncryptOptions extends AgeEncryptOptions {
  armor?: boolean;
}

function makeChunkNonce(chunkIndex: bigint, isLast: boolean): Uint8Array {
  if (chunkIndex < 0n || chunkIndex > AGE_MAX_CHUNK_INDEX) {
    throw new Error("Age payload chunk counter exhausted.");
  }
  const nonce = new Uint8Array(12);
  let temp = chunkIndex;
  for (let i = 10; i >= 0; i--) {
    nonce[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  nonce[11] = isLast ? 0x01 : 0x00;
  return nonce;
}

function concatBytes(chunks: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function appendBytes(left: Uint8Array, right: Uint8Array): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(left.length + right.length);
  result.set(left, 0);
  result.set(right, left.length);
  return result;
}

function indexOfBytes(bytes: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = from; i <= bytes.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (bytes[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

const AGE_HEADER_MAC_MARKER = new TextEncoder().encode("\n--- ");
const AGE_ARMOR_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----";

interface ParsedStanza {
  args: string[];
  body: Uint8Array;
}

function prefixedScryptSalt(salt: Uint8Array): Uint8Array {
  return concatBytes([AGE_SCRYPT_LABEL, salt]);
}

function parseHeaderStanzas(headerBytes: Uint8Array): ParsedStanza[] {
  for (const byte of headerBytes) {
    if (byte !== 0x0a && (byte < 0x20 || byte > 0x7e)) {
      throw new Error("Invalid age container: header contains non-ASCII characters.");
    }
  }

  const lines = new TextDecoder().decode(headerBytes).split("\n");
  if (lines.shift() !== AGE_VERSION_LINE) {
    throw new Error(`Invalid age container: expected version line '${AGE_VERSION_LINE}'.`);
  }

  const stanzas: ParsedStanza[] = [];
  for (let lineIndex = 0; lineIndex < lines.length;) {
    const argLine = lines[lineIndex++]!;
    if (!argLine.startsWith("-> ")) {
      throw new Error("Invalid age container: malformed recipient stanza argument line.");
    }
    const args = argLine.slice(3).split(" ");
    if (
      args.length === 0 ||
      args.length > 129 ||
      args.some((argument) => !/^[\x21-\x7e]+$/.test(argument))
    ) {
      throw new Error("Invalid age container: malformed recipient stanza arguments.");
    }

    const bodyLines: string[] = [];
    while (lineIndex < lines.length && !lines[lineIndex]!.startsWith("-> ")) {
      bodyLines.push(lines[lineIndex++]!);
    }
    if (bodyLines.length === 0) {
      throw new Error("Invalid age container: recipient stanza is missing its body.");
    }
    for (let i = 0; i < bodyLines.length - 1; i++) {
      if (bodyLines[i]!.length !== 64) {
        throw new Error("Invalid age container: stanza body has a non-final short line.");
      }
    }
    if (bodyLines[bodyLines.length - 1]!.length > 63) {
      throw new Error("Invalid age container: stanza body is missing its final short line.");
    }

    let body: Uint8Array;
    try {
      body = decodeBase64Raw(bodyLines.join(""));
    } catch {
      throw new Error("Invalid age container: stanza body is not canonical raw base64.");
    }
    stanzas.push({ args, body });
    if (stanzas.length > 1024) {
      throw new Error("Invalid age container: too many recipient stanzas.");
    }
  }
  if (stanzas.length === 0) {
    throw new Error("Invalid age container: no recipient stanzas.");
  }
  return stanzas;
}

function validateNativeStanzas(stanzas: ParsedStanza[]): void {
  const scryptStanzas = stanzas.filter((stanza) => stanza.args[0] === "scrypt");
  if (scryptStanzas.length > 0 && stanzas.length !== 1) {
    throw new Error("Invalid age container: an scrypt stanza must be the only stanza.");
  }

  for (const stanza of stanzas) {
    if (stanza.args[0] === "X25519") {
      if (stanza.args.length !== 2 || stanza.body.length !== 32) {
        throw new Error("Invalid age container: malformed X25519 recipient stanza.");
      }
      try {
        if (decodeBase64Raw(stanza.args[1]!).length !== 32) throw new Error();
      } catch {
        throw new Error("Invalid age container: malformed X25519 ephemeral share.");
      }
    } else if (stanza.args[0] === "scrypt") {
      if (stanza.args.length !== 3 || stanza.body.length !== 32) {
        throw new Error("Invalid age container: malformed scrypt recipient stanza.");
      }
      try {
        if (decodeBase64Raw(stanza.args[1]!).length !== 16) throw new Error();
      } catch {
        throw new Error("Invalid age container: malformed scrypt salt.");
      }
      const encodedLogN = stanza.args[2]!;
      if (!/^[1-9][0-9]*$/.test(encodedLogN)) {
        throw new Error("Invalid age container: malformed scrypt work factor.");
      }
      const logN = Number(encodedLogN);
      if (!Number.isSafeInteger(logN) || logN > AGE_MAX_SCRYPT_LOG_N) {
        throw new Error(
          `Invalid age container: scrypt work factor exceeds ${AGE_MAX_SCRYPT_LOG_N}.`,
        );
      }
    }
  }
}

/** Incremental raw-binary age encryptor. ASCII armor is intentionally unsupported. */
export class AgeEncryptor {
  private readonly crypto: AgeCrypto;
  private readonly header: Uint8Array;
  private readonly payloadKey: Uint8Array;
  private buffer = new Uint8Array(0);
  private chunkIndex = 0n;
  private headerEmitted = false;
  private finalized = false;

  constructor(crypto: AgeCrypto, options: AgeIncrementalEncryptOptions) {
    if (options.armor) {
      throw new Error(
        "AgeEncryptor does not support armored output; stream the raw binary age format.",
      );
    }

    this.crypto = crypto;
    const recipients = options.recipients ?? [];
    const passphrase = options.passphrase;
    if (recipients.length === 0 && !passphrase) {
      throw new Error(
        "AgeEncryptor requires at least one recipient (age1...) or a passphrase.",
      );
    }
    if (recipients.length > 0 && passphrase) {
      throw new Error("AgeEncryptor cannot mix an scrypt stanza with other recipients.");
    }

    const fileKey = options.fileKey ?? new Uint8Array(AGE_FILE_KEY_SIZE);
    if (fileKey.length !== AGE_FILE_KEY_SIZE) {
      throw new Error(`Age file key must be ${AGE_FILE_KEY_SIZE} bytes.`);
    }
    if (!options.fileKey) {
      if (typeof globalThis.crypto?.getRandomValues === "function") {
        globalThis.crypto.getRandomValues(fileKey);
      } else {
        throw new Error("CSPRNG unavailable for age file key generation.");
      }
    }

    const zeroNonce = new Uint8Array(12);
    const stanzas: string[] = [];
    for (const recipient of recipients) {
      const recipientPublicKey = parseAgeRecipient(recipient);
      const ephemeralPrivateKey = options.ephemeralKey ?? new Uint8Array(32);
      if (ephemeralPrivateKey.length !== 32) {
        throw new Error("Age X25519 ephemeral key must be 32 bytes.");
      }
      if (!options.ephemeralKey) {
        if (typeof globalThis.crypto?.getRandomValues === "function") {
          globalThis.crypto.getRandomValues(ephemeralPrivateKey);
        } else {
          throw new Error("CSPRNG unavailable for age ephemeral key generation.");
        }
      }
      const ephemeralPublicKey = crypto.x25519GetPublicKey(ephemeralPrivateKey);
      const sharedSecret = crypto.x25519SharedSecret(ephemeralPrivateKey, recipientPublicKey);
      const salt = new Uint8Array(64);
      salt.set(ephemeralPublicKey, 0);
      salt.set(recipientPublicKey, 32);
      const wrapKey = crypto.hkdfSha256(sharedSecret, salt, "age-encryption.org/v1/X25519", 32);
      const body = crypto.chacha20poly1305Encrypt(wrapKey, zeroNonce, fileKey);
      stanzas.push(
        `-> X25519 ${encodeBase64Raw(ephemeralPublicKey)}\n${encodeBase64Raw(body)}`,
      );
    }

    if (passphrase) {
      const salt = options.scryptSalt ?? new Uint8Array(16);
      if (salt.length !== 16) throw new Error("Age scrypt salt must be 16 bytes.");
      if (!options.scryptSalt) {
        if (typeof globalThis.crypto?.getRandomValues === "function") {
          globalThis.crypto.getRandomValues(salt);
        } else {
          throw new Error("CSPRNG unavailable for age scrypt salt generation.");
        }
      }
      const logN = options.scryptLogN ?? 14;
      if (!Number.isInteger(logN) || logN < 1 || logN > AGE_MAX_SCRYPT_LOG_N) {
        throw new Error(
          `Age scrypt work factor must be an integer from 1 through ${AGE_MAX_SCRYPT_LOG_N}.`,
        );
      }
      const wrapKey = crypto.scrypt(passphrase, prefixedScryptSalt(salt), logN);
      const body = crypto.chacha20poly1305Encrypt(wrapKey, zeroNonce, fileKey);
      stanzas.push(`-> scrypt ${encodeBase64Raw(salt)} ${logN}\n${encodeBase64Raw(body)}`);
    }

    const headerPrefix = `${AGE_VERSION_LINE}\n${stanzas.join("\n")}\n---`;
    const hmacKey = crypto.hkdfSha256(fileKey, new Uint8Array(0), "header", 32);
    const headerMac = crypto.hmacSha256(hmacKey, new TextEncoder().encode(headerPrefix));
    const header = new TextEncoder().encode(`${headerPrefix} ${encodeBase64Raw(headerMac)}\n`);
    const payloadNonce = options.payloadNonce ?? new Uint8Array(AGE_PAYLOAD_NONCE_SIZE);
    if (payloadNonce.length !== AGE_PAYLOAD_NONCE_SIZE) {
      throw new Error(`Age payload nonce must be ${AGE_PAYLOAD_NONCE_SIZE} bytes.`);
    }
    if (!options.payloadNonce) {
      if (typeof globalThis.crypto?.getRandomValues === "function") {
        globalThis.crypto.getRandomValues(payloadNonce);
      } else {
        throw new Error("CSPRNG unavailable for age payload nonce generation.");
      }
    }
    this.header = concatBytes([header, payloadNonce]);
    this.payloadKey = crypto.hkdfSha256(fileKey, payloadNonce, "payload", 32);
  }

  update(chunk: Uint8Array): Uint8Array {
    if (this.finalized) throw new Error("AgeEncryptor has already been finalized.");
    if (chunk.length === 0) return new Uint8Array(0);

    const combined = appendBytes(this.buffer, chunk);
    const output: Uint8Array[] = [];
    if (!this.headerEmitted) {
      output.push(this.header);
      this.headerEmitted = true;
    }

    let offset = 0;
    // A full frame may be the final frame, so it is held until more plaintext arrives.
    while (combined.length - offset > AGE_CHUNK_SIZE) {
      if (this.chunkIndex === AGE_MAX_CHUNK_INDEX) {
        throw new Error("Age payload chunk counter exhausted.");
      }
      const plaintext = combined.subarray(offset, offset + AGE_CHUNK_SIZE);
      const nonce = makeChunkNonce(this.chunkIndex, false);
      output.push(this.crypto.chacha20poly1305Encrypt(this.payloadKey, nonce, plaintext));
      this.chunkIndex++;
      offset += AGE_CHUNK_SIZE;
    }
    this.buffer = combined.slice(offset);
    return concatBytes(output);
  }

  finalize(): Uint8Array {
    if (this.finalized) throw new Error("AgeEncryptor has already been finalized.");
    this.finalized = true;

    const output: Uint8Array[] = [];
    if (!this.headerEmitted) output.push(this.header);
    const nonce = makeChunkNonce(this.chunkIndex, true);
    output.push(this.crypto.chacha20poly1305Encrypt(this.payloadKey, nonce, this.buffer));
    this.buffer = new Uint8Array(0);
    return concatBytes(output);
  }
}

/** Incremental raw-binary age decryptor. Plaintext is returned only for authenticated frames. */
export class AgeDecryptor {
  private readonly crypto: AgeCrypto;
  private readonly options: AgeDecryptOptions;
  private fileKey?: Uint8Array;
  private payloadKey?: Uint8Array;
  private buffer = new Uint8Array(0);
  private chunkIndex = 0n;
  private headerProcessed = false;
  private payloadNonceProcessed = false;
  private finalized = false;
  private failed = false;

  constructor(crypto: AgeCrypto, options: AgeDecryptOptions) {
    this.crypto = crypto;
    this.options = options;
  }

  private processPreamble(): boolean {
    if (!this.headerProcessed) {
      const armorPrefix = new TextEncoder().encode(AGE_ARMOR_BEGIN);
      if (
        this.buffer.length >= armorPrefix.length &&
        indexOfBytes(this.buffer.subarray(0, armorPrefix.length), armorPrefix) === 0
      ) {
        throw new Error(
          "AgeDecryptor does not support armored input; dearmor it before streaming.",
        );
      }

      const markerIndex = indexOfBytes(this.buffer, AGE_HEADER_MAC_MARKER);
      if (markerIndex === -1) {
        if (this.buffer.length > AGE_MAX_HEADER_SIZE) {
          throw new Error(
            `Invalid age container: header exceeds ${AGE_MAX_HEADER_SIZE} bytes.`,
          );
        }
        return false;
      }
      const macEndIndex = this.buffer.indexOf(0x0a, markerIndex + AGE_HEADER_MAC_MARKER.length);
      if (macEndIndex === -1) {
        if (this.buffer.length > AGE_MAX_HEADER_SIZE) {
          throw new Error(
            `Invalid age container: header exceeds ${AGE_MAX_HEADER_SIZE} bytes.`,
          );
        }
        return false;
      }
      if (macEndIndex + 1 > AGE_MAX_HEADER_SIZE) {
        throw new Error(`Invalid age container: header exceeds ${AGE_MAX_HEADER_SIZE} bytes.`);
      }

      const macLine = new TextDecoder().decode(
        this.buffer.subarray(markerIndex + AGE_HEADER_MAC_MARKER.length, macEndIndex),
      );
      let expectedHeaderMac: Uint8Array;
      try {
        expectedHeaderMac = decodeBase64Raw(macLine);
      } catch {
        throw new Error("Invalid age container: malformed header MAC encoding.");
      }
      if (macLine.length !== 43 || expectedHeaderMac.length !== 32) {
        throw new Error("Invalid age container: header MAC must encode 32 bytes.");
      }

      const stanzas = parseHeaderStanzas(this.buffer.subarray(0, markerIndex));
      validateNativeStanzas(stanzas);
      const fileKey = this.decryptFileKey(stanzas);
      const hmacKey = this.crypto.hkdfSha256(fileKey, new Uint8Array(0), "header", 32);
      const actualMac = this.crypto.hmacSha256(
        hmacKey,
        this.buffer.subarray(0, markerIndex + 4),
      );
      let difference = actualMac.length ^ expectedHeaderMac.length;
      for (let i = 0; i < Math.min(actualMac.length, expectedHeaderMac.length); i++) {
        difference |= actualMac[i]! ^ expectedHeaderMac[i]!;
      }
      if (difference !== 0) {
        throw new Error(
          "Invalid age container: header MAC authentication failed (tampered header).",
        );
      }

      this.fileKey = fileKey;
      this.buffer = this.buffer.slice(macEndIndex + 1);
      this.headerProcessed = true;
    }

    if (!this.payloadNonceProcessed) {
      if (this.buffer.length < AGE_PAYLOAD_NONCE_SIZE) return false;
      const payloadNonce = this.buffer.slice(0, AGE_PAYLOAD_NONCE_SIZE);
      this.payloadKey = this.crypto.hkdfSha256(this.fileKey!, payloadNonce, "payload", 32);
      this.fileKey = undefined;
      this.buffer = this.buffer.slice(AGE_PAYLOAD_NONCE_SIZE);
      this.payloadNonceProcessed = true;
    }
    return true;
  }

  private decryptFileKey(stanzas: ParsedStanza[]): Uint8Array {
    const zeroNonce = new Uint8Array(12);
    if (this.options.identities && this.options.identities.length > 0) {
      for (const identity of this.options.identities) {
        const identityPrivateKey = parseAgeIdentity(identity);
        const identityPublicKey = this.crypto.x25519GetPublicKey(identityPrivateKey);
        for (const stanza of stanzas) {
          if (stanza.args[0] !== "X25519") continue;
          const ephemeralPublicKey = decodeBase64Raw(stanza.args[1]!);
          let sharedSecret: Uint8Array;
          try {
            sharedSecret = this.crypto.x25519SharedSecret(
              identityPrivateKey,
              ephemeralPublicKey,
            );
          } catch {
            throw new Error("Invalid age container: invalid X25519 ephemeral share.");
          }
          if (sharedSecret.every((byte) => byte === 0)) {
            throw new Error("Invalid age container: all-zero X25519 shared secret.");
          }
          try {
            const salt = new Uint8Array(64);
            salt.set(ephemeralPublicKey, 0);
            salt.set(identityPublicKey, 32);
            const wrapKey = this.crypto.hkdfSha256(
              sharedSecret,
              salt,
              "age-encryption.org/v1/X25519",
              32,
            );
            const candidate = this.crypto.chacha20poly1305Decrypt(
              wrapKey,
              zeroNonce,
              stanza.body,
            );
            if (candidate.length === AGE_FILE_KEY_SIZE) return candidate;
          } catch {
            // This stanza does not match the identity.
          }
        }
      }
    }

    if (this.options.passphrase) {
      for (const stanza of stanzas) {
        if (stanza.args[0] !== "scrypt") continue;
        const salt = decodeBase64Raw(stanza.args[1]!);
        const logN = Number(stanza.args[2]!);
        try {
          const wrapKey = this.crypto.scrypt(
            this.options.passphrase,
            prefixedScryptSalt(salt),
            logN,
          );
          const candidate = this.crypto.chacha20poly1305Decrypt(
            wrapKey,
            zeroNonce,
            stanza.body,
          );
          if (candidate.length === AGE_FILE_KEY_SIZE) return candidate;
        } catch {
          // Incorrect passphrase.
        }
      }
    }

    throw new Error(
      "Could not decrypt age container: no matching identity or correct passphrase.",
    );
  }

  update(chunk: Uint8Array): Uint8Array {
    if (this.finalized) throw new Error("AgeDecryptor has already been finalized.");
    if (this.failed)
      throw new Error("AgeDecryptor cannot continue after an authentication failure.");
    if (chunk.length === 0) return new Uint8Array(0);

    try {
      this.buffer = appendBytes(this.buffer, chunk);
      if (!this.processPreamble()) return new Uint8Array(0);

      const output: Uint8Array[] = [];
      const frameSize = AGE_CHUNK_SIZE + AGE_TAG_SIZE;
      let offset = 0;
      // An exactly full frame may be final and must retain the final-bit nonce until more input arrives.
      while (this.buffer.length - offset > frameSize) {
        if (this.chunkIndex === AGE_MAX_CHUNK_INDEX) {
          throw new Error("Age payload chunk counter exhausted.");
        }
        const ciphertext = this.buffer.subarray(offset, offset + frameSize);
        const nonce = makeChunkNonce(this.chunkIndex, false);
        output.push(this.crypto.chacha20poly1305Decrypt(this.payloadKey!, nonce, ciphertext));
        this.chunkIndex++;
        offset += frameSize;
      }
      this.buffer = this.buffer.slice(offset);
      return concatBytes(output);
    } catch (error) {
      this.failed = true;
      throw error;
    }
  }

  finalize(): Uint8Array {
    if (this.finalized) throw new Error("AgeDecryptor has already been finalized.");
    if (this.failed)
      throw new Error("AgeDecryptor cannot finalize after an authentication failure.");
    this.finalized = true;

    if (!this.headerProcessed) {
      throw new Error("Invalid age container: incomplete header.");
    }
    if (!this.payloadNonceProcessed) {
      throw new Error("Invalid age container: incomplete payload nonce.");
    }
    const frameSize = AGE_CHUNK_SIZE + AGE_TAG_SIZE;
    if (this.buffer.length < AGE_TAG_SIZE || this.buffer.length > frameSize) {
      throw new Error(
        `Invalid age container: final payload frame is ${this.buffer.length} bytes (expected ${AGE_TAG_SIZE} to ${frameSize}).`,
      );
    }
    if (this.chunkIndex > 0n && this.buffer.length === AGE_TAG_SIZE) {
      throw new Error(
        "Invalid age container: final payload frame is empty after prior frames.",
      );
    }
    const nonce = makeChunkNonce(this.chunkIndex, true);
    const plaintext = this.crypto.chacha20poly1305Decrypt(this.payloadKey!, nonce, this.buffer);
    this.buffer = new Uint8Array(0);
    this.chunkIndex++;
    return plaintext;
  }
}

/**
 * Encrypts an arbitrary payload into the standard age container format.
 */
export function ageEncrypt(
  crypto: AgeCrypto,
  plaintext: Uint8Array,
  options: AgeEncryptOptions,
): Uint8Array {
  const encryptor = new AgeEncryptor(crypto, options);
  return concatBytes([encryptor.update(plaintext), encryptor.finalize()]);
}

/**
 * Decrypts an age container using private keys or a passphrase.
 */
export function ageDecrypt(
  crypto: AgeCrypto,
  containerBytes: Uint8Array,
  options: AgeDecryptOptions,
): Uint8Array {
  const decryptor = new AgeDecryptor(crypto, options);
  return concatBytes([decryptor.update(containerBytes), decryptor.finalize()]);
}

export function isArmoredAge(input: string | Uint8Array): boolean {
  const str =
    typeof input === "string" ? input : new TextDecoder().decode(input.subarray(0, 40));
  return str.trimStart().startsWith("-----BEGIN AGE ENCRYPTED FILE-----");
}

export function armorAge(bytes: Uint8Array): string {
  const chars = B64_CHARS;
  let b64 = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    b64 +=
      chars[(n >> 18) & 63]! + chars[(n >> 12) & 63]! + chars[(n >> 6) & 63]! + chars[n & 63]!;
  }
  if (i < bytes.length) {
    const b0 = bytes[i]!;
    if (i + 1 < bytes.length) {
      const b1 = bytes[i + 1]!;
      const n = (b0 << 16) | (b1 << 8);
      b64 += chars[(n >> 18) & 63]! + chars[(n >> 12) & 63]! + chars[(n >> 6) & 63]! + "=";
    } else {
      const n = b0 << 16;
      b64 += chars[(n >> 18) & 63]! + chars[(n >> 12) & 63]! + "==";
    }
  }

  const lines: string[] = ["-----BEGIN AGE ENCRYPTED FILE-----"];
  for (let c = 0; c < b64.length; c += 64) {
    lines.push(b64.slice(c, c + 64));
  }
  lines.push("-----END AGE ENCRYPTED FILE-----\n");
  return lines.join("\n");
}

export function dearmorAge(armored: string | Uint8Array): Uint8Array {
  const text = typeof armored === "string" ? armored : new TextDecoder().decode(armored);
  const startMarker = "-----BEGIN AGE ENCRYPTED FILE-----";
  const endMarker = "-----END AGE ENCRYPTED FILE-----";
  const normalized = text.trim().replace(/\r\n/g, "\n");
  if (normalized.includes("\r")) {
    throw new Error("Invalid age armored file: unsupported line endings.");
  }
  const lines = normalized.split("\n");
  if (lines[0] !== startMarker || lines.at(-1) !== endMarker) {
    throw new Error("Invalid age armored file: missing begin or end markers.");
  }
  const b64 = lines.slice(1, -1).join("");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b64)) {
    throw new Error("Invalid age armored file: malformed base64.");
  }
  const decoded = decodeBase64Raw(b64.replace(/=+$/, ""));
  if (armorAge(decoded).trim() !== normalized) {
    throw new Error("Invalid age armored file: non-canonical PEM encoding.");
  }
  return decoded;
}
