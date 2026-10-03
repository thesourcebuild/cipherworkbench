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
      res += B64_CHARS[(n >> 18) & 63]! + B64_CHARS[(n >> 12) & 63]! + B64_CHARS[(n >> 6) & 63]!;
    } else {
      const n = b0 << 16;
      res += B64_CHARS[(n >> 18) & 63]! + B64_CHARS[(n >> 12) & 63]!;
    }
  }
  return res;
}

export function decodeBase64Raw(str: string): Uint8Array {
  const clean = str.replace(/[^A-Za-z0-9+/]/g, "");
  const out: number[] = [];
  let i = 0;
  for (; i + 3 < clean.length; i += 4) {
    const n =
      (B64_REV[clean.charCodeAt(i)]! << 18) |
      (B64_REV[clean.charCodeAt(i + 1)]! << 12) |
      (B64_REV[clean.charCodeAt(i + 2)]! << 6) |
      B64_REV[clean.charCodeAt(i + 3)]!;
    out.push((n >> 16) & 255, (n >> 8) & 255, n & 255);
  }
  const rem = clean.length - i;
  if (rem === 2) {
    const n = (B64_REV[clean.charCodeAt(i)]! << 18) | (B64_REV[clean.charCodeAt(i + 1)]! << 12);
    out.push((n >> 16) & 255);
  } else if (rem === 3) {
    const n =
      (B64_REV[clean.charCodeAt(i)]! << 18) |
      (B64_REV[clean.charCodeAt(i + 1)]! << 12) |
      (B64_REV[clean.charCodeAt(i + 2)]! << 6);
    out.push((n >> 16) & 255, (n >> 8) & 255);
  }
  return new Uint8Array(out);
}

export interface AgeCrypto {
  chacha20poly1305Encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array;
  chacha20poly1305Decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array;
  x25519GetPublicKey(privateKey: Uint8Array): Uint8Array;
  x25519SharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array;
  hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: string | Uint8Array, length: number): Uint8Array;
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
}

export interface AgeDecryptOptions {
  identities?: string[];
  passphrase?: string;
}

function makeChunkNonce(chunkIndex: number, isLast: boolean): Uint8Array {
  const nonce = new Uint8Array(12);
  let temp = BigInt(chunkIndex);
  for (let i = 10; i >= 0; i--) {
    nonce[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  nonce[11] = isLast ? 0x01 : 0x00;
  return nonce;
}

/**
 * Encrypts an arbitrary payload into the standard age container format.
 */
export function ageEncrypt(
  crypto: AgeCrypto,
  plaintext: Uint8Array,
  options: AgeEncryptOptions,
): Uint8Array {
  const recipients = options.recipients ?? [];
  const passphrase = options.passphrase;

  if (recipients.length === 0 && !passphrase) {
    throw new Error("ageEncrypt requires at least one recipient (age1...) or a passphrase.");
  }

  // 1. Generate 16-byte random file key
  const fileKey = options.fileKey ?? new Uint8Array(AGE_FILE_KEY_SIZE);
  if (!options.fileKey) {
    if (typeof globalThis.crypto?.getRandomValues === "function") {
      globalThis.crypto.getRandomValues(fileKey);
    } else {
      throw new Error("CSPRNG unavailable for age file key generation.");
    }
  }

  const zeroNonce = new Uint8Array(12);
  const stanzas: string[] = [];

  // 2. Process X25519 recipients
  for (const recipStr of recipients) {
    const recipPk = parseAgeRecipient(recipStr);
    const ephemSk = options.ephemeralKey ?? new Uint8Array(32);
    if (!options.ephemeralKey) {
      globalThis.crypto.getRandomValues(ephemSk);
    }
    const ephemPk = crypto.x25519GetPublicKey(ephemSk);
    const sharedSecret = crypto.x25519SharedSecret(ephemSk, recipPk);

    const salt = new Uint8Array(64);
    salt.set(ephemPk, 0);
    salt.set(recipPk, 32);

    const wrapKey = crypto.hkdfSha256(sharedSecret, salt, "age-encryption.org/v1/X25519", 32);
    const body = crypto.chacha20poly1305Encrypt(wrapKey, zeroNonce, fileKey);

    stanzas.push(`-> X25519 ${encodeBase64Raw(ephemPk)}\n${encodeBase64Raw(body)}`);
  }

  // 3. Process passphrase recipient if present
  if (passphrase) {
    const salt = options.scryptSalt ?? new Uint8Array(16);
    if (!options.scryptSalt) {
      globalThis.crypto.getRandomValues(salt);
    }
    const logN = options.scryptLogN ?? 14;
    const wrapKey = crypto.scrypt(passphrase, salt, logN);
    const body = crypto.chacha20poly1305Encrypt(wrapKey, zeroNonce, fileKey);

    stanzas.push(`-> scrypt ${encodeBase64Raw(salt)} ${logN}\n${encodeBase64Raw(body)}`);
  }

  // 4. Assemble header and compute header MAC
  const headerPrefix = `${AGE_VERSION_LINE}\n${stanzas.join("\n")}\n---`;
  const hmacKey = crypto.hkdfSha256(fileKey, new Uint8Array(0), "header", 32);
  const headerMac = crypto.hmacSha256(hmacKey, new TextEncoder().encode(headerPrefix));
  const fullHeaderStr = `${headerPrefix} ${encodeBase64Raw(headerMac)}\n`;
  const fullHeaderBytes = new TextEncoder().encode(fullHeaderStr);

  // 5. Derive payload key
  const payloadKey = crypto.hkdfSha256(fileKey, new Uint8Array(0), "payload", 32);

  // 6. Encrypt payload in 64 KiB chunks
  const encryptedChunks: Uint8Array[] = [];
  const totalChunks = Math.ceil(plaintext.length / AGE_CHUNK_SIZE) || 1;

  for (let c = 0; c < totalChunks; c++) {
    const isLast = c === totalChunks - 1;
    const chunkStart = c * AGE_CHUNK_SIZE;
    const chunkPlain = plaintext.subarray(chunkStart, Math.min(chunkStart + AGE_CHUNK_SIZE, plaintext.length));
    const nonce = makeChunkNonce(c, isLast);
    const chunkCipher = crypto.chacha20poly1305Encrypt(payloadKey, nonce, chunkPlain);
    encryptedChunks.push(chunkCipher);
  }

  // 7. Combine full container
  const totalCipherLen = encryptedChunks.reduce((acc, ch) => acc + ch.length, 0);
  const out = new Uint8Array(fullHeaderBytes.length + totalCipherLen);
  out.set(fullHeaderBytes, 0);
  let off = fullHeaderBytes.length;
  for (const chunk of encryptedChunks) {
    out.set(chunk, off);
    off += chunk.length;
  }

  return out;
}

/**
 * Decrypts an age container using private keys or a passphrase.
 */
export function ageDecrypt(
  crypto: AgeCrypto,
  containerBytes: Uint8Array,
  options: AgeDecryptOptions,
): Uint8Array {
  // Find header end marker: "\n--- "
  const textHead = new TextDecoder().decode(containerBytes.subarray(0, Math.min(containerBytes.length, 8192)));
  const macMarkerIdx = textHead.indexOf("\n--- ");
  if (macMarkerIdx === -1) {
    throw new Error("Invalid age container: missing header MAC delimiter '--- '.");
  }

  const macEndIdx = textHead.indexOf("\n", macMarkerIdx + 5);
  if (macEndIdx === -1) {
    throw new Error("Invalid age container: malformed header line endings.");
  }

  const headerPrefix = textHead.substring(0, macMarkerIdx + 4); // includes "\n---"
  const macLine = textHead.substring(macMarkerIdx + 5, macEndIdx).trim();
  const expectedHeaderMac = decodeBase64Raw(macLine);

  const payloadOffset = new TextEncoder().encode(textHead.substring(0, macEndIdx + 1)).length;
  const payloadCiphertext = containerBytes.subarray(payloadOffset);

  // Parse stanzas
  const stanzaSections = textHead.substring(0, macMarkerIdx).split("\n-> ").slice(1);
  let fileKey: Uint8Array | undefined;

  const zeroNonce = new Uint8Array(12);

  // Attempt X25519 identity decryption
  if (options.identities && options.identities.length > 0) {
    for (const identityStr of options.identities) {
      const identSk = parseAgeIdentity(identityStr);
      const identPk = crypto.x25519GetPublicKey(identSk);

      for (const stanza of stanzaSections) {
        if (!stanza.startsWith("X25519 ")) continue;
        const lines = stanza.split("\n");
        const parts = lines[0]!.split(" ");
        const ephemPk = decodeBase64Raw(parts[1]!);
        const bodyCipher = decodeBase64Raw(lines[1]!);

        try {
          const sharedSecret = crypto.x25519SharedSecret(identSk, ephemPk);
          const salt = new Uint8Array(64);
          salt.set(ephemPk, 0);
          salt.set(identPk, 32);

          const wrapKey = crypto.hkdfSha256(sharedSecret, salt, "age-encryption.org/v1/X25519", 32);
          const candidate = crypto.chacha20poly1305Decrypt(wrapKey, zeroNonce, bodyCipher);
          if (candidate.length === AGE_FILE_KEY_SIZE) {
            fileKey = candidate;
            break;
          }
        } catch {
          // Stanza does not match this key
        }
      }
      if (fileKey) break;
    }
  }

  // Attempt scrypt passphrase decryption if still locked
  if (!fileKey && options.passphrase) {
    for (const stanza of stanzaSections) {
      if (!stanza.startsWith("scrypt ")) continue;
      const lines = stanza.split("\n");
      const parts = lines[0]!.split(" ");
      const salt = decodeBase64Raw(parts[1]!);
      const logN = parseInt(parts[2]!, 10);
      const bodyCipher = decodeBase64Raw(lines[1]!);

      try {
        const wrapKey = crypto.scrypt(options.passphrase, salt, logN);
        const candidate = crypto.chacha20poly1305Decrypt(wrapKey, zeroNonce, bodyCipher);
        if (candidate.length === AGE_FILE_KEY_SIZE) {
          fileKey = candidate;
          break;
        }
      } catch {
        // Incorrect passphrase
      }
    }
  }

  if (!fileKey) {
    throw new Error("Could not decrypt age container: no matching identity or correct passphrase.");
  }

  // Verify header MAC
  const hmacKey = crypto.hkdfSha256(fileKey, new Uint8Array(0), "header", 32);
  const actualMac = crypto.hmacSha256(hmacKey, new TextEncoder().encode(headerPrefix));
  if (actualMac.length !== expectedHeaderMac.length) {
    throw new Error("Invalid age container: header MAC length mismatch.");
  }
  let diff = 0;
  for (let i = 0; i < actualMac.length; i++) {
    diff |= actualMac[i]! ^ expectedHeaderMac[i]!;
  }
  if (diff !== 0) {
    throw new Error("Invalid age container: header MAC authentication failed (tampered header).");
  }

  // Derive payload key and decrypt chunks
  const payloadKey = crypto.hkdfSha256(fileKey, new Uint8Array(0), "payload", 32);
  const decryptedChunks: Uint8Array[] = [];

  let chunkIdx = 0;
  let pOff = 0;
  const chunkCipherMax = AGE_CHUNK_SIZE + AGE_TAG_SIZE;

  while (pOff < payloadCiphertext.length) {
    const remaining = payloadCiphertext.length - pOff;
    const isLast = remaining <= chunkCipherMax;
    const thisChunkCipher = payloadCiphertext.subarray(pOff, pOff + (isLast ? remaining : chunkCipherMax));
    const nonce = makeChunkNonce(chunkIdx, isLast);

    const chunkPlain = crypto.chacha20poly1305Decrypt(payloadKey, nonce, thisChunkCipher);
    decryptedChunks.push(chunkPlain);

    pOff += thisChunkCipher.length;
    chunkIdx++;
  }

  // Total plaintext assembly
  const totalPlainLen = decryptedChunks.reduce((acc, ch) => acc + ch.length, 0);
  const out = new Uint8Array(totalPlainLen);
  let dOff = 0;
  for (const ch of decryptedChunks) {
    out.set(ch, dOff);
    dOff += ch.length;
  }

  return out;
}

export function isArmoredAge(input: string | Uint8Array): boolean {
  const str = typeof input === "string" ? input : new TextDecoder().decode(input.subarray(0, 40));
  return str.trimStart().startsWith("-----BEGIN AGE ENCRYPTED FILE-----");
}

export function armorAge(bytes: Uint8Array): string {
  const chars = B64_CHARS;
  let b64 = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    b64 += chars[(n >> 18) & 63]! + chars[(n >> 12) & 63]! + chars[(n >> 6) & 63]! + chars[n & 63]!;
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
  const startIdx = text.indexOf(startMarker);
  const endIdx = text.indexOf(endMarker);
  if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) {
    throw new Error("Invalid age armored file: missing begin or end markers.");
  }
  const b64 = text.substring(startIdx + startMarker.length, endIdx).replace(/\s+/g, "");
  return decodeBase64Raw(b64);
}

