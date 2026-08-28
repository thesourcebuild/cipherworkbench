/**
 * Cobblestone -- C2SP streaming symmetric encryption.
 *
 * Implements the C2SP chunked-encryption specification (https://c2sp.org/chunked-encryption).
 * Instantiations:
 *   - Cobblestone-128: SHA-512 + AES-128-GCM (16-byte key)
 *   - Cobblestone-256: SHA-512 + AES-256-GCM (32-byte key)
 *
 * Key derivation:
 *   key || base_nonce || commitment = HKDF-Expand(
 *     prk = input_key,
 *     info = "c2sp.org/chunked-encryption@v1+" || aead || 0x00 || salt || context,
 *     L = len(key) + len(nonce) + 32
 *   )
 *
 * Chunk framing:
 *   - Chunks of 16 KiB (16,384 bytes).
 *   - Final chunk MUST be strictly shorter than 16 KiB (0 <= len < 16384).
 *   - Per-chunk nonce: base_nonce XOR (chunk_index as big-endian integer).
 *   - Ciphertext layout: salt (24 bytes) || commitment (32 bytes) || enc_chunks...
 */

import { constantTimeEqual } from "./fernet";

export const COBBLESTONE_CHUNK_SIZE = 16384; // 16 KiB
export const COBBLESTONE_SALT_LENGTH = 24;
export const COBBLESTONE_COMMITMENT_LENGTH = 32;
export const COBBLESTONE_HEADER_LENGTH = 56; // 24 + 32
export const COBBLESTONE_TAG_LENGTH = 16;
export const COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN = COBBLESTONE_CHUNK_SIZE + COBBLESTONE_TAG_LENGTH; // 16400

export type CobblestoneVariant = "cobblestone128" | "cobblestone256";

export interface CobblestoneCrypto {
  hkdfExpandSha512(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array;
  aesGcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Uint8Array;
  aesGcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array;
}

export interface CobblestoneEncryptOptions {
  variant?: CobblestoneVariant;
  context?: Uint8Array;
  salt?: Uint8Array;
}

export interface CobblestoneDecryptOptions {
  variant?: CobblestoneVariant;
  context?: Uint8Array;
}

export interface CobblestoneDerivedKeys {
  aeadKey: Uint8Array;
  baseNonce: Uint8Array;
  commitment: Uint8Array;
}

const C2SP_INFO_PREFIX = new Uint8Array([
  0x63, 0x32, 0x73, 0x70, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x65, 0x64,
  0x2d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x40, 0x76, 0x31, 0x2b,
]); // "c2sp.org/chunked-encryption@v1+"

const AEAD_NAME_AES_128_GCM = new Uint8Array([
  0x41, 0x45, 0x41, 0x44, 0x5f, 0x41, 0x45, 0x53, 0x5f, 0x31, 0x32, 0x38, 0x5f, 0x47, 0x43, 0x4d,
]); // "AEAD_AES_128_GCM"

const AEAD_NAME_AES_256_GCM = new Uint8Array([
  0x41, 0x45, 0x41, 0x44, 0x5f, 0x41, 0x45, 0x53, 0x5f, 0x32, 0x35, 0x36, 0x5f, 0x47, 0x43, 0x4d,
]); // "AEAD_AES_256_GCM"

/**
 * Derives the single-use AEAD key, base nonce, and commitment from input key, salt, and context.
 */
export function cobblestoneDeriveKeys(
  crypto: CobblestoneCrypto,
  inputKey: Uint8Array,
  salt: Uint8Array,
  context: Uint8Array = new Uint8Array(0),
  variant: CobblestoneVariant = "cobblestone128",
): CobblestoneDerivedKeys {
  const expectedKeyLen = variant === "cobblestone128" ? 16 : 32;
  if (inputKey.length !== expectedKeyLen) {
    throw new Error(
      `${variant} input key must be exactly ${expectedKeyLen} bytes; received ${inputKey.length} bytes.`,
    );
  }
  if (salt.length !== COBBLESTONE_SALT_LENGTH) {
    throw new Error(
      `Cobblestone salt must be exactly ${COBBLESTONE_SALT_LENGTH} bytes; received ${salt.length} bytes.`,
    );
  }

  const aeadName = variant === "cobblestone128" ? AEAD_NAME_AES_128_GCM : AEAD_NAME_AES_256_GCM;
  const infoLen = C2SP_INFO_PREFIX.length + aeadName.length + 1 + salt.length + context.length;
  const info = new Uint8Array(infoLen);
  let offset = 0;
  info.set(C2SP_INFO_PREFIX, offset);
  offset += C2SP_INFO_PREFIX.length;
  info.set(aeadName, offset);
  offset += aeadName.length;
  info[offset++] = 0x00;
  info.set(salt, offset);
  offset += salt.length;
  info.set(context, offset);

  const keyLen = expectedKeyLen;
  const nonceLen = 12;
  const totalDerivedLen = keyLen + nonceLen + COBBLESTONE_COMMITMENT_LENGTH;

  const derived = crypto.hkdfExpandSha512(inputKey, info, totalDerivedLen);
  const aeadKey = derived.slice(0, keyLen);
  const baseNonce = derived.slice(keyLen, keyLen + nonceLen);
  const commitment = derived.slice(keyLen + nonceLen, totalDerivedLen);

  return { aeadKey, baseNonce, commitment };
}

/**
 * Derives the per-chunk nonce by XORing the chunk counter (as a big-endian integer)
 * into the 12-byte base nonce.
 */
export function cobblestoneDeriveNonce(baseNonce: Uint8Array, chunkIndex: number | bigint): Uint8Array {
  const nonce = new Uint8Array(baseNonce);
  let idx = BigInt(chunkIndex);
  for (let i = nonce.length - 1; i >= 0 && idx > 0n; i--) {
    nonce[i] = nonce[i]! ^ Number(idx & 0xffn);
    idx >>= 8n;
  }
  return nonce;
}

/**
 * One-shot Cobblestone encryption.
 */
export function cobblestoneEncrypt(
  crypto: CobblestoneCrypto,
  inputKey: Uint8Array,
  plaintext: Uint8Array,
  options: CobblestoneEncryptOptions = {},
): {
  ciphertext: Uint8Array;
  salt: Uint8Array;
  commitment: Uint8Array;
  chunks: number;
} {
  const variant = options.variant ?? (inputKey.length === 32 ? "cobblestone256" : "cobblestone128");
  const context = options.context ?? new Uint8Array(0);

  const salt = options.salt ?? new Uint8Array(COBBLESTONE_SALT_LENGTH);
  if (options.salt) {
    if (options.salt.length !== COBBLESTONE_SALT_LENGTH) {
      throw new Error(
        `Cobblestone salt must be ${COBBLESTONE_SALT_LENGTH} bytes; received ${options.salt.length}.`,
      );
    }
  } else {
    if (typeof globalThis.crypto?.getRandomValues === "function") {
      globalThis.crypto.getRandomValues(salt);
    } else {
      throw new Error("No CSPRNG available to generate Cobblestone salt.");
    }
  }

  const { aeadKey, baseNonce, commitment } = cobblestoneDeriveKeys(
    crypto,
    inputKey,
    salt,
    context,
    variant,
  );

  const fullChunks = Math.floor(plaintext.length / COBBLESTONE_CHUNK_SIZE);
  const finalChunkSize = plaintext.length % COBBLESTONE_CHUNK_SIZE;
  const totalChunks = fullChunks + 1; // Final chunk is always present, even if empty

  // Calculate total ciphertext size: header (56) + fullChunks * 16400 + (finalChunkSize + 16)
  const totalCiphertextLen =
    COBBLESTONE_HEADER_LENGTH + fullChunks * COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN + (finalChunkSize + COBBLESTONE_TAG_LENGTH);

  const ciphertext = new Uint8Array(totalCiphertextLen);
  ciphertext.set(salt, 0);
  ciphertext.set(commitment, COBBLESTONE_SALT_LENGTH);

  let ctOffset = COBBLESTONE_HEADER_LENGTH;

  for (let k = 0; k < totalChunks; k++) {
    const isFinal = k === totalChunks - 1;
    const ptChunkStart = k * COBBLESTONE_CHUNK_SIZE;
    const ptChunkEnd = isFinal ? plaintext.length : ptChunkStart + COBBLESTONE_CHUNK_SIZE;
    const ptChunk = plaintext.subarray(ptChunkStart, ptChunkEnd);

    const nonce_k = cobblestoneDeriveNonce(baseNonce, k);
    const encChunk = crypto.aesGcmEncrypt(aeadKey, nonce_k, ptChunk);

    ciphertext.set(encChunk, ctOffset);
    ctOffset += encChunk.length;
  }

  return {
    ciphertext,
    salt,
    commitment,
    chunks: totalChunks,
  };
}

/**
 * One-shot Cobblestone decryption.
 */
export function cobblestoneDecrypt(
  crypto: CobblestoneCrypto,
  inputKey: Uint8Array,
  ciphertext: Uint8Array,
  options: CobblestoneDecryptOptions = {},
): {
  plaintext: Uint8Array;
  salt: Uint8Array;
  commitment: Uint8Array;
  chunks: number;
} {
  const variant = options.variant ?? (inputKey.length === 32 ? "cobblestone256" : "cobblestone128");
  const context = options.context ?? new Uint8Array(0);

  if (ciphertext.length < COBBLESTONE_HEADER_LENGTH + COBBLESTONE_TAG_LENGTH) {
    throw new Error(
      `Cobblestone ciphertext is too short: minimum length is ${COBBLESTONE_HEADER_LENGTH + COBBLESTONE_TAG_LENGTH} bytes; received ${ciphertext.length} bytes.`,
    );
  }

  const salt = ciphertext.subarray(0, COBBLESTONE_SALT_LENGTH);
  const commitment = ciphertext.subarray(COBBLESTONE_SALT_LENGTH, COBBLESTONE_HEADER_LENGTH);

  const { aeadKey, baseNonce, commitment: expectedCommitment } = cobblestoneDeriveKeys(
    crypto,
    inputKey,
    salt,
    context,
    variant,
  );

  if (!constantTimeEqual(commitment, expectedCommitment)) {
    throw new Error("Invalid Cobblestone commitment: wrong key, corrupted header, or wrong context.");
  }

  const payload = ciphertext.subarray(COBBLESTONE_HEADER_LENGTH);
  const payloadLen = payload.length;

  // Each full chunk is 16400 bytes. The final chunk must be between 16 and 16399 bytes.
  const fullChunks = Math.floor(payloadLen / COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN);
  const finalChunkCtLen = payloadLen % COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN;

  if (finalChunkCtLen < COBBLESTONE_TAG_LENGTH) {
    throw new Error(
      `Cobblestone ciphertext is truncated: final chunk ciphertext length is ${finalChunkCtLen} bytes (must be between ${COBBLESTONE_TAG_LENGTH} and ${COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN - 1} bytes).`,
    );
  }

  const totalChunks = fullChunks + 1;
  const totalPlaintextLen = fullChunks * COBBLESTONE_CHUNK_SIZE + (finalChunkCtLen - COBBLESTONE_TAG_LENGTH);
  const plaintext = new Uint8Array(totalPlaintextLen);

  let ctOffset = 0;
  let ptOffset = 0;

  for (let k = 0; k < totalChunks; k++) {
    const isFinal = k === totalChunks - 1;
    const chunkSize = isFinal ? finalChunkCtLen : COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN;
    const encChunk = payload.subarray(ctOffset, ctOffset + chunkSize);
    ctOffset += chunkSize;

    const nonce_k = cobblestoneDeriveNonce(baseNonce, k);
    const decChunk = crypto.aesGcmDecrypt(aeadKey, nonce_k, encChunk);

    plaintext.set(decChunk, ptOffset);
    ptOffset += decChunk.length;
  }

  return {
    plaintext,
    salt,
    commitment,
    chunks: totalChunks,
  };
}

/**
 * Incremental streaming encryptor for Cobblestone.
 */
export class CobblestoneEncryptor {
  private readonly crypto: CobblestoneCrypto;
  private readonly aeadKey: Uint8Array;
  private readonly baseNonce: Uint8Array;
  private readonly salt: Uint8Array;
  private readonly commitment: Uint8Array;
  private buffer: Uint8Array = new Uint8Array(0);
  private chunkIndex = 0;
  private headerEmitted = false;
  private finalized = false;

  constructor(
    crypto: CobblestoneCrypto,
    inputKey: Uint8Array,
    options: CobblestoneEncryptOptions = {},
  ) {
    this.crypto = crypto;
    const variant = options.variant ?? (inputKey.length === 32 ? "cobblestone256" : "cobblestone128");
    const context = options.context ?? new Uint8Array(0);

    const salt = options.salt ?? new Uint8Array(COBBLESTONE_SALT_LENGTH);
    if (options.salt) {
      if (options.salt.length !== COBBLESTONE_SALT_LENGTH) {
        throw new Error(
          `Cobblestone salt must be ${COBBLESTONE_SALT_LENGTH} bytes; received ${options.salt.length}.`,
        );
      }
    } else {
      if (typeof globalThis.crypto?.getRandomValues === "function") {
        globalThis.crypto.getRandomValues(salt);
      } else {
        throw new Error("No CSPRNG available to generate Cobblestone salt.");
      }
    }

    const { aeadKey, baseNonce, commitment } = cobblestoneDeriveKeys(
      crypto,
      inputKey,
      salt,
      context,
      variant,
    );

    this.aeadKey = aeadKey;
    this.baseNonce = baseNonce;
    this.salt = salt;
    this.commitment = commitment;
  }

  getSalt(): Uint8Array {
    return this.salt;
  }

  getCommitment(): Uint8Array {
    return this.commitment;
  }

  update(chunk: Uint8Array): Uint8Array {
    if (this.finalized) {
      throw new Error("CobblestoneEncryptor has already been finalized.");
    }
    if (chunk.length === 0) return new Uint8Array(0);

    const combined = new Uint8Array(this.buffer.length + chunk.length);
    combined.set(this.buffer, 0);
    combined.set(chunk, this.buffer.length);

    const outChunks: Uint8Array[] = [];

    if (!this.headerEmitted) {
      const header = new Uint8Array(COBBLESTONE_HEADER_LENGTH);
      header.set(this.salt, 0);
      header.set(this.commitment, COBBLESTONE_SALT_LENGTH);
      outChunks.push(header);
      this.headerEmitted = true;
    }

    let offset = 0;
    while (combined.length - offset >= COBBLESTONE_CHUNK_SIZE) {
      const ptSlice = combined.subarray(offset, offset + COBBLESTONE_CHUNK_SIZE);
      const nonce = cobblestoneDeriveNonce(this.baseNonce, this.chunkIndex++);
      const enc = this.crypto.aesGcmEncrypt(this.aeadKey, nonce, ptSlice);
      outChunks.push(enc);
      offset += COBBLESTONE_CHUNK_SIZE;
    }

    this.buffer = combined.slice(offset);

    const totalLen = outChunks.reduce((acc, c) => acc + c.length, 0);
    const result = new Uint8Array(totalLen);
    let rOffset = 0;
    for (const c of outChunks) {
      result.set(c, rOffset);
      rOffset += c.length;
    }
    return result;
  }

  finalize(): Uint8Array {
    if (this.finalized) {
      throw new Error("CobblestoneEncryptor has already been finalized.");
    }
    this.finalized = true;

    const outChunks: Uint8Array[] = [];
    if (!this.headerEmitted) {
      const header = new Uint8Array(COBBLESTONE_HEADER_LENGTH);
      header.set(this.salt, 0);
      header.set(this.commitment, COBBLESTONE_SALT_LENGTH);
      outChunks.push(header);
      this.headerEmitted = true;
    }

    // Final chunk is always strictly < 16 KiB
    const nonce = cobblestoneDeriveNonce(this.baseNonce, this.chunkIndex++);
    const enc = this.crypto.aesGcmEncrypt(this.aeadKey, nonce, this.buffer);
    outChunks.push(enc);
    this.buffer = new Uint8Array(0);

    const totalLen = outChunks.reduce((acc, c) => acc + c.length, 0);
    const result = new Uint8Array(totalLen);
    let rOffset = 0;
    for (const c of outChunks) {
      result.set(c, rOffset);
      rOffset += c.length;
    }
    return result;
  }
}

/**
 * Incremental streaming decryptor for Cobblestone.
 */
export class CobblestoneDecryptor {
  private readonly crypto: CobblestoneCrypto;
  private readonly inputKey: Uint8Array;
  private readonly context: Uint8Array;
  private readonly variant: CobblestoneVariant;

  private aeadKey?: Uint8Array;
  private baseNonce?: Uint8Array;
  private salt?: Uint8Array;
  private commitment?: Uint8Array;

  private buffer: Uint8Array = new Uint8Array(0);
  private chunkIndex = 0;
  private headerProcessed = false;
  private finalized = false;

  constructor(
    crypto: CobblestoneCrypto,
    inputKey: Uint8Array,
    options: CobblestoneDecryptOptions = {},
  ) {
    this.crypto = crypto;
    this.inputKey = inputKey;
    this.variant = options.variant ?? (inputKey.length === 32 ? "cobblestone256" : "cobblestone128");
    this.context = options.context ?? new Uint8Array(0);
  }

  update(chunk: Uint8Array): Uint8Array {
    if (this.finalized) {
      throw new Error("CobblestoneDecryptor has already been finalized.");
    }
    if (chunk.length === 0) return new Uint8Array(0);

    const combined = new Uint8Array(this.buffer.length + chunk.length);
    combined.set(this.buffer, 0);
    combined.set(chunk, this.buffer.length);
    this.buffer = combined;

    let offset = 0;

    if (!this.headerProcessed) {
      if (this.buffer.length < COBBLESTONE_HEADER_LENGTH) {
        return new Uint8Array(0);
      }
      this.salt = this.buffer.slice(0, COBBLESTONE_SALT_LENGTH);
      this.commitment = this.buffer.slice(COBBLESTONE_SALT_LENGTH, COBBLESTONE_HEADER_LENGTH);

      const derived = cobblestoneDeriveKeys(
        this.crypto,
        this.inputKey,
        this.salt,
        this.context,
        this.variant,
      );

      if (!constantTimeEqual(this.commitment, derived.commitment)) {
        throw new Error("Invalid Cobblestone commitment: wrong key, corrupted header, or wrong context.");
      }

      this.aeadKey = derived.aeadKey;
      this.baseNonce = derived.baseNonce;
      this.headerProcessed = true;
      offset = COBBLESTONE_HEADER_LENGTH;
    }

    const outChunks: Uint8Array[] = [];

    // In streaming decryption, we only decrypt a chunk if we know it is NOT the final chunk,
    // which requires having at least 16400 + 16 bytes available in the remainder buffer.
    while (this.buffer.length - offset >= COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN + COBBLESTONE_TAG_LENGTH) {
      const ctSlice = this.buffer.subarray(offset, offset + COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN);
      const nonce = cobblestoneDeriveNonce(this.baseNonce!, this.chunkIndex++);
      const dec = this.crypto.aesGcmDecrypt(this.aeadKey!, nonce, ctSlice);
      outChunks.push(dec);
      offset += COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN;
    }

    this.buffer = this.buffer.slice(offset);

    const totalLen = outChunks.reduce((acc, c) => acc + c.length, 0);
    const result = new Uint8Array(totalLen);
    let rOffset = 0;
    for (const c of outChunks) {
      result.set(c, rOffset);
      rOffset += c.length;
    }
    return result;
  }

  finalize(): Uint8Array {
    if (this.finalized) {
      throw new Error("CobblestoneDecryptor has already been finalized.");
    }
    this.finalized = true;

    if (!this.headerProcessed) {
      throw new Error("Cobblestone ciphertext is too short: missing header.");
    }

    // The remaining buffer must be a valid final chunk (16 <= len < 16400)
    if (
      this.buffer.length < COBBLESTONE_TAG_LENGTH ||
      this.buffer.length >= COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN
    ) {
      throw new Error(
        `Cobblestone ciphertext is truncated: final chunk ciphertext length is ${this.buffer.length} bytes (must be between ${COBBLESTONE_TAG_LENGTH} and ${COBBLESTONE_FULL_CHUNK_CIPHERTEXT_LEN - 1} bytes).`,
      );
    }

    const nonce = cobblestoneDeriveNonce(this.baseNonce!, this.chunkIndex++);
    const dec = this.crypto.aesGcmDecrypt(this.aeadKey!, nonce, this.buffer);
    this.buffer = new Uint8Array(0);
    return dec;
  }
}
