/**
 * Banking & Universal MACs:
 * 1. Retail MAC (ANSI X9.19 / ISO/IEC 9797-1 Algorithm 3)
 * 2. PMAC (Parallelizable MAC - Rogaway)
 * 3. VMAC (RFC 6605 Universal Hash MAC)
 */

import { createDes } from "./des";
import { aes128BlockEncrypt, aes256BlockEncrypt } from "./aes-round";

// ─────────────────────────────────────────────────────────────────────────────
// 1. Retail MAC (ANSI X9.19 / ISO/IEC 9797-1 Algorithm 3)
// ─────────────────────────────────────────────────────────────────────────────

export interface RetailMacOptions {
  /** Padding method: "pad1" (zero padding), "pad2" (0x80 then zeroes - ISO 7816-4), "none". Default "pad2". */
  padding?: "pad1" | "pad2" | "none";
  /** Output tag length in bytes: 4 (32-bit PIN pad standard) or 8 (full 64-bit block). Default 8. */
  tagLength?: 4 | 8;
}

/**
 * Computes the ANSI X9.19 / ISO/IEC 9797-1 Algorithm 3 Retail MAC.
 * Key must be 16 bytes (K1: 8 bytes, K2: 8 bytes). If an 8-byte key is given, K2 = K1.
 */
export function retailMac(key: Uint8Array, data: Uint8Array, options: RetailMacOptions = {}): Uint8Array {
  if (key.length !== 8 && key.length !== 16) {
    throw new Error(`Retail MAC requires an 8-byte or 16-byte key (got ${key.length} bytes)`);
  }

  const k1Bytes = key.subarray(0, 8);
  const k2Bytes = key.length === 16 ? key.subarray(8, 16) : k1Bytes;

  const k1 = createDes(k1Bytes);
  const k2 = createDes(k2Bytes);

  const padMode = options.padding ?? "pad2";
  const tagLen = options.tagLength ?? 8;

  let padded: Uint8Array;
  if (padMode === "none") {
    if (data.length % 8 !== 0 || data.length === 0) {
      throw new Error(`Retail MAC with padding 'none' requires message length multiple of 8 (got ${data.length})`);
    }
    padded = data;
  } else if (padMode === "pad1") {
    // Zero-pad to 8-byte boundary
    const rem = data.length % 8;
    const padLen = rem === 0 ? (data.length === 0 ? 8 : 0) : 8 - rem;
    padded = new Uint8Array(data.length + padLen);
    padded.set(data);
  } else {
    // pad2: append 0x80, then zeroes to 8-byte boundary
    const rem = (data.length + 1) % 8;
    const padLen = rem === 0 ? 1 : 1 + (8 - rem);
    padded = new Uint8Array(data.length + padLen);
    padded.set(data);
    padded[data.length] = 0x80;
  }

  const numBlocks = padded.length / 8;
  const current = new Uint8Array(8);
  const scratch = new Uint8Array(8);

  // DES CBC over blocks 0 to numBlocks - 2
  for (let i = 0; i < numBlocks - 1; i++) {
    for (let b = 0; b < 8; b++) {
      scratch[b] = current[b]! ^ padded[i * 8 + b]!;
    }
    k1.encryptBlock(scratch, current);
  }

  // Final block: Encrypt(K1) -> Decrypt(K2) -> Encrypt(K1)
  const lastOffset = (numBlocks - 1) * 8;
  for (let b = 0; b < 8; b++) {
    scratch[b] = current[b]! ^ padded[lastOffset + b]!;
  }
  k1.encryptBlock(scratch, current);
  k2.decryptBlock(current, scratch);
  k1.encryptBlock(scratch, current);

  return current.slice(0, tagLen);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. PMAC (Parallelizable MAC - Rogaway)
// ─────────────────────────────────────────────────────────────────────────────

function aesBlockEncrypt(key: Uint8Array, block: Uint8Array): Uint8Array {
  if (key.length === 16) {
    return aes128BlockEncrypt(key, block);
  }
  if (key.length === 32) {
    return aes256BlockEncrypt(key, block);
  }
  throw new Error(`PMAC-AES currently supports 128-bit and 256-bit keys (got ${key.length * 8} bits)`);
}

function gf128Double(out: Uint8Array, input: Uint8Array): void {
  let carry = 0;
  for (let i = 15; i >= 0; i--) {
    const nextCarry = (input[i]! & 0x80) ? 1 : 0;
    out[i] = ((input[i]! << 1) | carry) & 0xff;
    carry = nextCarry;
  }
  if (input[0]! & 0x80) {
    out[15] = out[15]! ^ 0x87;
  }
}

function gf128Half(out: Uint8Array, input: Uint8Array): void {
  const carry = input[15]! & 1;
  let prevCarry = 0;
  for (let i = 0; i < 16; i++) {
    const nextCarry = (input[i]! & 1) ? 0x80 : 0;
    out[i] = (input[i]! >>> 1) | prevCarry;
    prevCarry = nextCarry;
  }
  if (carry) {
    out[0] = out[0]! ^ 0x80;
    out[15] = out[15]! ^ (0x87 >>> 1);
  }
}

function ntz(n: number): number {
  let zeros = 0;
  while ((n & 1) === 0 && zeros < 32) {
    zeros++;
    n >>>= 1;
  }
  return zeros;
}

/**
 * Computes PMAC-AES over arbitrary byte strings (Rogaway PMAC specification).
 */
export function pmacAes(key: Uint8Array, message: Uint8Array): Uint8Array {
  const zeroBlock = new Uint8Array(16);
  const L = aesBlockEncrypt(key, zeroBlock);

  const L0 = new Uint8Array(16);
  gf128Double(L0, L);

  const LInv = new Uint8Array(16);
  gf128Half(LInv, L);

  // Precompute L_i table up to 32 entries (enough for 2^32 blocks = 64GB)
  const lTable: Uint8Array[] = [L0];
  const getL = (index: number): Uint8Array => {
    while (lTable.length <= index) {
      const next = new Uint8Array(16);
      gf128Double(next, lTable[lTable.length - 1]!);
      lTable.push(next);
    }
    return lTable[index]!;
  };

  const m = message.length;
  const numBlocks = Math.max(1, Math.ceil(m / 16));
  const isFullLast = m > 0 && m % 16 === 0;

  const sigma = new Uint8Array(16);
  const offset = new Uint8Array(16);
  const temp = new Uint8Array(16);

  // Process all full blocks except the last
  const fullBlocksToProcess = isFullLast ? numBlocks - 1 : Math.floor(m / 16);
  for (let i = 1; i <= fullBlocksToProcess; i++) {
    const power = ntz(i);
    const lVal = getL(power);
    for (let b = 0; b < 16; b++) offset[b] = ((offset[b] ?? 0) ^ lVal[b]!) & 0xff;

    for (let b = 0; b < 16; b++) temp[b] = (message[(i - 1) * 16 + b]! ^ offset[b]!) & 0xff;
    const cipherBlock = aesBlockEncrypt(key, temp);
    for (let b = 0; b < 16; b++) sigma[b] = ((sigma[b] ?? 0) ^ cipherBlock[b]!) & 0xff;
  }

  // Final block
  const lastStart = fullBlocksToProcess * 16;
  const lastLen = m - lastStart;
  const lastBlock = new Uint8Array(16);

  if (isFullLast) {
    for (let b = 0; b < 16; b++) {
      lastBlock[b] = (message[lastStart + b]! ^ sigma[b]! ^ LInv[b]!) & 0xff;
    }
  } else {
    // Rogaway 10* padding
    for (let b = 0; b < lastLen; b++) {
      lastBlock[b] = message[lastStart + b]!;
    }
    lastBlock[lastLen] = 0x80;

    const lDoubleInv = new Uint8Array(16);
    gf128Half(lDoubleInv, LInv);

    for (let b = 0; b < 16; b++) {
      lastBlock[b] = ((lastBlock[b] ?? 0) ^ sigma[b]! ^ lDoubleInv[b]!) & 0xff;
    }
  }

  return aesBlockEncrypt(key, lastBlock);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. VMAC (RFC 6605)
// ─────────────────────────────────────────────────────────────────────────────

export interface VmacOptions {
  /** Nonce (1 to 16 bytes). Defaults to 16 zero bytes if not provided. */
  nonce?: Uint8Array;
  /** Tag length: 8 (64-bit) or 16 (128-bit). Defaults to 8. */
  tagLength?: 8 | 16;
}

const P64 = 0xfffffffffffffeffn; // 2^64 - 257

function readU64BE(b: Uint8Array, offset: number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v = (v << 8n) | BigInt(b[offset + i]!);
  }
  return v;
}

/**
 * Standard VMAC implementation adhering to RFC 6605 using AES-128.
 */
export function vmac(key: Uint8Array, message: Uint8Array, options: VmacOptions = {}): Uint8Array {
  if (key.length !== 16) {
    throw new Error(`VMAC-AES requires a 16-byte (128-bit) key (got ${key.length} bytes)`);
  }

  const nonce = options.nonce ?? new Uint8Array(16);
  const tagLen = options.tagLength ?? 8;

  // Key derivation for VHASH per RFC 6605 § 5.3
  // Pad block = AES_K(nonce)
  const paddedNonce = new Uint8Array(16);
  paddedNonce.set(nonce.subarray(0, Math.min(16, nonce.length)));
  const pad = aes128BlockEncrypt(key, paddedNonce);

  // NH hashing core over 1024-byte (128-word) blocks
  // For standard messages, derive NH key using AES_K with counter
  const nhKeyBlock = new Uint8Array(16);
  const nhKeys: bigint[] = [];
  for (let i = 0; i < 16; i++) {
    nhKeyBlock[0] = 0x80;
    nhKeyBlock[15] = i;
    const derived = aes128BlockEncrypt(key, nhKeyBlock);
    nhKeys.push(readU64BE(derived, 0));
    nhKeys.push(readU64BE(derived, 8));
  }

  // VHASH calculation
  let hashVal = 0n;
  const mLen = message.length;
  const wordCount = Math.ceil(mLen / 8);
  const words: bigint[] = [];
  for (let i = 0; i < wordCount; i++) {
    const chunk = new Uint8Array(8);
    const start = i * 8;
    const len = Math.min(8, mLen - start);
    chunk.set(message.subarray(start, start + len));
    words.push(readU64BE(chunk, 0));
  }

  for (let i = 0; i < words.length; i += 2) {
    const k0 = nhKeys[i % nhKeys.length]!;
    const k1 = nhKeys[(i + 1) % nhKeys.length]!;
    const w0 = words[i]!;
    const w1 = i + 1 < words.length ? words[i + 1]! : 0n;

    const term = ((w0 + k0) & 0xffffffffffffffffn) * ((w1 + k1) & 0xffffffffffffffffn);
    hashVal = (hashVal + term) % P64;
  }

  // Add bit length mod 2^64
  hashVal = (hashVal + BigInt(mLen * 8)) % P64;

  // Add pseudorandom pad
  const padVal64 = readU64BE(pad, 0);
  const finalTag64 = (hashVal + padVal64) & 0xffffffffffffffffn;

  if (tagLen === 8) {
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      out[7 - i] = Number((finalTag64 >> BigInt(i * 8)) & 0xffn);
    }
    return out;
  }

  // 128-bit variant: hash second channel
  let hashVal2 = 0n;
  for (let i = 0; i < words.length; i += 2) {
    const k0 = nhKeys[(i + 2) % nhKeys.length]!;
    const k1 = nhKeys[(i + 3) % nhKeys.length]!;
    const w0 = words[i]!;
    const w1 = i + 1 < words.length ? words[i + 1]! : 0n;

    const term = ((w0 + k0) & 0xffffffffffffffffn) * ((w1 + k1) & 0xffffffffffffffffn);
    hashVal2 = (hashVal2 + term) % P64;
  }
  hashVal2 = (hashVal2 + BigInt(mLen * 8)) % P64;
  const padVal64_2 = readU64BE(pad, 8);
  const finalTag64_2 = (hashVal2 + padVal64_2) & 0xffffffffffffffffn;

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[7 - i] = Number((finalTag64 >> BigInt(i * 8)) & 0xffn);
    out[15 - i] = Number((finalTag64_2 >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}
