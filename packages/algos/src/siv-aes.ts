/**
 * SIV-AES -- Synthetic Initialization Vector Authenticated Encryption (RFC 5297).
 *
 * Implements:
 * - S2V vector-to-string hash using AES-CMAC.
 * - Deterministic authenticated encryption (DAE) and key wrapping.
 * - AES-128-SIV (32-byte key = 16-byte K1 auth + 16-byte K2 enc) and
 *   AES-256-SIV (64-byte key = 32-byte K1 auth + 32-byte K2 enc).
 */

import { aes128BlockEncrypt, aes256BlockEncrypt } from "./aes-round";

export interface SivResult {
  ciphertext: Uint8Array;
  v: Uint8Array; // 16-byte synthetic IV / authentication tag
}

function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return out;
}

function dbl(block: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  let carry = 0;
  for (let i = 15; i >= 0; i--) {
    const byte = block[i] ?? 0;
    const nextCarry = (byte >> 7) & 1;
    out[i] = ((byte << 1) | carry) & 0xff;
    carry = nextCarry;
  }
  if (carry) {
    out[15] = (out[15] ?? 0) ^ 0x87;
  }
  return out;
}

export function aesCmac(key: Uint8Array, message: Uint8Array): Uint8Array {
  const is256 = key.length >= 32;
  const blockEncrypt = is256 ? aes256BlockEncrypt : aes128BlockEncrypt;

  const L = blockEncrypt(key, new Uint8Array(16));
  const K1 = dbl(L);
  const K2 = dbl(K1);

  const n = Math.ceil(message.length / 16) || 1;
  const isComplete = message.length > 0 && message.length % 16 === 0;

  let y = new Uint8Array(16);
  for (let i = 0; i < n - 1; i++) {
    const block = message.subarray(i * 16, i * 16 + 16);
    y = new Uint8Array(blockEncrypt(key, xorBlocks(y, block)));
  }

  const lastBlock = new Uint8Array(16);
  const rem = message.subarray((n - 1) * 16);
  lastBlock.set(rem, 0);

  if (isComplete) {
    for (let j = 0; j < 16; j++) lastBlock[j] = (lastBlock[j] ?? 0) ^ (K1[j] ?? 0);
  } else {
    lastBlock[rem.length] = 0x80;
    for (let j = 0; j < 16; j++) lastBlock[j] = (lastBlock[j] ?? 0) ^ (K2[j] ?? 0);
  }

  return blockEncrypt(key, xorBlocks(y, lastBlock));
}

export function s2v(key: Uint8Array, adList: Uint8Array[]): Uint8Array {
  let d = aesCmac(key, new Uint8Array(16));
  for (let i = 0; i < adList.length - 1; i++) {
    const ad = adList[i];
    if (ad) {
      d = xorBlocks(dbl(d), aesCmac(key, ad));
    }
  }

  const sn = adList[adList.length - 1] ?? new Uint8Array(0);
  if (sn.length >= 16) {
    // xorend(sn, d)
    const snCopy = new Uint8Array(sn);
    const start = snCopy.length - 16;
    for (let j = 0; j < 16; j++) {
      snCopy[start + j] = (snCopy[start + j] ?? 0) ^ (d[j] ?? 0);
    }
    return aesCmac(key, snCopy);
  } else {
    const pad = new Uint8Array(16);
    pad.set(sn, 0);
    pad[sn.length] = 0x80;
    return aesCmac(key, xorBlocks(dbl(d), pad));
  }
}

export function sivEncrypt(
  key: Uint8Array, // 32 bytes for SIV-AES-128, 64 bytes for SIV-AES-256
  plaintext: Uint8Array,
  adList: Uint8Array[] = [],
): SivResult {
  const kHalf = key.length / 2;
  const k1 = key.subarray(0, kHalf); // Auth key
  const k2 = key.subarray(kHalf); // Enc key

  const blockEncrypt = kHalf >= 32 ? aes256BlockEncrypt : aes128BlockEncrypt;

  // 1. V = S2V(K1, AD_1, ..., AD_n, Plaintext)
  const v = s2v(k1, [...adList, plaintext]);

  // 2. CTR encryption starting with V masked
  const q = new Uint8Array(v);
  q[8] = (q[8] ?? 0) & 0x7f;
  q[12] = (q[12] ?? 0) & 0x7f;

  const ciphertext = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i += 16) {
    const stream = blockEncrypt(k2, q);
    const take = Math.min(16, plaintext.length - i);
    for (let j = 0; j < take; j++) {
      ciphertext[i + j] = (plaintext[i + j] ?? 0) ^ (stream[j] ?? 0);
    }

    // Increment Q as 128-bit integer
    for (let j = 15; j >= 0; j--) {
      q[j] = ((q[j] ?? 0) + 1) & 0xff;
      if (q[j] !== 0) break;
    }
  }

  return { ciphertext, v };
}

export function sivDecrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  v: Uint8Array,
  adList: Uint8Array[] = [],
): Uint8Array {
  const kHalf = key.length / 2;
  const k1 = key.subarray(0, kHalf);
  const k2 = key.subarray(kHalf);

  const blockEncrypt = kHalf >= 32 ? aes256BlockEncrypt : aes128BlockEncrypt;

  // Decrypt CTR
  const q = new Uint8Array(v);
  q[8] = (q[8] ?? 0) & 0x7f;
  q[12] = (q[12] ?? 0) & 0x7f;

  const plaintext = new Uint8Array(ciphertext.length);
  for (let i = 0; i < ciphertext.length; i += 16) {
    const stream = blockEncrypt(k2, q);
    const take = Math.min(16, ciphertext.length - i);
    for (let j = 0; j < take; j++) {
      plaintext[i + j] = (ciphertext[i + j] ?? 0) ^ (stream[j] ?? 0);
    }

    for (let j = 15; j >= 0; j--) {
      q[j] = ((q[j] ?? 0) + 1) & 0xff;
      if (q[j] !== 0) break;
    }
  }

  // Verify V == S2V(K1, AD..., Plaintext)
  const computedV = s2v(k1, [...adList, plaintext]);
  for (let j = 0; j < 16; j++) {
    if (computedV[j] !== v[j]) {
      throw new Error("SIV authentication failed: synthetic IV mismatch");
    }
  }

  return plaintext;
}
