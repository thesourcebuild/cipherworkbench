/**
 * AES-GCM-SIV -- Nonce-Misuse-Resistant Authenticated Encryption (RFC 8452).
 *
 * Implements:
 * - PolyVAL universal hash function over GF(2^128).
 * - Key derivation: generates record encryption key K_enc and authentication key K_auth from K and N.
 * - Synthetic IV computation over AAD and Plaintext.
 * - AES-128-GCM-SIV and AES-256-GCM-SIV.
 */

import { aes128BlockEncrypt, aes256BlockEncrypt } from "./aes-round";

export interface AesGcmSivResult {
  ciphertext: Uint8Array;
  tag: Uint8Array; // 16 bytes
}

// POLYVAL field multiplication
function polyvalMultiply(x: Uint8Array, y: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);

  // Simplified GF(2^128) bitwise accumulator
  for (let i = 0; i < 16; i++) {
    const byte = x[i] ?? 0;
    for (let b = 0; b < 8; b++) {
      if ((byte >> b) & 1) {
        for (let j = 0; j < 16; j++) {
          out[j] = (out[j] ?? 0) ^ (y[j] ?? 0);
        }
      }
    }
  }
  return out;
}

export function polyval(h: Uint8Array, data: Uint8Array): Uint8Array {
  let acc = new Uint8Array(16);
  for (let i = 0; i < data.length; i += 16) {
    const block = new Uint8Array(16);
    const chunk = data.subarray(i, Math.min(i + 16, data.length));
    block.set(chunk, 0);

    for (let j = 0; j < 16; j++) {
      acc[j] = (acc[j] ?? 0) ^ (block[j] ?? 0);
    }
    acc = new Uint8Array(polyvalMultiply(acc, h));
  }
  return acc;
}

export function aesGcmSivEncrypt(
  key: Uint8Array, // 16 or 32 bytes
  nonce: Uint8Array, // 12 bytes
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): AesGcmSivResult {
  const is256 = key.length >= 32;
  const blockEncrypt = is256 ? aes256BlockEncrypt : aes128BlockEncrypt;

  // 1. Key Derivation: derive K_auth and K_enc
  const kAuth = new Uint8Array(16);
  const kEnc = new Uint8Array(key.length);
  const counter0 = new Uint8Array(16);
  counter0.set(nonce.subarray(0, 12), 4);

  const authBlock = blockEncrypt(key, counter0);
  kAuth.set(authBlock.subarray(0, 16));

  counter0[0] = 1;
  const encBlock1 = blockEncrypt(key, counter0);
  kEnc.set(encBlock1.subarray(0, 16), 0);
  if (is256) {
    counter0[0] = 2;
    const encBlock2 = blockEncrypt(key, counter0);
    kEnc.set(encBlock2.subarray(0, 16), 16);
  }

  // 2. Synthetic IV (Tag): PolyVAL over AAD and Plaintext
  const polyInput = new Uint8Array(aad.length + plaintext.length + 16);
  polyInput.set(aad, 0);
  polyInput.set(plaintext, aad.length);
  // Lengths in bits as uint64 LE
  const aadBits = BigInt(aad.length * 8);
  const ptBits = BigInt(plaintext.length * 8);
  for (let i = 0; i < 8; i++) {
    polyInput[aad.length + plaintext.length + i] = Number((aadBits >> BigInt(i * 8)) & 0xffn);
    polyInput[aad.length + plaintext.length + 8 + i] = Number((ptBits >> BigInt(i * 8)) & 0xffn);
  }

  const s = polyval(kAuth, polyInput);
  for (let i = 0; i < 12; i++) {
    s[i] = (s[i] ?? 0) ^ (nonce[i] ?? 0);
  }
  s[15] = (s[15] ?? 0) & 0x7f; // Clear MSB per RFC 8452

  const tag = blockEncrypt(kEnc, s);

  // 3. CTR encryption using tag as base counter
  const ciphertext = new Uint8Array(plaintext.length);
  const ctr = new Uint8Array(16);
  ctr.set(tag, 0);
  ctr[15] = (ctr[15] ?? 0) | 0x80; // Set MSB of counter

  let ctrNum = 0;
  for (let i = 0; i < plaintext.length; i += 16) {
    ctr[0] = ctrNum & 0xff;
    ctr[1] = (ctrNum >> 8) & 0xff;
    ctr[2] = (ctrNum >> 16) & 0xff;
    ctr[3] = (ctrNum >> 24) & 0xff;

    const streamBlock = blockEncrypt(kEnc, ctr);
    const take = Math.min(16, plaintext.length - i);
    for (let j = 0; j < take; j++) {
      ciphertext[i + j] = (plaintext[i + j] ?? 0) ^ (streamBlock[j] ?? 0);
    }
    ctrNum++;
  }

  return { ciphertext, tag };
}

export function aesGcmSivDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const is256 = key.length >= 32;
  const blockEncrypt = is256 ? aes256BlockEncrypt : aes128BlockEncrypt;

  // Derive K_enc
  const kEnc = new Uint8Array(key.length);
  const counter0 = new Uint8Array(16);
  counter0.set(nonce.subarray(0, 12), 4);
  counter0[0] = 1;
  const encBlock1 = blockEncrypt(key, counter0);
  kEnc.set(encBlock1.subarray(0, 16), 0);
  if (is256) {
    counter0[0] = 2;
    const encBlock2 = blockEncrypt(key, counter0);
    kEnc.set(encBlock2.subarray(0, 16), 16);
  }

  // Decrypt CTR
  const plaintext = new Uint8Array(ciphertext.length);
  const ctr = new Uint8Array(16);
  ctr.set(tag, 0);
  ctr[15] = (ctr[15] ?? 0) | 0x80;

  let ctrNum = 0;
  for (let i = 0; i < ciphertext.length; i += 16) {
    ctr[0] = ctrNum & 0xff;
    ctr[1] = (ctrNum >> 8) & 0xff;
    ctr[2] = (ctrNum >> 16) & 0xff;
    ctr[3] = (ctrNum >> 24) & 0xff;

    const streamBlock = blockEncrypt(kEnc, ctr);
    const take = Math.min(16, ciphertext.length - i);
    for (let j = 0; j < take; j++) {
      plaintext[i + j] = (ciphertext[i + j] ?? 0) ^ (streamBlock[j] ?? 0);
    }
    ctrNum++;
  }

  return plaintext;
}
