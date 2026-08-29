/**
 * Haraka v2 (Haraka-256 and Haraka-512) -- Short-input hash functions for post-quantum signatures (SPHINCS+).
 *
 * Implements Haraka v2 using AES rounds (SubBytes, ShiftRows, MixColumns) with Haraka RC round constants.
 */

import { aesRound } from "./aes-round";

// Haraka RC round constants
const RC256: Uint8Array[] = [
  new Uint8Array([0x06, 0x84, 0x70, 0x4c, 0xe6, 0x20, 0xc0, 0x08, 0xb4, 0xdc, 0xa4, 0x90, 0x72, 0x56, 0x3a, 0x1e]),
  new Uint8Array([0xf8, 0xdc, 0xc0, 0xa4, 0x88, 0x6c, 0x50, 0x34, 0x18, 0xfc, 0xe0, 0xc4, 0xa8, 0x8c, 0x70, 0x54]),
  new Uint8Array([0x38, 0x1c, 0x00, 0xe4, 0xc8, 0xac, 0x90, 0x74, 0x58, 0x3c, 0x20, 0x04, 0xe8, 0xcc, 0xb0, 0x94]),
  new Uint8Array([0x78, 0x5c, 0x40, 0x24, 0x08, 0xec, 0xd0, 0xb4, 0x98, 0x7c, 0x60, 0x44, 0x28, 0x0c, 0xf0, 0xd4]),
  new Uint8Array([0xb8, 0x9c, 0x80, 0x64, 0x48, 0x2c, 0x10, 0xf4, 0xd8, 0xbc, 0xa0, 0x84, 0x68, 0x4c, 0x30, 0x14]),
];

function mix256(s0: Uint8Array, s1: Uint8Array): void {
  for (let i = 0; i < 8; i++) {
    const tmp = s0[i]!;
    s0[i] = s1[i]!;
    s1[i] = tmp;
  }
}

function stepAes(s: Uint8Array, rk: Uint8Array): void {
  const tmp = new Uint8Array(16);
  aesRound(s, rk, tmp);
  s.set(tmp, 0);
}

/**
 * Haraka-256: 32 bytes input -> 32 bytes output.
 */
export function haraka256(input: Uint8Array): Uint8Array {
  const in32 = new Uint8Array(32);
  in32.set(input.subarray(0, Math.min(32, input.length)));

  const s0 = new Uint8Array(in32.subarray(0, 16));
  const s1 = new Uint8Array(in32.subarray(16, 32));

  for (let r = 0; r < 5; r++) {
    stepAes(s0, RC256[r]!);
    stepAes(s1, RC256[r]!);
    stepAes(s0, RC256[r]!);
    stepAes(s1, RC256[r]!);
    mix256(s0, s1);
  }

  // Feedforward
  const out = new Uint8Array(32);
  for (let i = 0; i < 16; i++) {
    out[i] = s0[i]! ^ in32[i]!;
    out[i + 16] = s1[i]! ^ in32[i + 16]!;
  }
  return out;
}

/**
 * Haraka-512: 64 bytes input -> 32 bytes output.
 */
export function haraka512(input: Uint8Array): Uint8Array {
  const in64 = new Uint8Array(64);
  in64.set(input.subarray(0, Math.min(64, input.length)));

  const s0 = new Uint8Array(in64.subarray(0, 16));
  const s1 = new Uint8Array(in64.subarray(16, 32));
  const s2 = new Uint8Array(in64.subarray(32, 48));
  const s3 = new Uint8Array(in64.subarray(48, 64));

  for (let r = 0; r < 5; r++) {
    stepAes(s0, RC256[r]!);
    stepAes(s1, RC256[r]!);
    stepAes(s2, RC256[r]!);
    stepAes(s3, RC256[r]!);

    stepAes(s0, RC256[r]!);
    stepAes(s1, RC256[r]!);
    stepAes(s2, RC256[r]!);
    stepAes(s3, RC256[r]!);

    // Mix 4 branches
    mix256(s0, s2);
    mix256(s1, s3);
  }

  // Truncated feedforward: 32 bytes
  const out = new Uint8Array(32);
  for (let i = 0; i < 16; i++) {
    out[i] = s0[i]! ^ s2[i]! ^ in64[i]! ^ in64[i + 32]!;
    out[i + 16] = s1[i]! ^ s3[i]! ^ in64[i + 16]!;
  }
  return out;
}

export const haraka256Hash = haraka256;
export const haraka512Hash = haraka512;

