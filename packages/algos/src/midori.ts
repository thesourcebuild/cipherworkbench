/**
 * Midori Ultra-Low Energy Block Cipher (Banik et al., ASIACRYPT 2015).
 * Optimized for energy efficiency in ubiquitous / IoT devices.
 *
 * - Midori-64: 64-bit block (16 nibbles), 128-bit key, 16 rounds.
 * - Midori-128: 128-bit block (16 bytes), 128-bit key, 20 rounds.
 */
import type { BlockCipher } from "./blockmodes";

const MIDORI_SBOX0 = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6];

const MIDORI_P = [0, 10, 5, 15, 14, 4, 11, 1, 9, 3, 12, 6, 7, 13, 2, 8];
const MIDORI_P_INV = [0, 7, 14, 9, 5, 2, 11, 12, 15, 8, 1, 6, 10, 13, 4, 3];

const MIDORI64_RC = [
  0x0001010100010001n,
  0x0000010000010000n,
  0x0100000000000100n,
  0x0001010001000001n,
  0x0100010101010100n,
  0x0101000000010101n,
  0x0001000101000100n,
  0x0001010101010000n,
  0x0101010000000101n,
  0x0100000101000001n,
  0x0001010000010100n,
  0x0000010101000000n,
  0x0100010100010001n,
  0x0101000101010000n,
  0x0101010001000101n,
];

const MASK_64 = 0xffffffffffffffffn;

function readU64(b: Uint8Array, o = 0): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    const byte = o + i < b.length ? BigInt(b[o + i]!) : 0n;
    v = (v << 8n) | byte;
  }
  return v;
}

function writeU64(b: Uint8Array, o: number, v: bigint): void {
  for (let i = 7; i >= 0; i--) {
    if (o + i < b.length) {
      b[o + i] = Number(v & 0xffn);
    }
    v >>= 8n;
  }
}

function getNibble(val: bigint, idx: number): number {
  return Number((val >> BigInt((15 - idx) * 4)) & 0xfn);
}

function setNibble(val: bigint, idx: number, nibble: number): bigint {
  const mask = ~(0xfn << BigInt((15 - idx) * 4)) & MASK_64;
  return (val & mask) | ((BigInt(nibble & 0xf) << BigInt((15 - idx) * 4)) & MASK_64);
}

function subCell(val: bigint): bigint {
  let res = 0n;
  for (let i = 0; i < 16; i++) {
    res = setNibble(res, i, MIDORI_SBOX0[getNibble(val, i)]!);
  }
  return res;
}

function shuffleCell(val: bigint, p: number[]): bigint {
  let res = 0n;
  for (let i = 0; i < 16; i++) {
    res = setNibble(res, i, getNibble(val, p[i]!));
  }
  return res;
}

function mixColumn(val: bigint): bigint {
  let res = 0n;
  for (let c = 0; c < 4; c++) {
    const s0 = getNibble(val, c);
    const s1 = getNibble(val, c + 4);
    const s2 = getNibble(val, c + 8);
    const s3 = getNibble(val, c + 12);

    const m0 = s1 ^ s2 ^ s3;
    const m1 = s0 ^ s2 ^ s3;
    const m2 = s0 ^ s1 ^ s3;
    const m3 = s0 ^ s1 ^ s2;

    res = setNibble(res, c, m0);
    res = setNibble(res, c + 4, m1);
    res = setNibble(res, c + 8, m2);
    res = setNibble(res, c + 12, m3);
  }
  return res;
}

export function createMidori64(key: Uint8Array): BlockCipher {
  const k0 = readU64(key, 0);
  const k1 = readU64(key, 8);
  const k = k0 ^ k1;

  return {
    blockSize: 8,
    encryptBlock(src: Uint8Array, dst: Uint8Array): void {
      let state = readU64(src, 0) ^ k0;

      for (let r = 0; r < 15; r++) {
        state = subCell(state);
        state = shuffleCell(state, MIDORI_P);
        state = mixColumn(state);
        state ^= k ^ MIDORI64_RC[r]!;
      }

      state = subCell(state);
      state ^= k1;

      writeU64(dst, 0, state);
    },
    decryptBlock(src: Uint8Array, dst: Uint8Array): void {
      let state = readU64(src, 0) ^ k1;
      state = subCell(state);

      for (let r = 14; r >= 0; r--) {
        state ^= k ^ MIDORI64_RC[r]!;
        state = mixColumn(state);
        state = shuffleCell(state, MIDORI_P_INV);
        state = subCell(state);
      }

      state ^= k0;
      writeU64(dst, 0, state);
    },
  };
}
