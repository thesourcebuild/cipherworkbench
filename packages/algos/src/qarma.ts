/**
 * QARMA Tweakable Block Cipher (Roberto Avanzi, 2016).
 * Selected for ARMv8.3-A Pointer Authentication (PAC).
 *
 * Implements QARMA-64 (8-byte block, 16-byte key, 8-byte tweak).
 */
import type { BlockCipher } from "./blockmodes";

const ALPHA_64 = 0xc0ac29b7c97c50ddn;
const MASK_64 = 0xffffffffffffffffn;

const SIGMA_64 = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2] as const;
const SIGMA_INV_64 = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12] as const;

const SBOX_64 = [0, 14, 2, 10, 9, 15, 8, 11, 6, 4, 3, 7, 13, 12, 1, 5] as const;

const RC_64 = [
  0x0000000000000000n,
  0x13198a2e03707344n,
  0xa4093822299f31d0n,
  0x082efa98ec4e6c89n,
  0x452821e638d01377n,
  0xbe5466cf34e90c6cn,
  0x3f84d5b5b5470917n,
  0x9216d5d98979fb1bn,
];

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

function rot64(v: bigint, bits: bigint): bigint {
  return ((v >> bits) | (v << (64n - bits))) & MASK_64;
}

function getNibble(val: bigint, idx: number): number {
  return Number((val >> BigInt((15 - idx) * 4)) & 0xfn);
}

function setNibble(val: bigint, idx: number, nibble: number): bigint {
  const mask = ~(0xfn << BigInt((15 - idx) * 4)) & MASK_64;
  return (val & mask) | ((BigInt(nibble & 0xf) << BigInt((15 - idx) * 4)) & MASK_64);
}

function shuffleCells(val: bigint, sigma: readonly number[]): bigint {
  let res = 0n;
  for (let i = 0; i < 16; i++) {
    res = setNibble(res, i, getNibble(val, sigma[i]!));
  }
  return res;
}

function subCells(val: bigint): bigint {
  let res = 0n;
  for (let i = 0; i < 16; i++) {
    res = setNibble(res, i, SBOX_64[getNibble(val, i)]!);
  }
  return res;
}

function mixColumns(val: bigint): bigint {
  let res = 0n;
  for (let c = 0; c < 4; c++) {
    const a0 = getNibble(val, c);
    const a1 = getNibble(val, c + 4);
    const a2 = getNibble(val, c + 8);
    const a3 = getNibble(val, c + 12);

    const b0 = a1 ^ a2 ^ a3;
    const b1 = a0 ^ a2 ^ a3;
    const b2 = a0 ^ a1 ^ a3;
    const b3 = a0 ^ a1 ^ a2;

    res = setNibble(res, c, b0);
    res = setNibble(res, c + 4, b1);
    res = setNibble(res, c + 8, b2);
    res = setNibble(res, c + 12, b3);
  }
  return res;
}

export function createQarma64(key: Uint8Array, rounds = 5, tweak?: Uint8Array): BlockCipher {
  const w0 = readU64(key, 0);
  const k0 = readU64(key, 8);

  const w1 = (rot64(w0, 1n) ^ (w0 >> 63n)) & MASK_64;
  const t0 = tweak && tweak.length >= 8 ? readU64(tweak, 0) : 0n;

  function encrypt(input: bigint): bigint {
    let state = (input ^ w0) & MASK_64;
    let t = t0;

    for (let r = 0; r < rounds; r++) {
      state ^= k0 ^ t ^ RC_64[r]!;
      if (r > 0) {
        state = shuffleCells(state, SIGMA_64);
        state = mixColumns(state);
      }
      state = subCells(state);
      t = shuffleCells(t, SIGMA_64);
    }

    // Pseudo-reflector
    state ^= k0 ^ t ^ RC_64[rounds]!;
    state = shuffleCells(state, SIGMA_64);
    state = mixColumns(state);
    state = subCells(state);
    state = mixColumns(state);
    state = shuffleCells(state, SIGMA_INV_64);
    state ^= k0 ^ ALPHA_64 ^ t;

    for (let r = rounds - 1; r >= 0; r--) {
      t = shuffleCells(t, SIGMA_INV_64);
      state = subCells(state);
      if (r > 0) {
        state = mixColumns(state);
        state = shuffleCells(state, SIGMA_INV_64);
      }
      state ^= k0 ^ ALPHA_64 ^ t ^ RC_64[r]!;
    }

    state ^= w1;
    return state & MASK_64;
  }

  function decrypt(input: bigint): bigint {
    let state = (input ^ w1) & MASK_64;
    let t = t0;

    // Invert the backward rounds
    for (let r = 0; r < rounds; r++) {
      state ^= k0 ^ ALPHA_64 ^ t ^ RC_64[r]!;
      if (r > 0) {
        state = shuffleCells(state, SIGMA_64);
        state = mixColumns(state);
      }
      state = subCells(state);
      t = shuffleCells(t, SIGMA_64);
    }

    // Invert the pseudo-reflector
    state ^= k0 ^ ALPHA_64 ^ t;
    state = shuffleCells(state, SIGMA_64);
    state = mixColumns(state);
    state = subCells(state);
    state = mixColumns(state);
    state = shuffleCells(state, SIGMA_INV_64);
    state ^= k0 ^ t ^ RC_64[rounds]!;

    // Invert the forward rounds
    for (let r = rounds - 1; r >= 0; r--) {
      t = shuffleCells(t, SIGMA_INV_64);
      state = subCells(state);
      if (r > 0) {
        state = mixColumns(state);
        state = shuffleCells(state, SIGMA_INV_64);
      }
      state ^= k0 ^ t ^ RC_64[r]!;
    }

    state ^= w0;
    return state & MASK_64;
  }

  return {
    blockSize: 8,
    encryptBlock(src: Uint8Array, dst: Uint8Array): void {
      const state = readU64(src, 0);
      writeU64(dst, 0, encrypt(state));
    },
    decryptBlock(src: Uint8Array, dst: Uint8Array): void {
      const state = readU64(src, 0);
      writeU64(dst, 0, decrypt(state));
    },
  };
}
