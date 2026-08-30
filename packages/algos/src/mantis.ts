/**
 * MANTIS Tweakable Block Cipher (Beierle et al., CRYPTO 2016).
 *
 * Dedicated low-latency memory encryption cipher based on Midori & Skinny components with α-reflection.
 * - Block: 64 bits (8 bytes).
 * - Key: 128 bits (16 bytes).
 * - Tweak: 64 bits (8 bytes).
 * - Rounds: MANTIS-5 (r=5), MANTIS-7 (r=7), MANTIS-8 (r=8).
 */
import type { BlockCipher } from "./blockmodes";

const MANTIS_SBOX = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6];

const MANTIS_PERM = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2];
const MANTIS_PERM_INV = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12];

const MANTIS_TWEAK_P = [6, 5, 14, 15, 0, 1, 2, 3, 7, 12, 13, 4, 8, 9, 10, 11];
const MANTIS_TWEAK_P_INV = [4, 5, 6, 7, 11, 1, 0, 8, 12, 13, 14, 15, 9, 10, 2, 3];

const MANTIS_RC = [
  0x0000000000000000n,
  0x13198a2e03707344n,
  0xa4093822299f31d0n,
  0x082efa98ec4e6c89n,
  0x452821e638d01377n,
  0xbe5466cf34e90c6cn,
  0x3f84d5b5b5470917n,
  0x9216d5d98979fb1bn,
];

const ALPHA = 0x243f6a8885a308d3n;
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

function permuteNibbles(val: bigint, perm: readonly number[]): bigint {
  let res = 0n;
  for (let i = 0; i < 16; i++) {
    res = setNibble(res, i, getNibble(val, perm[i]!));
  }
  return res;
}

function subNibbles(val: bigint): bigint {
  let res = 0n;
  for (let i = 0; i < 16; i++) {
    res = setNibble(res, i, MANTIS_SBOX[getNibble(val, i)]!);
  }
  return res;
}

function mixColumns(val: bigint): bigint {
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

function mantisCore(
  input: bigint,
  k0In: bigint,
  k0Out: bigint,
  k1Val: bigint,
  tweakVal: bigint,
  rounds: number,
): bigint {
  let state = (input ^ k0In ^ k1Val ^ tweakVal) & MASK_64;
  let t = tweakVal;

  for (let r = 0; r < rounds; r++) {
    state = subNibbles(state);
    state ^= k1Val ^ t ^ MANTIS_RC[r]!;
    state = permuteNibbles(state, MANTIS_PERM);
    state = mixColumns(state);
    t = permuteNibbles(t, MANTIS_TWEAK_P);
  }

  state = subNibbles(state);
  state = mixColumns(state);
  state = subNibbles(state);

  for (let r = rounds - 1; r >= 0; r--) {
    t = permuteNibbles(t, MANTIS_TWEAK_P_INV);
    state = mixColumns(state);
    state = permuteNibbles(state, MANTIS_PERM_INV);
    state ^= k1Val ^ t ^ ALPHA ^ MANTIS_RC[r]!;
    state = subNibbles(state);
  }

  state ^= k0Out ^ k1Val ^ ALPHA ^ tweakVal;
  return state & MASK_64;
}

export function createMantis(key: Uint8Array, rounds = 7, tweak?: Uint8Array): BlockCipher {
  const k0 = readU64(key, 0);
  const k1 = readU64(key, 8);

  const k0Prime = (rot64(k0, 1n) ^ (k0 >> 63n)) & MASK_64;
  const t0 = tweak && tweak.length >= 8 ? readU64(tweak, 0) : 0n;

  return {
    blockSize: 8,
    encryptBlock(src: Uint8Array, dst: Uint8Array): void {
      const state = readU64(src, 0);
      const out = mantisCore(state, k0, k0Prime, k1, t0, rounds);
      writeU64(dst, 0, out);
    },
    decryptBlock(src: Uint8Array, dst: Uint8Array): void {
      const state = readU64(src, 0);
      const out = mantisCore(state, k0Prime, k0, k1 ^ ALPHA, t0, rounds);
      writeU64(dst, 0, out);
    },
  };
}
