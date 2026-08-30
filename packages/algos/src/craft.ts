/**
 * CRAFT Lightweight Tweakable Block Cipher (Beierle et al., FSE/ToSC 2019).
 * Designed for efficient protection against fault attacks and side-channel leakage.
 *
 * - Block: 64 bits (16 nibbles)
 * - Key: 128 bits (divided into K0, K1 of 64 bits each)
 * - Tweak: 64 bits
 * - Rounds: 32
 */
import type { BlockCipher } from "./blockmodes";

const CRAFT_SBOX = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6];

const CRAFT_P = [15, 12, 13, 14, 10, 9, 8, 11, 6, 5, 4, 7, 1, 2, 3, 0];
const CRAFT_P_INV = [15, 12, 13, 14, 10, 9, 8, 11, 6, 5, 4, 7, 1, 2, 3, 0];

const CRAFT_RC_4 = [
  0x1, 0x3, 0x7, 0xf, 0xf, 0xf, 0xe, 0xd,
  0xa, 0x5, 0xa, 0x5, 0xb, 0x6, 0xc, 0x9,
  0x3, 0x6, 0xd, 0xb, 0x7, 0xe, 0xd, 0xa,
  0x4, 0x9, 0x2, 0x4, 0x9, 0x3, 0x6, 0xc,
];

const CRAFT_RC_3 = [
  0x1, 0x2, 0x4, 0x0, 0x1, 0x3, 0x6, 0x5,
  0x3, 0x7, 0x6, 0x4, 0x1, 0x2, 0x5, 0x2,
  0x5, 0x3, 0x7, 0x7, 0x6, 0x5, 0x2, 0x4,
  0x1, 0x3, 0x7, 0x6, 0x4, 0x0, 0x0, 0x1,
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

function subBox(val: bigint): bigint {
  let res = 0n;
  for (let i = 0; i < 16; i++) {
    res = setNibble(res, i, CRAFT_SBOX[getNibble(val, i)]!);
  }
  return res;
}

function permuteNibbles(val: bigint, p: number[]): bigint {
  let res = 0n;
  for (let i = 0; i < 16; i++) {
    res = setNibble(res, i, getNibble(val, p[i]!));
  }
  return res;
}

function mixColumns(val: bigint): bigint {
  let res = 0n;
  for (let c = 0; c < 4; c++) {
    const x0 = getNibble(val, c);
    const x1 = getNibble(val, c + 4);
    const x2 = getNibble(val, c + 8);
    const x3 = getNibble(val, c + 12);

    const y0 = x0 ^ x1 ^ x3;
    const y1 = x1 ^ x2;
    const y2 = x2;
    const y3 = x3;

    res = setNibble(res, c, y0);
    res = setNibble(res, c + 4, y1);
    res = setNibble(res, c + 8, y2);
    res = setNibble(res, c + 12, y3);
  }
  return res;
}

function mixColumnsInv(val: bigint): bigint {
  let res = 0n;
  for (let c = 0; c < 4; c++) {
    const y0 = getNibble(val, c);
    const y1 = getNibble(val, c + 4);
    const y2 = getNibble(val, c + 8);
    const y3 = getNibble(val, c + 12);

    const x2 = y2;
    const x3 = y3;
    const x1 = y1 ^ x2;
    const x0 = y0 ^ x1 ^ x3;

    res = setNibble(res, c, x0);
    res = setNibble(res, c + 4, x1);
    res = setNibble(res, c + 8, x2);
    res = setNibble(res, c + 12, x3);
  }
  return res;
}

export function createCraft(key: Uint8Array, tweak?: Uint8Array): BlockCipher {
  const k0 = readU64(key, 0);
  const k1 = readU64(key, 8);

  const t0 = tweak && tweak.length >= 8 ? readU64(tweak, 0) : 0n;

  const TWEAK_Q = [12, 10, 15, 9, 14, 8, 13, 11, 0, 1, 2, 3, 4, 5, 6, 7];
  const tQ = permuteNibbles(t0, TWEAK_Q);

  const tk = [k0 ^ t0, k1 ^ t0, k0 ^ tQ, k1 ^ tQ];

  return {
    blockSize: 8,
    encryptBlock(src: Uint8Array, dst: Uint8Array): void {
      let state = readU64(src, 0);

      for (let r = 0; r < 32; r++) {
        state = mixColumns(state);
        const rc4 = BigInt(CRAFT_RC_4[r]!);
        const rc3 = BigInt(CRAFT_RC_3[r]!);
        state ^= (rc4 << 60n) | (rc3 << 56n);
        state ^= tk[r % 4]!;

        if (r < 31) {
          state = permuteNibbles(state, CRAFT_P);
          state = subBox(state);
        }
      }

      writeU64(dst, 0, state);
    },
    decryptBlock(src: Uint8Array, dst: Uint8Array): void {
      let state = readU64(src, 0);

      for (let r = 31; r >= 0; r--) {
        if (r < 31) {
          state = subBox(state);
          state = permuteNibbles(state, CRAFT_P_INV);
        }

        const rc4 = BigInt(CRAFT_RC_4[r]!);
        const rc3 = BigInt(CRAFT_RC_3[r]!);
        state ^= tk[r % 4]!;
        state ^= (rc4 << 60n) | (rc3 << 56n);
        state = mixColumnsInv(state);
      }

      writeU64(dst, 0, state);
    },
  };
}
