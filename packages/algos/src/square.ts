/**
 * SQUARE Block Cipher:
 * 128-bit block cipher designed by Joan Daemen, Lars Knudsen, and Vincent Rijmen (1997).
 * Direct predecessor of the Rijndael / AES architecture.
 */

import type { BlockCipher } from "./blockmodes";

function gfMul(a: number, b: number): number {
  let p = 0;
  let hi: number;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b; // polynomial x^8 + x^4 + x^3 + x + 1 (same as AES)
    b >>>= 1;
  }
  return p;
}

function gfInv(a: number): number {
  if (a === 0) return 0;
  for (let b = 1; b < 256; b++) {
    if (gfMul(a, b) === 1) return b;
  }
  return 0;
}

const rotl8 = (x: number, n: number) => (((x << n) | (x >>> (8 - n))) & 0xff);

// Bijective Square S-box generated via GF(2^8) inverse and affine transform
const SQUARE_SBOX = new Uint8Array(256);
const SQUARE_INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  const inv = gfInv(i);
  SQUARE_SBOX[i] = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63;
  SQUARE_INV_SBOX[SQUARE_SBOX[i]!] = i;
}

function squarePi(state: Uint8Array): Uint8Array {
  const trans = new Uint8Array(16);
  for (let row = 0; row < 4; row++) {
    for (let col = 0; col < 4; col++) {
      trans[col * 4 + row] = state[row * 4 + col]!;
    }
  }
  return trans;
}

export class SquareCipher {
  private roundKeys: Uint8Array[] = [];

  constructor(key: Uint8Array) {
    if (key.length !== 16) throw new Error("SQUARE requires a 16-byte (128-bit) key.");
    this.keySchedule(key);
  }

  private keySchedule(key: Uint8Array): void {
    this.roundKeys = [new Uint8Array(key)];
    let prev = new Uint8Array(key);

    // 8 rounds -> 9 round keys
    for (let r = 1; r <= 8; r++) {
      const nextKey = new Uint8Array(16);
      // Linear transformation and round constant
      const rcon = gfMul(0x02, r);
      nextKey[0] = prev[0]! ^ prev[12]! ^ rcon;
      nextKey[1] = prev[1]! ^ prev[13]!;
      nextKey[2] = prev[2]! ^ prev[14]!;
      nextKey[3] = prev[3]! ^ prev[15]!;

      for (let i = 4; i < 16; i++) {
        nextKey[i] = nextKey[i - 4]! ^ prev[i]!;
      }
      this.roundKeys.push(nextKey);
      prev = nextKey;
    }
  }

  encryptBlock(block: Uint8Array): Uint8Array {
    let state: Uint8Array = new Uint8Array(block);

    for (let i = 0; i < 16; i++) state[i]! ^= this.roundKeys[0]![i]!;

    for (let r = 1; r <= 8; r++) {
      for (let i = 0; i < 16; i++) state[i] = SQUARE_SBOX[state[i]!]!;
      state = new Uint8Array(squarePi(state));

      if (r < 8) {
        const thetaState = new Uint8Array(16);
        for (let col = 0; col < 4; col++) {
          const c = col * 4;
          const a0 = state[c]!, a1 = state[c + 1]!, a2 = state[c + 2]!, a3 = state[c + 3]!;
          thetaState[c]     = gfMul(0x02, a0) ^ gfMul(0x03, a1) ^ a2 ^ a3;
          thetaState[c + 1] = a0 ^ gfMul(0x02, a1) ^ gfMul(0x03, a2) ^ a3;
          thetaState[c + 2] = a0 ^ a1 ^ gfMul(0x02, a2) ^ gfMul(0x03, a3);
          thetaState[c + 3] = gfMul(0x03, a0) ^ a1 ^ a2 ^ gfMul(0x02, a3);
        }
        state = thetaState;
      }

      for (let i = 0; i < 16; i++) state[i]! ^= this.roundKeys[r]![i]!;
    }

    return state;
  }

  decryptBlock(block: Uint8Array): Uint8Array {
    let state: Uint8Array = new Uint8Array(block);

    for (let r = 8; r >= 1; r--) {
      for (let i = 0; i < 16; i++) state[i]! ^= this.roundKeys[r]![i]!;
      if (r < 8) {
        const invTheta = new Uint8Array(16);
        for (let col = 0; col < 4; col++) {
          const c = col * 4;
          const a0 = state[c]!, a1 = state[c + 1]!, a2 = state[c + 2]!, a3 = state[c + 3]!;
          invTheta[c]     = gfMul(0x0e, a0) ^ gfMul(0x0b, a1) ^ gfMul(0x0d, a2) ^ gfMul(0x09, a3);
          invTheta[c + 1] = gfMul(0x09, a0) ^ gfMul(0x0e, a1) ^ gfMul(0x0b, a2) ^ gfMul(0x0d, a3);
          invTheta[c + 2] = gfMul(0x0d, a0) ^ gfMul(0x09, a1) ^ gfMul(0x0e, a2) ^ gfMul(0x0b, a3);
          invTheta[c + 3] = gfMul(0x0b, a0) ^ gfMul(0x0d, a1) ^ gfMul(0x09, a2) ^ gfMul(0x0e, a3);
        }
        state = invTheta;
      }
      state = new Uint8Array(squarePi(state));
      for (let i = 0; i < 16; i++) state[i] = SQUARE_INV_SBOX[state[i]!]!;
    }

    for (let i = 0; i < 16; i++) state[i]! ^= this.roundKeys[0]![i]!;
    return state;
  }
}

export function createSquare(key: Uint8Array): BlockCipher {
  const cipher = new SquareCipher(key);
  return {
    blockSize: 16,
    encryptBlock(src: Uint8Array, dst: Uint8Array): void {
      const block = src.subarray(0, 16);
      const enc = cipher.encryptBlock(block);
      dst.set(enc);
    },
    decryptBlock(src: Uint8Array, dst: Uint8Array): void {
      const block = src.subarray(0, 16);
      const dec = cipher.decryptBlock(block);
      dst.set(dec);
    },
  };
}

export function squareEncryptEcb(key: Uint8Array, data: Uint8Array): Uint8Array {
  const cipher = new SquareCipher(key);
  const padLen = 16 - (data.length % 16);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded.fill(padLen, data.length);

  const out = new Uint8Array(padded.length);
  for (let i = 0; i < padded.length; i += 16) {
    out.set(cipher.encryptBlock(padded.subarray(i, i + 16)), i);
  }
  return out;
}

export function squareDecryptEcb(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (data.length % 16 !== 0) throw new Error("Invalid SQUARE ciphertext length.");
  const cipher = new SquareCipher(key);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 16) {
    out.set(cipher.decryptBlock(data.subarray(i, i + 16)), i);
  }
  const padLen = out[out.length - 1]!;
  if (padLen > 0 && padLen <= 16) {
    return out.slice(0, out.length - padLen);
  }
  return out;
}
