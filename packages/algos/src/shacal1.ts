/**
 * SHACAL-1 160-bit Block Cipher (Handschuh & Naccache, NESSIE submission 2000).
 * Based on the inner compression function of the SHA-1 hash standard.
 *
 * - Block size: 160 bits (20 bytes / 5 32-bit words)
 * - Key size: 128 to 512 bits (16 to 64 bytes)
 * - Rounds: 80
 */
import type { BlockCipher } from "./blockmodes";

const K_ROUNDS = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

function rotl(n: number, b: number): number {
  return ((n << b) | (n >>> (32 - b))) >>> 0;
}

function rotr(n: number, b: number): number {
  return ((n >>> b) | (n << (32 - b))) >>> 0;
}

function readU32(b: Uint8Array, o = 0): number {
  let v = 0;
  for (let i = 0; i < 4; i++) {
    const byte = o + i < b.length ? b[o + i]! : 0;
    v = ((v << 8) | byte) >>> 0;
  }
  return v;
}

function writeU32(b: Uint8Array, o: number, v: number): void {
  for (let i = 3; i >= 0; i--) {
    if (o + i < b.length) {
      b[o + i] = v & 0xff;
    }
    v >>>= 8;
  }
}

function expandKey(key: Uint8Array): Uint32Array {
  const W = new Uint32Array(80);
  const keyLen = Math.min(key.length, 64);
  const paddedKey = new Uint8Array(64);
  paddedKey.set(key.subarray(0, keyLen));

  for (let i = 0; i < 16; i++) {
    W[i] = readU32(paddedKey, i * 4);
  }

  for (let i = 16; i < 80; i++) {
    W[i] = rotl(W[i - 3]! ^ W[i - 8]! ^ W[i - 14]! ^ W[i - 16]!, 1);
  }

  return W;
}

export function createShacal1(key: Uint8Array): BlockCipher {
  const W = expandKey(key);

  return {
    blockSize: 20,
    encryptBlock(src: Uint8Array, dst: Uint8Array): void {
      let A = readU32(src, 0);
      let B = readU32(src, 4);
      let C = readU32(src, 8);
      let D = readU32(src, 12);
      let E = readU32(src, 16);

      for (let i = 0; i < 80; i++) {
        let f: number;
        let k: number;

        if (i < 20) {
          f = (B & C) | (~B & D);
          k = K_ROUNDS[0]!;
        } else if (i < 40) {
          f = B ^ C ^ D;
          k = K_ROUNDS[1]!;
        } else if (i < 60) {
          f = (B & C) | (B & D) | (C & D);
          k = K_ROUNDS[2]!;
        } else {
          f = B ^ C ^ D;
          k = K_ROUNDS[3]!;
        }

        const temp = (rotl(A, 5) + f + E + k + W[i]!) >>> 0;
        E = D;
        D = C;
        C = rotl(B, 30);
        B = A;
        A = temp;
      }

      writeU32(dst, 0, A);
      writeU32(dst, 4, B);
      writeU32(dst, 8, C);
      writeU32(dst, 12, D);
      writeU32(dst, 16, E);
    },
    decryptBlock(src: Uint8Array, dst: Uint8Array): void {
      let A = readU32(src, 0);
      let B = readU32(src, 4);
      let C = readU32(src, 8);
      let D = readU32(src, 12);
      let E = readU32(src, 16);

      for (let i = 79; i >= 0; i--) {
        const prevA = B;
        const prevB = rotr(C, 30);
        const prevC = D;
        const prevD = E;

        let f: number;
        let k: number;

        if (i < 20) {
          f = (prevB & prevC) | (~prevB & prevD);
          k = K_ROUNDS[0]!;
        } else if (i < 40) {
          f = prevB ^ prevC ^ prevD;
          k = K_ROUNDS[1]!;
        } else if (i < 60) {
          f = (prevB & prevC) | (prevB & prevD) | (prevC & prevD);
          k = K_ROUNDS[2]!;
        } else {
          f = prevB ^ prevC ^ prevD;
          k = K_ROUNDS[3]!;
        }

        const prevE = (A - rotl(prevA, 5) - f - k - W[i]!) >>> 0;

        A = prevA;
        B = prevB;
        C = prevC;
        D = prevD;
        E = prevE;
      }

      writeU32(dst, 0, A);
      writeU32(dst, 4, B);
      writeU32(dst, 8, C);
      writeU32(dst, 12, D);
      writeU32(dst, 16, E);
    },
  };
}
