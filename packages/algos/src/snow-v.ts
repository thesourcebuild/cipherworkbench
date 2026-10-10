/**
 * SNOW-V Stream Cipher (Ekdahl et al., 2019).
 * Designed for 5G mobile communications encryption and integrity with 256-bit security.
 *
 * Combines two 16-element 16-bit LFSRs with an AES-round-based FSM generating 128 bits per step.
 */

import { aesRound } from "./aes-round";

const ZERO_ROUND_KEY = new Uint8Array(16);

const readU16LE = (input: Uint8Array, offset: number): number =>
  input[offset]! | (input[offset + 1]! << 8);

const readU32LE = (input: Uint8Array, offset: number): number =>
  (input[offset]! |
    (input[offset + 1]! << 8) |
    (input[offset + 2]! << 16) |
    (input[offset + 3]! << 24)) >>>
  0;

function writeU32LE(output: Uint8Array, offset: number, value: number): void {
  output[offset] = value;
  output[offset + 1] = value >>> 8;
  output[offset + 2] = value >>> 16;
  output[offset + 3] = value >>> 24;
}

const mulX = (value: number, reduction: number): number =>
  ((value << 1) ^ (value & 0x8000 ? reduction : 0)) & 0xffff;

const mulXInverse = (value: number, reduction: number): number =>
  ((value >>> 1) ^ (value & 1 ? reduction : 0)) & 0xffff;

export interface SnowVEngine {
  /** SNOW-V is its own inverse; calls continue from the previous byte. */
  process(input: Uint8Array): Uint8Array;
}

export function createSnowV(key: Uint8Array, iv: Uint8Array): SnowVEngine {
  if (key.length !== 32) {
    throw new Error(`SNOW-V requires a 256-bit (32-byte) key, got ${key.length} bytes.`);
  }
  if (iv.length !== 16) {
    throw new Error(`SNOW-V requires a 128-bit (16-byte) IV, got ${iv.length} bytes.`);
  }

  const lfsrA = new Uint16Array(16);
  const lfsrB = new Uint16Array(16);
  for (let i = 0; i < 8; i++) {
    lfsrA[i] = readU16LE(iv, i * 2);
    lfsrA[i + 8] = readU16LE(key, i * 2);
    lfsrB[i + 8] = readU16LE(key, 16 + i * 2);
  }

  const r1 = new Uint32Array(4);
  const r2 = new Uint32Array(4);
  const r3 = new Uint32Array(4);
  const nextR1 = new Uint32Array(4);
  const nextR2 = new Uint32Array(4);
  const nextR3 = new Uint32Array(4);
  const aesInput = new Uint8Array(16);
  const aesOutput = new Uint8Array(16);

  const aesRoundWords = (input: Uint32Array, output: Uint32Array): void => {
    for (let i = 0; i < 4; i++) writeU32LE(aesInput, i * 4, input[i]!);
    aesRound(aesInput, ZERO_ROUND_KEY, aesOutput);
    for (let i = 0; i < 4; i++) output[i] = readU32LE(aesOutput, i * 4);
  };

  const updateFsm = (): void => {
    const u = new Uint32Array(4);
    for (let i = 0; i < 4; i++) {
      const t2 = (lfsrA[2 * i]! | (lfsrA[2 * i + 1]! << 16)) >>> 0;
      u[i] = (r2[i]! + (r3[i]! ^ t2)) >>> 0;
    }

    for (let word = 0; word < 4; word++) {
      nextR1[word] =
        (((u[0]! >>> (word * 8)) & 0xff) |
          (((u[1]! >>> (word * 8)) & 0xff) << 8) |
          (((u[2]! >>> (word * 8)) & 0xff) << 16) |
          (((u[3]! >>> (word * 8)) & 0xff) << 24)) >>>
        0;
    }
    aesRoundWords(r1, nextR2);
    aesRoundWords(r2, nextR3);
    r1.set(nextR1);
    r2.set(nextR2);
    r3.set(nextR3);
  };

  const updateLfsr = (): void => {
    for (let clock = 0; clock < 8; clock++) {
      const nextA =
        mulX(lfsrA[0]!, 0x990f) ^ lfsrA[1]! ^ mulXInverse(lfsrA[8]!, 0xcc87) ^ lfsrB[0]!;
      const nextB =
        mulX(lfsrB[0]!, 0xc963) ^ lfsrB[3]! ^ mulXInverse(lfsrB[8]!, 0xe4b1) ^ lfsrA[0]!;
      lfsrA.copyWithin(0, 1);
      lfsrB.copyWithin(0, 1);
      lfsrA[15] = nextA;
      lfsrB[15] = nextB;
    }
  };

  const block = new Uint8Array(16);
  const step = (): void => {
    for (let i = 0; i < 4; i++) {
      const t1 = (lfsrB[8 + 2 * i]! | (lfsrB[9 + 2 * i]! << 16)) >>> 0;
      writeU32LE(block, i * 4, ((r1[i]! + t1) ^ r2[i]!) >>> 0);
    }
    updateFsm();
    updateLfsr();
  };

  for (let round = 0; round < 16; round++) {
    step();
    for (let i = 0; i < 8; i++) {
      lfsrA[i + 8] = lfsrA[i + 8]! ^ readU16LE(block, i * 2);
    }
    if (round === 14 || round === 15) {
      const keyOffset = round === 14 ? 0 : 16;
      for (let i = 0; i < 4; i++) {
        r1[i] = (r1[i]! ^ readU32LE(key, keyOffset + i * 4)) >>> 0;
      }
    }
  }

  let blockAt = 16;
  const fill = (): void => {
    step();
    blockAt = 0;
  };

  return {
    process(input: Uint8Array): Uint8Array {
      const output = new Uint8Array(input.length);
      for (let i = 0; i < input.length; i++) {
        if (blockAt === block.length) fill();
        output[i] = input[i]! ^ block[blockAt++]!;
      }
      return output;
    },
  };
}

export function snowVCrypt(key: Uint8Array, iv: Uint8Array, input: Uint8Array): Uint8Array {
  return createSnowV(key, iv).process(input);
}
