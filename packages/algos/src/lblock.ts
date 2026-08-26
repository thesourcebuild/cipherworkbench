/**
 * LBlock-80, the lightweight Feistel (Wu and Zhang, ACNS 2011).
 *
 * `legacy`. No break of the full 32 rounds, but biclique attacks reach all 32 at a cost just under
 * exhaustive search and impossible-differential results reach 23 -- so it is a design to reproduce values
 * from rather than to choose.
 *
 * The reason it is worth having beside TWINE and PRESENT is that it is the one in this family with
 * **eight different S-boxes**. Everything else here reuses one 4-bit box across the state; LBlock's round
 * function applies S0 through S7 to the eight nibbles of its half-block, and the key schedule uses two
 * more, S8 and S9. Ten tables of sixteen nibbles is more than any of its neighbours, and it is the whole
 * of the cipher's non-linearity.
 *
 * Three things to preserve.
 *
 * **The round is a Feistel with a rotation on the *other* half.** The new left half is
 * `F(left, key) XOR (right rotated left by eight bits)`, and the new right half is the old left. That
 * rotation is easy to lose because it is applied to the branch that is *not* going through F -- and losing
 * it leaves a cipher that inverts against itself and reproduces nothing.
 *
 * **The halves swap once more at the very end.** Thirty-two rounds, then one unconditional exchange. That
 * final swap is what makes the cipher's own inverse the same shape, and it is outside the loop.
 *
 * **The key register rotates by 29 bits, not by a byte count.** Ten bytes rotated left 29 places, which is
 * three whole bytes plus five bits -- so every output byte is built from two input bytes, and no shift
 * amount in the expression is a multiple of eight. Then two S-boxes and a round counter go in.
 *
 * No oracle -- OpenSSL has never implemented LBlock. What stands behind it is the two vectors FELICS's
 * benchmarking suite carries, both checked in both directions.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
const KEY = 10;
const ROUNDS = 32;

/**
 * Ten 4-bit S-boxes: S0 to S7 for the round function, S8 and S9 for the key schedule.
 *
 * More tables than anything else in this family, and there is nothing to derive them from -- the paper
 * tabulates all ten. So the load-time check that each is a permutation is doing real work here.
 */
const SBOXES: readonly (readonly number[])[] = [
  [14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5],
  [4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3],
  [1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10],
  [7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1],
  [14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3],
  [2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5],
  [11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2],
  [13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6],
  [8, 7, 14, 5, 15, 13, 0, 6, 11, 12, 9, 10, 2, 4, 1, 3],
  [11, 5, 15, 0, 7, 2, 9, 13, 4, 8, 1, 12, 14, 10, 3, 6],
];

{
  for (const [index, box] of SBOXES.entries()) {
    if (new Set(box).size !== 16) throw new Error(`LBlock's S${index} is not a permutation.`);
  }
}

/** Exported so a test can assert all ten are distinct, which is the cipher's distinguishing feature. */
export const LBLOCK_SBOXES = SBOXES;

/** The 32 round keys, four bytes each, from a ten-byte register rotated 29 bits per round. */
function schedule(key: Uint8Array): number[][] {
  const k = Array.from(key);
  const rounds: number[][] = [[k[6]!, k[7]!, k[8]!, k[9]!]];
  for (let round = 1; round < ROUNDS; round++) {
    const top = [k[6]!, k[7]!, k[8]!, k[9]!];
    // Rotate the eighty-bit register left by twenty-nine: three bytes and five bits.
    k[9] = (((k[6]! & 0x07) << 5) & 0xe0) ^ (((k[5]! & 0xf8) >> 3) & 0x1f);
    k[8] = (((k[5]! & 0x07) << 5) & 0xe0) ^ (((k[4]! & 0xf8) >> 3) & 0x1f);
    k[7] = (((k[4]! & 0x07) << 5) & 0xe0) ^ (((k[3]! & 0xf8) >> 3) & 0x1f);
    k[6] = (((k[3]! & 0x07) << 5) & 0xe0) ^ (((k[2]! & 0xf8) >> 3) & 0x1f);
    k[5] = (((k[2]! & 0x07) << 5) & 0xe0) ^ (((k[1]! & 0xf8) >> 3) & 0x1f);
    k[4] = (((k[1]! & 0x07) << 5) & 0xe0) ^ (((k[0]! & 0xf8) >> 3) & 0x1f);
    k[3] = (((k[0]! & 0x07) << 5) & 0xe0) ^ (((top[3]! & 0xf8) >> 3) & 0x1f);
    k[2] = (((top[3]! & 0x07) << 5) & 0xe0) ^ (((top[2]! & 0xf8) >> 3) & 0x1f);
    k[1] = (((top[2]! & 0x07) << 5) & 0xe0) ^ (((top[1]! & 0xf8) >> 3) & 0x1f);
    k[0] = (((top[1]! & 0x07) << 5) & 0xe0) ^ (((top[0]! & 0xf8) >> 3) & 0x1f);
    // S9 and S8 on the top byte, then the round counter into two places.
    k[9] = ((SBOXES[9]![(k[9]! >> 4) & 0xf]! << 4) ^ SBOXES[8]![k[9]! & 0xf]!) & 0xff;
    k[6] = k[6]! ^ ((round >> 2) & 0x07);
    k[5] = k[5]! ^ ((round & 0x03) << 6);
    rounds.push([k[6]!, k[7]!, k[8]!, k[9]!]);
  }
  return rounds;
}

/** `P(S(half XOR key))` -- the round function, over four bytes. */
function roundFunction(half: readonly number[], roundKey: readonly number[]): number[] {
  const y = [
    half[0]! ^ roundKey[0]!,
    half[1]! ^ roundKey[1]!,
    half[2]! ^ roundKey[2]!,
    half[3]! ^ roundKey[3]!,
  ];
  y[3] = ((SBOXES[7]![(y[3]! >> 4) & 0xf]! << 4) ^ SBOXES[6]![y[3]! & 0xf]!) & 0xff;
  y[2] = ((SBOXES[5]![(y[2]! >> 4) & 0xf]! << 4) ^ SBOXES[4]![y[2]! & 0xf]!) & 0xff;
  y[1] = ((SBOXES[3]![(y[1]! >> 4) & 0xf]! << 4) ^ SBOXES[2]![y[1]! & 0xf]!) & 0xff;
  y[0] = ((SBOXES[1]![(y[0]! >> 4) & 0xf]! << 4) ^ SBOXES[0]![y[0]! & 0xf]!) & 0xff;
  // The nibble permutation, which shuffles the eight nibbles across the four bytes.
  return [
    (y[1]! & 0xf0) ^ ((y[0]! >> 4) & 0x0f),
    ((y[1]! & 0x0f) << 4) ^ (y[0]! & 0x0f),
    (y[3]! & 0xf0) ^ ((y[2]! >> 4) & 0x0f),
    ((y[3]! & 0x0f) << 4) ^ (y[2]! & 0x0f),
  ];
}

/** LBlock-80 as a `BlockCipher`. */
export function createLblock(key: Uint8Array): BlockCipher {
  if (key.length !== KEY) {
    throw new Error(`LBlock-80's key is exactly 10 bytes; this one is ${key.length}.`);
  }
  const rounds = schedule(key);
  const swapHalves = (x: number[]): void => {
    for (let i = 0; i < 4; i++) {
      const t = x[i]!;
      x[i] = x[4 + i]!;
      x[4 + i] = t;
    }
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      const x = Array.from(src.subarray(0, BLOCK));
      for (let round = 0; round < ROUNDS; round++) {
        const left = [x[4]!, x[5]!, x[6]!, x[7]!];
        const p = roundFunction(left, rounds[round]!);
        // The right half rotates left by eight bits as it crosses.
        x[7] = x[2]! ^ p[3]!;
        x[6] = x[1]! ^ p[2]!;
        x[5] = x[0]! ^ p[1]!;
        x[4] = x[3]! ^ p[0]!;
        for (let i = 0; i < 4; i++) x[i] = left[i]!;
      }
      swapHalves(x);
      dst.set(x);
    },
    decryptBlock: (src, dst) => {
      const x = Array.from(src.subarray(0, BLOCK));
      swapHalves(x);
      for (let round = ROUNDS - 1; round >= 0; round--) {
        // The half that did not go through F is now in the low four bytes.
        const previousLeft = [x[0]!, x[1]!, x[2]!, x[3]!];
        const p = roundFunction(previousLeft, rounds[round]!);
        const previousRight = [x[5]! ^ p[1]!, x[6]! ^ p[2]!, x[7]! ^ p[3]!, x[4]! ^ p[0]!];
        for (let i = 0; i < 4; i++) {
          x[i] = previousRight[i]!;
          x[4 + i] = previousLeft[i]!;
        }
      }
      dst.set(x);
    },
  };
}
