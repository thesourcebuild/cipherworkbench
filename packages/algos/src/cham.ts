/**
 * CHAM, the Korean lightweight ARX family (Koo, Roh, Kim, Jung, Lee and Kwon, ICISC 2017).
 *
 * `modern`: no attack on the full cipher. The revised version -- CHAM-64/128 at 88 rounds and
 * CHAM-128/128 at 112 -- exists because a related-key differential reached the original round counts,
 * and **this implements the original**, which is what every published vector and every deployment uses.
 * The note on the metadata says so; a tool that silently implemented the revision would reproduce
 * nothing.
 *
 * It is here as the extreme of the ARX end: **no tables, no S-box and no constants at all**. The round
 * function is one addition, two rotations, two XORs and the round index, and the key schedule is four
 * XORs of rotations. That makes it the smallest block cipher in this repo by source size, which is the
 * whole point of the design -- it targets 8-bit microcontrollers where even Simon's word logic costs.
 *
 * Three things to preserve.
 *
 * **The round index is an operand.** `x[0] ^ i` uses the *round number*, so there is no constant table
 * and no LFSR -- the counter is the constant. An implementation that dropped it would be a cipher whose
 * rounds are all identical, which round-trips perfectly and matches nothing.
 *
 * **The rotations alternate by round parity.** Even rounds rotate the second word by 1 and the result
 * by 8; odd rounds swap those. Using one pair throughout is right for half the rounds.
 *
 * **The state shift is folded into the index arithmetic**, as the reference does. The specification
 * shifts the four words left by one each round and writes the new word at index 3; here the word at
 * `round mod 4` is overwritten instead, which is the same thing because the round count is a multiple
 * of four. Writing it as an actual shift is also correct but four times the work.
 *
 * No oracle -- OpenSSL has never implemented CHAM. What stands behind it is thirty vectors from
 * Crypto++'s `TestVectors/cham.txt`, ten per parameter set, of which the first at each set is the
 * designers' own from the paper's appendix and the rest are from their reference implementation.
 */
import type { BlockCipher } from "./blockmodes";

export type ChamVariant = "64-128" | "128-128" | "128-256";

interface ChamParams {
  /** Word size in bits: 16 for the 64-bit block, 32 for the 128-bit one. */
  readonly wordBits: 16 | 32;
  readonly keyBytes: number;
  readonly rounds: number;
}

/**
 * The three sets, and the round counts are the *original* specification's.
 *
 * `128-256` runs 96 rounds where the two 128-bit-key sets run 80. That is the only place the key length
 * changes anything but the schedule length.
 */
export const CHAM_VARIANTS: Readonly<Record<ChamVariant, ChamParams>> = {
  "64-128": { wordBits: 16, keyBytes: 16, rounds: 80 },
  "128-128": { wordBits: 32, keyBytes: 16, rounds: 80 },
  "128-256": { wordBits: 32, keyBytes: 32, rounds: 96 },
};

const maskFor = (wordBits: number): number => (wordBits === 16 ? 0xffff : 0xffffffff);

const rotl = (x: number, n: number, wordBits: number): number =>
  (((x << n) | (x >>> (wordBits - n))) & maskFor(wordBits)) >>> 0;

/** Words are big-endian, which is what the published vectors assume. */
function readWord(bytes: Uint8Array, index: number, wordBytes: number): number {
  let w = 0;
  for (let b = 0; b < wordBytes; b++) w = ((w << 8) | bytes[index * wordBytes + b]!) >>> 0;
  return w;
}

function writeWord(word: number, out: Uint8Array, index: number, wordBytes: number): void {
  for (let b = 0; b < wordBytes; b++) {
    out[index * wordBytes + b] = (word >>> (8 * (wordBytes - 1 - b))) & 0xff;
  }
}

/**
 * The round keys: `2k` of them from `k` key words, and nothing else.
 *
 * Each key word produces two, at `i` and at `(i + k) XOR 1`. That XOR is not a typo -- it swaps
 * adjacent pairs in the second half, and dropping it gives a schedule whose second half is in the wrong
 * order while every individual value is right.
 */
function roundKeys(key: Uint8Array, wordBits: 16 | 32): number[] {
  const wordBytes = wordBits / 8;
  const count = key.length / wordBytes;
  const rk = new Array<number>(2 * count).fill(0);
  const mask = maskFor(wordBits);
  for (let i = 0; i < count; i++) {
    const w = readWord(key, i, wordBytes) & mask;
    rk[i] = (w ^ rotl(w, 1, wordBits) ^ rotl(w, 8, wordBits)) >>> 0;
    rk[(i + count) ^ 1] = (w ^ rotl(w, 1, wordBits) ^ rotl(w, 11, wordBits)) >>> 0;
  }
  return rk;
}

/** CHAM as a `BlockCipher`. */
export function createCham(key: Uint8Array, variant: ChamVariant = "128-128"): BlockCipher {
  const params = CHAM_VARIANTS[variant];
  if (params === undefined) throw new Error(`Unknown CHAM variant: ${String(variant)}.`);
  if (key.length !== params.keyBytes) {
    throw new Error(
      `CHAM-${variant}'s key is exactly ${params.keyBytes} bytes; this one is ${key.length}.`,
    );
  }
  const { wordBits, rounds } = params;
  const wordBytes = wordBits / 8;
  const mask = maskFor(wordBits);
  const rk = roundKeys(key, wordBits);
  const blockSize = 4 * wordBytes;

  return {
    blockSize,
    encryptBlock: (src, dst) => {
      const x = [0, 1, 2, 3].map((i) => readWord(src, i, wordBytes));
      for (let round = 0; round < rounds; round++) {
        // The position within the sixteen-round group decides the rotations and the word to replace.
        const step = round % 16;
        const target = step % 4;
        const partner = (step + 1) % 4;
        const even = step % 2 === 0;
        const a = (x[target]! ^ round) & mask;
        const b = (rotl(x[partner]!, even ? 1 : 8, wordBits) ^ rk[round % rk.length]!) & mask;
        x[target] = rotl((a + b) & mask, even ? 8 : 1, wordBits);
      }
      for (let i = 0; i < 4; i++) writeWord(x[i]!, dst, i, wordBytes);
    },
    decryptBlock: (src, dst) => {
      const x = [0, 1, 2, 3].map((i) => readWord(src, i, wordBytes));
      for (let round = rounds - 1; round >= 0; round--) {
        const step = round % 16;
        const target = step % 4;
        const partner = (step + 1) % 4;
        const even = step % 2 === 0;
        // Undo the outer rotation, subtract, then undo the round-index XOR.
        const rotated = rotl(x[target]!, wordBits - (even ? 8 : 1), wordBits);
        const b = (rotl(x[partner]!, even ? 1 : 8, wordBits) ^ rk[round % rk.length]!) & mask;
        x[target] = (((rotated - b) & mask) ^ round) & mask;
      }
      for (let i = 0; i < 4; i++) writeWord(x[i]!, dst, i, wordBytes);
    },
  };
}
