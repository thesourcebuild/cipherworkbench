/**
 * LED-64-80, the "Lightweight Encryption Device" (Guo, Peyrin, Poschmann and Robshaw, CHES 2011).
 *
 * `legacy`. No break of the full 48 rounds, and the design is unusually well analysed -- but nothing has
 * been built on it since, and its own paper's security argument is about *related-key* resistance, which
 * it achieves by the most extreme means available: **there is no key schedule at all.** The key nibbles
 * are XORed in cyclically, unchanged, every four rounds. That is the thing worth knowing about LED, and
 * it is why it is here beside PRESENT rather than instead of it.
 *
 * Structurally it is AES over nibbles: SubCells, ShiftRows, MixColumnsSerial over GF(2^4), and a key
 * addition once per group of four rounds rather than once per round.
 *
 * Four things to preserve.
 *
 * **The round constants are the same six-bit LFSR SKINNY uses**, so this file imports `SKINNY_RC` rather
 * than storing 48 more bytes. That is not a coincidence to be tidy about: SKINNY's designers took the
 * generator from LED, and the shared table means Romulus's 7,559 assertions and SKINNY's own vectors
 * already pin the sequence LED reads.
 *
 * **The S-box is PRESENT's**, which is also stated rather than restated -- `PRESENT_SBOX` comes from
 * `present.ts`, where that cipher's own published vectors check it.
 *
 * **The inverse MixColumns matrix is derived, not stored.** Gauss-Jordan over GF(2^4) under `x^4 + x + 1`
 * inverts the forward matrix at load, and the tests compare the result against the reference's literal --
 * so a mistyped forward entry fails the derivation rather than only the vectors.
 *
 * **The key is twenty nibbles used modulo twenty, and the state is sixteen.** So the key material walks
 * the state at an offset that advances by sixteen each time and never repeats within the cipher -- the
 * `(i + 16 * half) % 20` below is the whole key schedule, and getting the modulus wrong gives a cipher
 * whose first two key additions are right.
 *
 * No oracle -- OpenSSL has never implemented LED. What stands behind it is the designers' own vector, as
 * carried by FELICS's benchmarking suite, checked in both directions.
 */
import type { BlockCipher } from "./blockmodes";
import { PRESENT_SBOX } from "./present";
import { SKINNY_RC } from "./skinny";

const BLOCK = 8;
const KEY = 10;
/** Forty-eight rounds in twelve groups of four, with a key addition between groups. */
const GROUPS = 12;

/** The MixColumnsSerial matrix, and its inverse derived below. */
const MATRIX: readonly (readonly number[])[] = [
  [4, 1, 2, 2],
  [8, 6, 5, 6],
  [11, 14, 10, 9],
  [2, 2, 15, 11],
];

/** Multiplication in GF(2^4) under `x^4 + x + 1`, which LED writes as the reduction 0x3. */
function gf16(a: number, b: number): number {
  let x = a;
  let result = 0;
  for (let i = 0; i < 4; i++) {
    if (((b >> i) & 1) !== 0) result ^= x;
    x = (x & 8) !== 0 ? ((x << 1) ^ 0x3) & 0xf : (x << 1) & 0xf;
  }
  return result & 0xf;
}

/**
 * The inverse matrix, by Gauss-Jordan over GF(2^4).
 *
 * Every reference ships it as a second literal; deriving it means a mistyped entry in the forward matrix
 * breaks the derivation rather than only the decrypt path -- and the tests compare this against the
 * reference's literal, so the derivation is checked rather than merely self-consistent.
 */
const MATRIX_INVERSE: readonly (readonly number[])[] = (() => {
  const reciprocal = (x: number): number => {
    for (let y = 1; y < 16; y++) if (gf16(x, y) === 1) return y;
    throw new Error(`LED: ${x} has no inverse in GF(2^4).`);
  };
  const rows = MATRIX.map((row, i) => [
    ...row,
    ...Array.from({ length: 4 }, (_, j) => (i === j ? 1 : 0)),
  ]);
  for (let col = 0; col < 4; col++) {
    let pivot = col;
    while (rows[pivot]![col] === 0) pivot++;
    const swap = rows[col]!;
    rows[col] = rows[pivot]!;
    rows[pivot] = swap;
    const scale = reciprocal(rows[col]![col]!);
    for (let j = 0; j < 8; j++) rows[col]![j] = gf16(rows[col]![j]!, scale);
    for (let r = 0; r < 4; r++) {
      if (r === col || rows[r]![col] === 0) continue;
      const factor = rows[r]![col]!;
      for (let j = 0; j < 8; j++) rows[r]![j] = rows[r]![j]! ^ gf16(rows[col]![j]!, factor);
    }
  }
  return rows.map((row) => row.slice(4));
})();

/** Exported so a test can compare the derivation against a reference's literal. */
export const LED_MATRIX_INVERSE = MATRIX_INVERSE;

const SBOX = PRESENT_SBOX;
const SBOX_INVERSE = (() => {
  const out = new Array<number>(16).fill(-1);
  SBOX.forEach((v, i) => (out[v] = i));
  if (out.some((v) => v < 0)) throw new Error("LED's S-box is not a permutation.");
  return out;
})();

/** LED-64-80 as a `BlockCipher`. */
export function createLed(key: Uint8Array): BlockCipher {
  if (key.length !== KEY) {
    throw new Error(`LED-64-80's key is exactly 10 bytes; this one is ${key.length}.`);
  }
  // Twenty key nibbles, high half of each byte first.
  const keyNibbles: number[] = [];
  for (let i = 0; i < 2 * KEY; i++) {
    keyNibbles.push(i % 2 === 1 ? key[i >> 1]! & 0xf : (key[i >> 1]! >> 4) & 0xf);
  }

  const load = (src: Uint8Array): number[] => {
    const out: number[] = [];
    for (let i = 0; i < 16; i++) {
      out.push(i % 2 === 1 ? src[i >> 1]! & 0xf : (src[i >> 1]! >> 4) & 0xf);
    }
    return out;
  };
  const store = (s: readonly number[], dst: Uint8Array): void => {
    for (let i = 0; i < BLOCK; i++) {
      dst[i] = ((s[2 * i]! & 0xf) << 4) | (s[2 * i + 1]! & 0xf);
    }
  };
  const addKey = (s: number[], half: number): void => {
    for (let i = 0; i < 16; i++) s[i] = s[i]! ^ keyNibbles[(i + 16 * half) % 20]!;
  };
  /** The two constant columns: the key size in column zero, the round constant in column one. */
  const addConstants = (s: number[], round: number): void => {
    s[0] = s[0]! ^ 5;
    s[4] = s[4]! ^ 4;
    s[8] = s[8]! ^ 2;
    s[12] = s[12]! ^ 3;
    const high = (SKINNY_RC[round]! >> 3) & 7;
    const low = SKINNY_RC[round]! & 7;
    s[1] = s[1]! ^ high;
    s[9] = s[9]! ^ high;
    s[5] = s[5]! ^ low;
    s[13] = s[13]! ^ low;
  };
  const mix = (s: number[], matrix: readonly (readonly number[])[]): void => {
    for (let c = 0; c < 4; c++) {
      const column = [s[c]!, s[4 + c]!, s[8 + c]!, s[12 + c]!];
      for (let i = 0; i < 4; i++) {
        let sum = 0;
        for (let n = 0; n < 4; n++) sum ^= gf16(matrix[i]![n]!, column[n]!);
        s[4 * i + c] = sum;
      }
    }
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      const s = load(src);
      addKey(s, 0);
      for (let group = 0; group < GROUPS; group++) {
        for (let j = 0; j < 4; j++) {
          addConstants(s, group * 4 + j);
          for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]!]!;
          for (let row = 1; row < 4; row++) {
            const before = s.slice(4 * row, 4 * row + 4);
            for (let c = 0; c < 4; c++) s[4 * row + c] = before[(c + row) & 3]!;
          }
          mix(s, MATRIX);
        }
        addKey(s, group + 1);
      }
      store(s, dst);
    },
    decryptBlock: (src, dst) => {
      const s = load(src);
      for (let group = GROUPS - 1; group >= 0; group--) {
        addKey(s, group + 1);
        for (let j = 3; j >= 0; j--) {
          mix(s, MATRIX_INVERSE);
          for (let row = 1; row < 4; row++) {
            const before = s.slice(4 * row, 4 * row + 4);
            for (let c = 0; c < 4; c++) s[4 * row + c] = before[(c - row + 4) & 3]!;
          }
          for (let i = 0; i < 16; i++) s[i] = SBOX_INVERSE[s[i]!]!;
          addConstants(s, group * 4 + j);
        }
      }
      addKey(s, 0);
      store(s, dst);
    },
  };
}
