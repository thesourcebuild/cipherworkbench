/**
 * SKINNY, the tweakable block cipher family (Beierle et al., CRYPTO 2016), at all six sizes.
 *
 * `modern`: no attack on any full member after a decade of a public cryptanalysis competition aimed at
 * it. It is also the most *load-bearing* cipher in this repo -- ISO/IEC 18033-7 standardises it, and
 * three NIST lightweight submissions are built on it, one of which (Romulus) is a finalist and is
 * already here. So `skinny128384plus` in `lwc-romulus.ts` was the 40-round reduction Romulus uses, and
 * this file is the family it came from.
 *
 * **It shares that file's S-box, tweakey permutation and MixColumns rather than restating them**, which
 * means the 8-bit half of this cipher is already pinned by Romulus's 7,559 known-answer assertions and a
 * failure in SKINNY's own vectors points at the round count, the 4-bit path or the decryption.
 *
 * Five things to preserve.
 *
 * **The round constants are derived from a six-bit LFSR, not stored.** `rc <- (rc << 1) | (b5 ^ b4 ^ 1)`
 * gives all 56, and `lwc-romulus.ts`'s literal 40 are the first 40 of them -- which the tests assert, so
 * the derivation is checked against something rather than merely self-consistent.
 *
 * **The two LFSRs on the tweakey lanes differ between cell widths.** Lane 2 shifts left and feeds
 * `bit(top) ^ bit(top-2)` into bit 0; lane 3 shifts right and feeds `bit0 ^ bit(top-1)` into the top.
 * At four bits those taps are 3 and 2, and 0 and 3; at eight bits they are 7 and 5, and 0 and 6. Reusing
 * the eight-bit taps for nibbles is right for no input at all, which is the good case.
 *
 * **Only the top two rows take the tweakey**, and only the *first* lane is a plain permutation -- lanes
 * 2 and 3 get the LFSR after it. A schedule that permuted all three identically is correct for
 * SKINNY-64-64 and SKINNY-128-128, the two single-lane members, and wrong for the other four.
 *
 * **MixColumns is a binary matrix with no multiplication.** Four XORs and a rotation of the column, and
 * its inverse is *not* the same shape read backwards -- writing one from the other by hand is how a
 * decryption path ends up self-consistent and wrong, which is why the tests decrypt published
 * ciphertext rather than re-decrypting ours.
 *
 * **The tweakey is the key here.** SKINNY's third input is a tweak, and this tool spends the whole
 * tweakey on key material -- which is what the standardised block cipher does, and what the published
 * vectors use. A tool that exposed the tweak separately would be a different, tweakable, tool; the
 * cipher family has no place to put a per-block tweak, and Romulus is the thing that uses it as one.
 *
 * What stands behind it: the designers' own vectors for SKINNY-64-128 and SKINNY-128-128, plus the
 * agreement with `skinny128384plus` at 40 rounds, which covers the 128-bit path at three lanes -- the
 * widest member, and the one no published vector here reaches.
 */
import type { BlockCipher } from "./blockmodes";
import { SKINNY_SBOX8, SKINNY_TWEAKEY_P } from "./lwc-romulus";

export type SkinnyVariant = "64-64" | "64-128" | "64-192" | "128-128" | "128-256" | "128-384";

interface SkinnyParams {
  /** Cell width in bits: nibbles for the 64-bit block, bytes for the 128-bit one. */
  readonly cell: 4 | 8;
  /** How many tweakey lanes, which is the tweakey size over the block size. */
  readonly lanes: 1 | 2 | 3;
  readonly rounds: number;
}

export const SKINNY_VARIANTS: Readonly<Record<SkinnyVariant, SkinnyParams>> = {
  "64-64": { cell: 4, lanes: 1, rounds: 32 },
  "64-128": { cell: 4, lanes: 2, rounds: 36 },
  "64-192": { cell: 4, lanes: 3, rounds: 40 },
  "128-128": { cell: 8, lanes: 1, rounds: 40 },
  "128-256": { cell: 8, lanes: 2, rounds: 48 },
  "128-384": { cell: 8, lanes: 3, rounds: 56 },
};

/** The 4-bit S-box, and both inverses derived at load. */
const SBOX4 = new Uint8Array([12, 6, 9, 0, 1, 10, 2, 11, 3, 8, 5, 13, 4, 14, 7, 15]);

function inverseOf(box: Readonly<Uint8Array>): Uint8Array {
  const out = new Uint8Array(box.length);
  const seen = new Set<number>();
  box.forEach((v, i) => {
    out[v] = i;
    seen.add(v);
  });
  if (seen.size !== box.length) throw new Error("A SKINNY S-box is not a permutation.");
  return out;
}
const SBOX4_INV = inverseOf(SBOX4);
const SBOX8_INV = inverseOf(SKINNY_SBOX8);

/**
 * All 56 round constants, from the specification's six-bit LFSR.
 *
 * `lwc-romulus.ts` stores the first 40 as a literal because that is all Romulus needs, and
 * `tests/algos-lightweight-block.test.ts` asserts these reproduce them -- which is what makes deriving
 * the other sixteen safe. The comparison lives in the test rather than here so that the derivation and
 * the literal stay genuinely independent.
 */
export const SKINNY_RC = (() => {
  const out: number[] = [];
  let rc = 0;
  for (let i = 0; i < 56; i++) {
    const bit5 = (rc >> 5) & 1;
    const bit4 = (rc >> 4) & 1;
    rc = ((rc << 1) & 0x3f) | (bit5 ^ bit4 ^ 1);
    out.push(rc);
  }
  return out;
})();

const loadCells = (bytes: Uint8Array, cell: 4 | 8): number[] => {
  if (cell === 8) return Array.from(bytes);
  const out: number[] = [];
  for (const b of bytes) out.push((b >> 4) & 0xf, b & 0xf);
  return out;
};

const storeCells = (cells: readonly number[], cell: 4 | 8, out: Uint8Array): void => {
  if (cell === 8) {
    for (let i = 0; i < cells.length; i++) out[i] = cells[i]! & 0xff;
    return;
  }
  for (let i = 0; i < cells.length / 2; i++) {
    out[i] = ((cells[2 * i]! & 0xf) << 4) | (cells[2 * i + 1]! & 0xf);
  }
};

/** Lane 2's LFSR: shift left, feeding the top bit XOR two below it into bit 0. */
const laneTwoLfsr = (x: number, cell: 4 | 8): number =>
  cell === 8
    ? (((x << 1) & 0xfe) ^ ((x >> 7) & 1) ^ ((x >> 5) & 1)) & 0xff
    : (((x << 1) & 0xe) ^ ((x >> 3) & 1) ^ ((x >> 2) & 1)) & 0xf;

/** Lane 3's: shift right, feeding bit 0 XOR one below the top into the top. */
const laneThreeLfsr = (x: number, cell: 4 | 8): number =>
  cell === 8
    ? (((x >> 1) & 0x7f) ^ ((x << 7) & 0x80) ^ ((x << 1) & 0x80)) & 0xff
    : (((x >> 1) & 0x7) ^ ((x << 3) & 0x8) ^ ((x << 2) & 0x8)) & 0xf;

/** The eight cells added to the top two rows, one row per round. */
function tweakeySchedule(tweakey: Uint8Array, params: SkinnyParams): number[][] {
  const { cell, lanes, rounds } = params;
  const laneBytes = cell === 8 ? 16 : 8;
  const lane = Array.from({ length: lanes }, (_, l) =>
    loadCells(tweakey.subarray(l * laneBytes, (l + 1) * laneBytes), cell),
  );

  const schedule: number[][] = [];
  for (let round = 0; round < rounds; round++) {
    const row = new Array<number>(8).fill(0);
    for (let i = 0; i < 8; i++) for (const l of lane) row[i] = row[i]! ^ l[i]!;
    schedule.push(row);

    for (let l = 0; l < lanes; l++) {
      const permuted = SKINNY_TWEAKEY_P.map((from) => lane[l]![from]!);
      // Only the top half runs the LFSR, and only on lanes two and three.
      if (l === 1) for (let i = 0; i < 8; i++) permuted[i] = laneTwoLfsr(permuted[i]!, cell);
      if (l === 2) for (let i = 0; i < 8; i++) permuted[i] = laneThreeLfsr(permuted[i]!, cell);
      lane[l] = permuted;
    }
  }
  return schedule;
}

/**
 * SKINNY as a `BlockCipher`, with the whole tweakey used as key material.
 *
 * `rounds` overrides the variant's count, which exists for exactly one caller: the test that checks this
 * generic implementation against `skinny128384plus`, whose "+" *is* a reduced round count.
 */
export function createSkinny(
  tweakey: Uint8Array,
  variant: SkinnyVariant = "128-256",
  rounds?: number,
): BlockCipher {
  const declared = SKINNY_VARIANTS[variant];
  if (declared === undefined) throw new Error(`Unknown SKINNY variant: ${String(variant)}.`);
  const params: SkinnyParams = rounds === undefined ? declared : { ...declared, rounds };

  const { cell, lanes } = params;
  const blockSize = cell === 8 ? 16 : 8;
  const expected = blockSize * lanes;
  if (tweakey.length !== expected) {
    throw new Error(
      `SKINNY-${variant}'s key is exactly ${expected} bytes; this one is ${tweakey.length}.`,
    );
  }
  if (params.rounds > SKINNY_RC.length) {
    throw new Error(`SKINNY runs at most ${SKINNY_RC.length} rounds; this asked for ${params.rounds}.`);
  }

  const sbox = cell === 8 ? SKINNY_SBOX8 : SBOX4;
  const sboxInverse = cell === 8 ? SBOX8_INV : SBOX4_INV;
  const mask = cell === 8 ? 0xff : 0xf;
  const schedule = tweakeySchedule(tweakey, params);

  return {
    blockSize,
    encryptBlock: (src, dst) => {
      const s = loadCells(src.subarray(0, blockSize), cell);
      for (let round = 0; round < params.rounds; round++) {
        for (let i = 0; i < 16; i++) s[i] = sbox[s[i]!]!;
        s[0] = s[0]! ^ (SKINNY_RC[round]! & 0xf);
        s[4] = s[4]! ^ ((SKINNY_RC[round]! >> 4) & 0x3);
        s[8] = s[8]! ^ 0x2;
        for (let i = 0; i < 8; i++) s[i] = s[i]! ^ schedule[round]![i]!;
        // ShiftRows: row i rotated right by i.
        for (let row = 1; row < 4; row++) {
          const before = s.slice(4 * row, 4 * row + 4);
          for (let c = 0; c < 4; c++) s[4 * row + c] = before[(c - row + 4) % 4]!;
        }
        for (let c = 0; c < 4; c++) {
          const r0 = s[c]!;
          const r1 = s[4 + c]!;
          const r2 = s[8 + c]!;
          const r3 = s[12 + c]!;
          const mid = r1 ^ r2;
          const low = r0 ^ r2;
          s[c] = (r3 ^ low) & mask;
          s[4 + c] = r0 & mask;
          s[8 + c] = mid & mask;
          s[12 + c] = low & mask;
        }
      }
      storeCells(s, cell, dst);
    },
    decryptBlock: (src, dst) => {
      const s = loadCells(src.subarray(0, blockSize), cell);
      for (let round = params.rounds - 1; round >= 0; round--) {
        for (let c = 0; c < 4; c++) {
          const out0 = s[c]!;
          const out1 = s[4 + c]!;
          const out2 = s[8 + c]!;
          const out3 = s[12 + c]!;
          const r0 = out1;
          const low = out3;
          const r2 = low ^ r0;
          const r1 = out2 ^ r2;
          const r3 = out0 ^ low;
          s[c] = r0 & mask;
          s[4 + c] = r1 & mask;
          s[8 + c] = r2 & mask;
          s[12 + c] = r3 & mask;
        }
        for (let row = 1; row < 4; row++) {
          const before = s.slice(4 * row, 4 * row + 4);
          for (let c = 0; c < 4; c++) s[4 * row + c] = before[(c + row) % 4]!;
        }
        for (let i = 0; i < 8; i++) s[i] = s[i]! ^ schedule[round]![i]!;
        s[0] = s[0]! ^ (SKINNY_RC[round]! & 0xf);
        s[4] = s[4]! ^ ((SKINNY_RC[round]! >> 4) & 0x3);
        s[8] = s[8]! ^ 0x2;
        for (let i = 0; i < 16; i++) s[i] = sboxInverse[s[i]!]!;
      }
      storeCells(s, cell, dst);
    },
  };
}
