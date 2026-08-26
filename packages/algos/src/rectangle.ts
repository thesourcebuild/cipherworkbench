/**
 * RECTANGLE, the bit-slice-oriented lightweight cipher (Zhang, Bao, Lin, Rijmen, Yang and Verbauwhede,
 * SCIENCE CHINA 2015), at both key sizes.
 *
 * `legacy`. No break of the full 25 rounds, and the analysis is reasonably mature -- but nothing has been
 * built on it and the 64-bit block carries the usual birthday bound, so it is a design to reproduce rather
 * than to choose.
 *
 * It is here because it is the clearest example in this repo of a cipher **designed to be bit-sliced**.
 * The state is four 16-bit rows, the S-box is applied to the four bits at the same position across those
 * rows *simultaneously* by fourteen logic gates, and the permutation layer is three rotations of three
 * rows. So there is no S-box table anywhere in the implementation -- and that is the point of the design,
 * not an optimisation of it.
 *
 * Four things to preserve.
 *
 * **The S-box is written as gates, and the table is derived from them.** `substitute` is the reference's
 * fourteen-operation sequence; `RECTANGLE_SBOX` below is built by running it over the sixteen possible
 * columns, and the inverse from that. So the table serves the decrypt path and the load-time permutation
 * check, and the gate sequence remains the definition -- which is the right way round, because the gates
 * are what the vectors check.
 *
 * **The two key sizes have genuinely different schedules.** The 80-bit one holds five 16-bit rows and
 * rotates a 16-bit word by twelve; the 128-bit one holds eight and rotates bytes. They share only the
 * S-box and the round constants, so this is two code paths rather than one parameterised by a length.
 *
 * **Only the low nibble of each key row is substituted, and only in the 80-bit schedule.** The 128-bit one
 * substitutes a whole byte column. Applying either rule to the other size gives a schedule whose first
 * round key is correct.
 *
 * **The rows are little-endian 16-bit words.** Row `i` is bytes `2i` and `2i+1`, low byte first, which is
 * what the published vectors assume.
 *
 * No oracle -- OpenSSL has never implemented RECTANGLE. What stands behind it is one published vector per
 * key size from FELICS's benchmarking suite, each checked in both directions.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
const ROUNDS = 25;

export type RectangleVariant = "64-80" | "64-128";

/** The 25 round constants, five bits each. */
const ROUND_CONSTANTS = [
  0x01, 0x02, 0x04, 0x09, 0x12, 0x05, 0x0b, 0x16, 0x0c, 0x19, 0x13, 0x07, 0x0f, 0x1f, 0x1e, 0x1c,
  0x18, 0x11, 0x03, 0x06, 0x0d, 0x1b, 0x17, 0x0e, 0x1d,
] as const;

const u16 = (x: number): number => x & 0xffff;
const rotl = (x: number, n: number): number => u16((x << n) | (x >>> (16 - n)));

/**
 * The S-box as fourteen logic gates over four rows, applied to all sixteen columns at once.
 *
 * This is the definition, transcribed from the reference. The table below is derived from it.
 */
function substitute(row: number[]): void {
  const t = new Array<number>(5);
  t[0] = u16(row[1]! ^ 0xffff);
  t[1] = u16(row[0]! & t[0]!);
  t[2] = u16(row[2]! ^ row[3]!);
  t[3] = u16(t[1]! ^ t[2]!);
  t[1] = u16(row[3]! | t[0]!);
  t[0] = u16(row[0]! ^ t[1]!);
  t[1] = u16(row[2]! ^ t[0]!);
  t[4] = u16(row[1]! ^ row[2]!);
  row[3] = u16(u16(t[2]! & t[0]!) ^ t[4]!);
  row[2] = u16(u16(t[3]! | t[4]!) ^ t[0]!);
  row[0] = t[3]!;
  row[1] = t[1]!;
}

/** The 4-bit table the gates compute, and its inverse. Both derived, neither transcribed. */
const SBOX = new Uint8Array(16);
const SBOX_INVERSE = new Uint8Array(16);
{
  for (let n = 0; n < 16; n++) {
    const column = [n & 1, (n >> 1) & 1, (n >> 2) & 1, (n >> 3) & 1];
    substitute(column);
    const value =
      (column[0]! & 1) | ((column[1]! & 1) << 1) | ((column[2]! & 1) << 2) | ((column[3]! & 1) << 3);
    SBOX[n] = value;
    SBOX_INVERSE[value] = n;
  }
  if (new Set(SBOX).size !== 16) throw new Error("RECTANGLE's gate sequence is not a permutation.");
}

/** Exported so a test can pin the derivation against the specification's published table. */
export const RECTANGLE_SBOX: Readonly<Uint8Array> = SBOX;

/** The inverse, applied column by column through the derived table. */
function substituteInverse(row: number[]): void {
  const out = [0, 0, 0, 0];
  for (let bit = 0; bit < 16; bit++) {
    const column =
      ((row[0]! >> bit) & 1) |
      (((row[1]! >> bit) & 1) << 1) |
      (((row[2]! >> bit) & 1) << 2) |
      (((row[3]! >> bit) & 1) << 3);
    const value = SBOX_INVERSE[column]!;
    for (let r = 0; r < 4; r++) out[r] = out[r]! | (((value >> r) & 1) << bit);
  }
  for (let r = 0; r < 4; r++) row[r] = u16(out[r]!);
}

/** Row 1 rotates by one, row 2 by twelve, row 3 by thirteen. */
const permute = (row: number[]): void => {
  row[1] = rotl(row[1]!, 1);
  row[2] = rotl(row[2]!, 12);
  row[3] = rotl(row[3]!, 13);
};
const permuteInverse = (row: number[]): void => {
  row[1] = rotl(row[1]!, 15);
  row[2] = rotl(row[2]!, 4);
  row[3] = rotl(row[3]!, 3);
};

/** The 80-bit schedule: five 16-bit rows, a nibble substitution and a 16-bit rotation by twelve. */
function schedule80(key: Uint8Array): number[][] {
  const k = Array.from(key);
  const out: number[][] = [];
  const emit = (): void => {
    const row: number[] = [];
    for (let j = 0; j < 4; j++) row.push(u16(k[2 * j]! | (k[2 * j + 1]! << 8)));
    out.push(row);
  };
  for (let round = 0; round < ROUNDS; round++) {
    emit();
    // Only the low nibble of each odd byte goes through the S-box.
    const lanes = [0, 1, 2, 3].map((j) => u16(k[2 * j + 1]! << 8));
    substitute(lanes);
    for (let j = 0; j < 4; j++) {
      k[2 * j + 1] = (k[2 * j + 1]! & 0xf0) ^ (((lanes[j]! >> 8) & 0xff) & 0x0f);
    }
    const t0 = k[0]!;
    const t1 = k[1]!;
    k[0] = k[1]! ^ k[2]!;
    k[1] = t0 ^ k[3]!;
    k[2] = k[4]!;
    k[3] = k[5]!;
    k[4] = k[6]!;
    k[5] = k[7]!;
    const rotated = rotl(u16((k[6]! << 8) ^ k[7]!), 12);
    k[6] = ((rotated >> 8) ^ k[8]!) & 0xff;
    k[7] = ((rotated & 255) ^ k[9]!) & 0xff;
    k[8] = t0;
    k[9] = t1;
    k[1] = k[1]! ^ ROUND_CONSTANTS[round]!;
  }
  emit();
  return out;
}

/** The 128-bit schedule: eight rows, a byte-column substitution, and two byte rotations. */
function schedule128(key: Uint8Array): number[][] {
  const k = Array.from(key);
  const out: number[][] = [];
  const emit = (): void => {
    const row: number[] = [];
    for (let j = 0; j < 4; j++) row.push(u16(k[j * 4 + 2]! | (k[j * 4 + 3]! << 8)));
    out.push(row);
  };
  for (let round = 0; round < ROUNDS; round++) {
    emit();
    const lanes = [0, 1, 2, 3].map((j) => u16(k[4 * j + 3]! << 8));
    substitute(lanes);
    for (let j = 0; j < 4; j++) k[4 * j + 3] = (lanes[j]! >> 8) & 0xff;
    const t = [k[0]!, k[1]!, k[2]!, k[3]!];
    k[0] = k[1]! ^ k[4]!;
    k[1] = k[2]! ^ k[5]!;
    k[2] = k[3]! ^ k[6]!;
    k[3] = t[0]! ^ k[7]!;
    for (let j = 0; j < 4; j++) k[4 + j] = k[8 + j]!;
    const t8 = k[8]!;
    const t9 = k[9]!;
    k[8] = k[10]! ^ k[12]!;
    k[9] = k[11]! ^ k[13]!;
    k[10] = t8 ^ k[14]!;
    k[11] = t9 ^ k[15]!;
    for (let j = 0; j < 4; j++) k[12 + j] = t[j]!;
    k[3] = k[3]! ^ ROUND_CONSTANTS[round]!;
  }
  emit();
  return out;
}

const KEY_LENGTHS: Readonly<Record<RectangleVariant, number>> = { "64-80": 10, "64-128": 16 };

/** RECTANGLE as a `BlockCipher`, at either key size. */
export function createRectangle(key: Uint8Array, variant: RectangleVariant = "64-128"): BlockCipher {
  const expected = KEY_LENGTHS[variant];
  if (expected === undefined) throw new Error(`Unknown RECTANGLE variant: ${String(variant)}.`);
  if (key.length !== expected) {
    throw new Error(
      `RECTANGLE-${variant}'s key is exactly ${expected} bytes; this one is ${key.length}.`,
    );
  }
  const rounds = variant === "64-80" ? schedule80(key) : schedule128(key);

  const load = (src: Uint8Array): number[] =>
    [0, 1, 2, 3].map((i) => u16(src[2 * i]! | (src[2 * i + 1]! << 8)));
  const store = (row: readonly number[], dst: Uint8Array): void => {
    for (let i = 0; i < 4; i++) {
      dst[2 * i] = row[i]! & 0xff;
      dst[2 * i + 1] = (row[i]! >> 8) & 0xff;
    }
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      const row = load(src);
      for (let r = 0; r < ROUNDS; r++) {
        for (let i = 0; i < 4; i++) row[i] = u16(row[i]! ^ rounds[r]![i]!);
        substitute(row);
        permute(row);
      }
      for (let i = 0; i < 4; i++) row[i] = u16(row[i]! ^ rounds[ROUNDS]![i]!);
      store(row, dst);
    },
    decryptBlock: (src, dst) => {
      const row = load(src);
      for (let i = 0; i < 4; i++) row[i] = u16(row[i]! ^ rounds[ROUNDS]![i]!);
      for (let r = ROUNDS - 1; r >= 0; r--) {
        permuteInverse(row);
        substituteInverse(row);
        for (let i = 0; i < 4; i++) row[i] = u16(row[i]! ^ rounds[r]![i]!);
      }
      store(row, dst);
    },
  };
}
