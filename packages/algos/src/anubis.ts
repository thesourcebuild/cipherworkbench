/**
 * Anubis, Barreto and Rijmen's NESSIE submission -- Khazad's sibling, at a 128-bit block.
 *
 * The two were designed together and share more than a lineage: **Anubis-tweaked's S-box is Khazad's,
 * entry for entry**, so this file imports `KHAZAD_SBOX` rather than storing a second copy. That is the
 * strongest form of the derive-don't-transcribe rule available here -- those 256 bytes are already
 * pinned by Khazad's 450 NESSIE vectors, so a failure in Anubis's own vectors points at the key
 * schedule or the matrix and not at a table.
 *
 * `legacy`. There is no attack on the full cipher; NESSIE declined to select it, and nothing has been
 * built on it since. Where Khazad is involutional with a 64-bit block, Anubis is involutional with a
 * 128-bit one and a key from 128 to 320 bits in 32-bit steps -- so it is the only cipher in this repo
 * with **seven** key lengths.
 *
 * **Two variants, and both are offered.** The submission was revised during NESSIE: the tweak replaced
 * the S-box. LibTomCrypt publishes fourteen vectors for each, so both are checkable, and the tool has a
 * variant control for the same reason GOST 28147-89 has an S-box-set control -- two implementations that
 * disagree about the table agree about nothing, and a value someone is holding came from one of them.
 * `tweaked` is the default: it is the final NESSIE version, and it is the one whose S-box is Khazad's.
 *
 * Four things to preserve.
 *
 * **Nothing else is stored either.** Every table an implementation normally ships comes out of two
 * facts -- the S-box and the matrix:
 *
 *  - `T0..T3[x]` are the four rows of the involutory matrix `[[1,2,4,6],[2,1,6,4],[4,6,1,2],[6,4,2,1]]`
 *    times `S[x]` over GF(2^8) under 0x11d. Note `T1` is *not* a byte rotation of `T0` even though `T2`
 *    is, because the matrix rows are reflections rather than rotations -- deriving them as rotations is
 *    right for two of the four.
 *  - `T4[x]` is `S[x]` in all four bytes.
 *  - `T5[x]` is `(x, 2x, 6x, 8x)`, the key schedule's own multipliers -- a different quadruple from the
 *    cipher's, which is the one thing here that looks like a typo and is not.
 *  - the **round constants are the S-box read four bytes at a time**: `rc[r] = S[4r..4r+3]`. So there is
 *    no constant table at all, and a wrong S-box entry breaks the schedule as well as the substitution.
 *
 * **The matrix is involutory, which is the whole design.** `H * H` is the identity, so encryption and
 * decryption are the same circuit and only the key schedule runs backwards. The tests assert that
 * rather than trusting it: a single wrong entry would leave encryption correct and make decryption a
 * different function, which is exactly what a round trip cannot see.
 *
 * **The last round masks each table's contribution to one byte.** Every round but the last XORs four
 * full words; the last takes the top byte from `T0`, the second from `T1`, and so on -- which is the
 * usual "no diffusion in the final round" written table-wise. Applying a full round there gives a
 * cipher that inverts against itself and reproduces nothing.
 *
 * **The inverse round keys are the forward ones in reverse with the matrix applied to the middle.**
 * `K'[0] = K[R]`, `K'[R] = K[0]`, and `K'[r] = theta(K[R-r])` for everything between. The middle step is
 * easy to leave out, and leaving it out is correct for a two-round cipher and nothing larger.
 *
 * No oracle: OpenSSL never implemented Anubis and nothing in this tree has it. What stands behind it is
 * LibTomCrypt's twenty-eight self-test vectors -- fourteen per variant, two at each of the seven key
 * lengths. See `tests/algos-anubis.test.ts`.
 */
import type { BlockCipher } from "./blockmodes";
import { KHAZAD_SBOX } from "./phase8-ciphers";

const BLOCK = 16;

/**
 * The original submission's S-box, which the tweak replaced.
 *
 * The one stored table in this file, and only because it is the variant Khazad does not share. Its
 * construction from a 4-bit mini-box was *tried* -- the same three-round structure `KHAZAD_SBOX` is
 * built from, over the specification's own P -- and reproduces none of these entries, so it is parsed
 * from a reference rather than derived. The tests require it to be a permutation and pin both ends.
 */
const ORIGINAL_SBOX = new Uint8Array([
  0xa7, 0xd3, 0xe6, 0x71, 0xd0, 0xac, 0x4d, 0x79, 0x3a, 0xc9, 0x91, 0xfc, 0x1e, 0x47, 0x54, 0xbd,
  0x8c, 0xa5, 0x7a, 0xfb, 0x63, 0xb8, 0xdd, 0xd4, 0xe5, 0xb3, 0xc5, 0xbe, 0xa9, 0x88, 0x0c, 0xa2,
  0x39, 0xdf, 0x29, 0xda, 0x2b, 0xa8, 0xcb, 0x4c, 0x4b, 0x22, 0xaa, 0x24, 0x41, 0x70, 0xa6, 0xf9,
  0x5a, 0xe2, 0xb0, 0x36, 0x7d, 0xe4, 0x33, 0xff, 0x60, 0x20, 0x08, 0x8b, 0x5e, 0xab, 0x7f, 0x78,
  0x7c, 0x2c, 0x57, 0xd2, 0xdc, 0x6d, 0x7e, 0x0d, 0x53, 0x94, 0xc3, 0x28, 0x27, 0x06, 0x5f, 0xad,
  0x67, 0x5c, 0x55, 0x48, 0x0e, 0x52, 0xea, 0x42, 0x5b, 0x5d, 0x30, 0x58, 0x51, 0x59, 0x3c, 0x4e,
  0x38, 0x8a, 0x72, 0x14, 0xe7, 0xc6, 0xde, 0x50, 0x8e, 0x92, 0xd1, 0x77, 0x93, 0x45, 0x9a, 0xce,
  0x2d, 0x03, 0x62, 0xb6, 0xb9, 0xbf, 0x96, 0x6b, 0x3f, 0x07, 0x12, 0xae, 0x40, 0x34, 0x46, 0x3e,
  0xdb, 0xcf, 0xec, 0xcc, 0xc1, 0xa1, 0xc0, 0xd6, 0x1d, 0xf4, 0x61, 0x3b, 0x10, 0xd8, 0x68, 0xa0,
  0xb1, 0x0a, 0x69, 0x6c, 0x49, 0xfa, 0x76, 0xc4, 0x9e, 0x9b, 0x6e, 0x99, 0xc2, 0xb7, 0x98, 0xbc,
  0x8f, 0x85, 0x1f, 0xb4, 0xf8, 0x11, 0x2e, 0x00, 0x25, 0x1c, 0x2a, 0x3d, 0x05, 0x4f, 0x7b, 0xb2,
  0x32, 0x90, 0xaf, 0x19, 0xa3, 0xf7, 0x73, 0x9d, 0x15, 0x74, 0xee, 0xca, 0x9f, 0x0f, 0x1b, 0x75,
  0x86, 0x84, 0x9c, 0x4a, 0x97, 0x1a, 0x65, 0xf6, 0xed, 0x09, 0xbb, 0x26, 0x83, 0xeb, 0x6f, 0x81,
  0x04, 0x6a, 0x43, 0x01, 0x17, 0xe1, 0x87, 0xf5, 0x8d, 0xe3, 0x23, 0x80, 0x44, 0x16, 0x66, 0x21,
  0xfe, 0xd5, 0x31, 0xd9, 0x35, 0x18, 0x02, 0x64, 0xf2, 0xf1, 0x56, 0xcd, 0x82, 0xc8, 0xba, 0xf0,
  0xef, 0xe9, 0xe8, 0xfd, 0x89, 0xd7, 0xc7, 0xb5, 0xa4, 0x2f, 0x95, 0x13, 0x0b, 0xf3, 0xe0, 0x37,
]);

/** Anubis's involutory diffusion matrix. Its rows are reflections of the first, not rotations. */
const MATRIX: readonly (readonly number[])[] = [
  [1, 2, 4, 6],
  [2, 1, 6, 4],
  [4, 6, 1, 2],
  [6, 4, 2, 1],
];

/** The key schedule's multipliers, which are a different quadruple from the cipher's. */
const SCHEDULE_MULTIPLIERS = [1, 2, 6, 8] as const;

const REDUCTION = 0x11d;

function gmul(a: number, b: number): number {
  let r = 0;
  let x = a;
  let y = b;
  for (let i = 0; i < 8; i++) {
    if ((y & 1) !== 0) r ^= x;
    x <<= 1;
    if ((x & 0x100) !== 0) x ^= REDUCTION;
    y >>= 1;
  }
  return r & 0xff;
}

const u32 = (x: number): number => x >>> 0;
const pack = (a: number, b: number, c: number, d: number): number =>
  u32((a << 24) | (b << 16) | (c << 8) | d);

export type AnubisVariant = "original" | "tweaked";

interface AnubisTables {
  /** The matrix rows applied to the S-box: `T[i][x] = H[i] * S[x]`, packed. */
  readonly rows: readonly Uint32Array[];
  /** `S[x]` broadcast to four bytes. */
  readonly broadcast: Uint32Array;
  /** `(x, 2x, 6x, 8x)`, for the key schedule. Independent of the S-box, so it is built once. */
  readonly scheduleMul: Uint32Array;
  /** Nineteen constants, which are the S-box read four bytes at a time. */
  readonly constants: Uint32Array;
  readonly sbox: Readonly<Uint8Array>;
}

/** Independent of the S-box, so it is shared rather than rebuilt per variant. */
const SCHEDULE_MUL = Uint32Array.from({ length: 256 }, (_, x) =>
  pack(...(SCHEDULE_MULTIPLIERS.map((m) => gmul(x, m)) as [number, number, number, number])),
);

function buildTables(sbox: Readonly<Uint8Array>): AnubisTables {
  const rows = MATRIX.map((row) =>
    Uint32Array.from({ length: 256 }, (_, x) =>
      pack(
        gmul(sbox[x]!, row[0]!),
        gmul(sbox[x]!, row[1]!),
        gmul(sbox[x]!, row[2]!),
        gmul(sbox[x]!, row[3]!),
      ),
    ),
  );
  const broadcast = Uint32Array.from({ length: 256 }, (_, x) =>
    pack(sbox[x]!, sbox[x]!, sbox[x]!, sbox[x]!),
  );
  // Nineteen is enough for the longest key: R = 8 + N, and N tops out at 10.
  const constants = Uint32Array.from({ length: 19 }, (_, r) =>
    pack(sbox[4 * r]!, sbox[4 * r + 1]!, sbox[4 * r + 2]!, sbox[4 * r + 3]!),
  );
  return { rows, broadcast, scheduleMul: SCHEDULE_MUL, constants, sbox };
}

const TABLES: Readonly<Record<AnubisVariant, AnubisTables>> = {
  tweaked: buildTables(KHAZAD_SBOX),
  original: buildTables(ORIGINAL_SBOX),
};

{
  // A stored table gets what a derived one does not need: the property a mistyped entry breaks.
  if (new Set(ORIGINAL_SBOX).size !== 256) {
    throw new Error("Anubis's original S-box is not a permutation.");
  }
}

/** Exported so the tests can pin the two S-boxes and the derived constants without re-deriving them. */
export const ANUBIS_SBOX_FIRST: Readonly<Record<AnubisVariant, number>> = {
  tweaked: KHAZAD_SBOX[0]!,
  original: ORIGINAL_SBOX[0]!,
};
export const ANUBIS_MATRIX = MATRIX;
export const ANUBIS_ROUND_CONSTANT_FIRST: Readonly<Record<AnubisVariant, number>> = {
  tweaked: TABLES.tweaked.constants[0]!,
  original: TABLES.original.constants[0]!,
};

const KEY_LENGTHS: readonly number[] = [16, 20, 24, 28, 32, 36, 40];

/** The byte at position `slot` of a word, counting from the most significant. */
const byteAt = (word: number, slot: number): number => (word >>> (24 - 8 * slot)) & 0xff;

interface Schedule {
  readonly encryptKeys: readonly number[][];
  readonly decryptKeys: readonly number[][];
  readonly rounds: number;
}

function schedule(key: Uint8Array, t: AnubisTables): Schedule {
  if (!KEY_LENGTHS.includes(key.length)) {
    throw new Error(
      `Anubis's key is 16, 20, 24, 28, 32, 36 or 40 bytes; this one is ${key.length}.`,
    );
  }
  const words = key.length >> 2;
  const rounds = 8 + words;

  const kappa = Array.from({ length: words }, (_, i) =>
    pack(key[4 * i]!, key[4 * i + 1]!, key[4 * i + 2]!, key[4 * i + 3]!),
  );

  const encryptKeys: number[][] = [];
  for (let round = 0; round <= rounds; round++) {
    // The round key: the last key word substituted, then folded with each earlier word in turn.
    let current = [0, 1, 2, 3].map((slot) => t.broadcast[byteAt(kappa[words - 1]!, slot)]!);
    for (let i = words - 2; i >= 0; i--) {
      current = current.map((value, slot) =>
        u32(
          t.broadcast[byteAt(kappa[i]!, slot)]! ^
            (t.scheduleMul[byteAt(value, 0)]! & 0xff000000) ^
            (t.scheduleMul[byteAt(value, 1)]! & 0x00ff0000) ^
            (t.scheduleMul[byteAt(value, 2)]! & 0x0000ff00) ^
            (t.scheduleMul[byteAt(value, 3)]! & 0x000000ff),
        ),
      );
    }
    encryptKeys.push(current);
    if (round === rounds) break;

    // Evolve the key state: the same diffusion the cipher uses, over a rotating word index.
    const next: number[] = [];
    for (let i = 0; i < words; i++) {
      let j = i;
      let acc = t.rows[0]![byteAt(kappa[j]!, 0)]!;
      j = j === 0 ? words - 1 : j - 1;
      acc = u32(acc ^ t.rows[1]![byteAt(kappa[j]!, 1)]!);
      j = j === 0 ? words - 1 : j - 1;
      acc = u32(acc ^ t.rows[2]![byteAt(kappa[j]!, 2)]!);
      j = j === 0 ? words - 1 : j - 1;
      acc = u32(acc ^ t.rows[3]![byteAt(kappa[j]!, 3)]!);
      next.push(acc);
    }
    kappa[0] = u32(next[0]! ^ t.constants[round]!);
    for (let i = 1; i < words; i++) kappa[i] = next[i]!;
  }

  // The inverse schedule: reversed, with the diffusion applied to everything but the two ends.
  const decryptKeys: number[][] = Array.from({ length: rounds + 1 }, () => [0, 0, 0, 0]);
  for (let i = 0; i < 4; i++) {
    decryptKeys[0]![i] = encryptKeys[rounds]![i]!;
    decryptKeys[rounds]![i] = encryptKeys[0]![i]!;
  }
  for (let round = 1; round < rounds; round++) {
    for (let i = 0; i < 4; i++) {
      const w = encryptKeys[rounds - round]![i]!;
      decryptKeys[round]![i] = u32(
        t.rows[0]![t.broadcast[byteAt(w, 0)]! & 0xff]! ^
          t.rows[1]![t.broadcast[byteAt(w, 1)]! & 0xff]! ^
          t.rows[2]![t.broadcast[byteAt(w, 2)]! & 0xff]! ^
          t.rows[3]![t.broadcast[byteAt(w, 3)]! & 0xff]!,
      );
    }
  }
  return { encryptKeys, decryptKeys, rounds };
}

const LAST_ROUND_MASKS = [0xff000000, 0x00ff0000, 0x0000ff00, 0x000000ff] as const;

/** One direction. Both use the same function; only the round keys differ, which is the involution. */
function crypt(
  src: Uint8Array,
  dst: Uint8Array,
  roundKeys: readonly number[][],
  rounds: number,
  t: AnubisTables,
): void {
  let state = [0, 1, 2, 3].map((i) =>
    u32(pack(src[4 * i]!, src[4 * i + 1]!, src[4 * i + 2]!, src[4 * i + 3]!) ^ roundKeys[0]![i]!),
  );

  for (let round = 1; round < rounds; round++) {
    const previous = state;
    state = [0, 1, 2, 3].map((slot) =>
      u32(
        t.rows[0]![byteAt(previous[0]!, slot)]! ^
          t.rows[1]![byteAt(previous[1]!, slot)]! ^
          t.rows[2]![byteAt(previous[2]!, slot)]! ^
          t.rows[3]![byteAt(previous[3]!, slot)]! ^
          roundKeys[round]![slot]!,
      ),
    );
  }

  // The last round keeps one byte from each table instead of the whole word: no diffusion.
  for (let slot = 0; slot < 4; slot++) {
    const w = u32(
      (t.rows[0]![byteAt(state[0]!, slot)]! & LAST_ROUND_MASKS[0]) ^
        (t.rows[1]![byteAt(state[1]!, slot)]! & LAST_ROUND_MASKS[1]) ^
        (t.rows[2]![byteAt(state[2]!, slot)]! & LAST_ROUND_MASKS[2]) ^
        (t.rows[3]![byteAt(state[3]!, slot)]! & LAST_ROUND_MASKS[3]) ^
        roundKeys[rounds]![slot]!,
    );
    dst[4 * slot] = (w >>> 24) & 0xff;
    dst[4 * slot + 1] = (w >>> 16) & 0xff;
    dst[4 * slot + 2] = (w >>> 8) & 0xff;
    dst[4 * slot + 3] = w & 0xff;
  }
}

/**
 * Anubis as a `BlockCipher`.
 *
 * The key is 16 to 40 bytes in steps of four, and the variant defaults to `tweaked` -- NESSIE's final
 * version, and the one whose S-box is Khazad's.
 */
export function createAnubis(key: Uint8Array, variant: AnubisVariant = "tweaked"): BlockCipher {
  const t = TABLES[variant];
  const { encryptKeys, decryptKeys, rounds } = schedule(key, t);
  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => crypt(src, dst, encryptKeys, rounds, t),
    decryptBlock: (src, dst) => crypt(src, dst, decryptKeys, rounds, t),
  };
}
