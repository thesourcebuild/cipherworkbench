/**
 * SNOW 3G, the stream cipher behind 3GPP's 128-EEA1 and 128-EIA1 -- LTE's confidentiality and
 * integrity algorithms, and UMTS's UEA2/UIA2 before them.
 *
 * It is the third 3GPP primitive here, after KASUMI and ZUC, and the one that has held up: KASUMI is
 * `broken` under related keys, ZUC is the newer replacement, and SNOW 3G has no attack on its full
 * form after twenty years of being in every LTE handset. `modern`, and here to reproduce values -- a
 * captured LTE bearer is a real thing to want to check.
 *
 * A sixteen-stage LFSR over GF(2^32) driving a three-register finite state machine. Structurally it is
 * SNOW 2.0 with a third FSM register and a second 32-bit S-box, which is what closed the distinguisher
 * Watanabe, Biryukov and De Canniere found in SNOW 2.0.
 *
 * Four things to preserve.
 *
 * **S1's byte substitution is the AES S-box.** Not "AES-like" -- the same 256 entries, which is why
 * this file imports `AES_SBOX` from `aes-round.ts` rather than storing a table. Its 4x4 matrix is also
 * AES's MixColumns, reduced by 0x1b. So half of SNOW 3G's substitution layer is already pinned by
 * AES's own vectors, ARIA's, Groestl's, SHAvite-3's, ECHO's and now Deoxys-II's.
 *
 * **S2's is not, and that table is stored.** `SQ` is the specification's own 256-byte S-box, and its
 * matrix reduces by 0x69 instead. The specification describes it as coming from a Dickson polynomial
 * over GF(2^8); that construction was *tried* here and reproduces none of these entries under any
 * degree from 2 to 255 crossed with all thirty irreducible degree-8 polynomials, so the table is
 * parsed from a reference rather than derived. Recording the negative result so nobody repeats the
 * search -- and the tests check it is a permutation and pin both ends, which is what a stored table
 * gets instead of a derivation.
 *
 * **Both 256-entry 32-bit tables are derived.** MULalpha and DIValpha are `MULxPOW` at the exponents
 * (23, 245, 48, 239) and (16, 39, 6, 64) over the reduction byte 0xa9 -- which is the same field
 * polynomial SOSEMANUK uses, a coincidence of the two designs rather than shared structure. 2 KB of
 * table out of two lines, on the same principle as `sosemanuk.ts`'s 512 words.
 *
 * **The generator discards one output.** After the 32 initialisation rounds the FSM is clocked and the
 * LFSR advanced once with nothing emitted, and only then does each round produce a word. Skipping that
 * shifts the whole keystream by four bytes -- the same trap ZUC's discarded round has, one file over.
 *
 * No oracle. What stands behind it is all four test sets from 3GPP TS 35.216, one of which runs to
 * 10,000 bytes; see `tests/algos-snow3g.test.ts`.
 */
import { AES_SBOX } from "./aes-round";

const u32 = (x: number): number => x >>> 0;

/**
 * The S2 substitution, from the specification's own table.
 *
 * Stored rather than derived, and the header says why. `SQ[0]` is 0x25, which is where
 * `S2(0) = 0x25252525` comes from -- a value that appears in every reference implementation as a
 * hardcoded shortcut for the first initialisation round, and therefore a useful thing to recognise.
 */
const SQ = new Uint8Array([
  0x25, 0x24, 0x73, 0x67, 0xd7, 0xae, 0x5c, 0x30, 0xa4, 0xee, 0x6e, 0xcb, 0x7d, 0xb5, 0x82, 0xdb,
  0xe4, 0x8e, 0x48, 0x49, 0x4f, 0x5d, 0x6a, 0x78, 0x70, 0x88, 0xe8, 0x5f, 0x5e, 0x84, 0x65, 0xe2,
  0xd8, 0xe9, 0xcc, 0xed, 0x40, 0x2f, 0x11, 0x28, 0x57, 0xd2, 0xac, 0xe3, 0x4a, 0x15, 0x1b, 0xb9,
  0xb2, 0x80, 0x85, 0xa6, 0x2e, 0x02, 0x47, 0x29, 0x07, 0x4b, 0x0e, 0xc1, 0x51, 0xaa, 0x89, 0xd4,
  0xca, 0x01, 0x46, 0xb3, 0xef, 0xdd, 0x44, 0x7b, 0xc2, 0x7f, 0xbe, 0xc3, 0x9f, 0x20, 0x4c, 0x64,
  0x83, 0xa2, 0x68, 0x42, 0x13, 0xb4, 0x41, 0xcd, 0xba, 0xc6, 0xbb, 0x6d, 0x4d, 0x71, 0x21, 0xf4,
  0x8d, 0xb0, 0xe5, 0x93, 0xfe, 0x8f, 0xe6, 0xcf, 0x43, 0x45, 0x31, 0x22, 0x37, 0x36, 0x96, 0xfa,
  0xbc, 0x0f, 0x08, 0x52, 0x1d, 0x55, 0x1a, 0xc5, 0x4e, 0x23, 0x69, 0x7a, 0x92, 0xff, 0x5b, 0x5a,
  0xeb, 0x9a, 0x1c, 0xa9, 0xd1, 0x7e, 0x0d, 0xfc, 0x50, 0x8a, 0xb6, 0x62, 0xf5, 0x0a, 0xf8, 0xdc,
  0x03, 0x3c, 0x0c, 0x39, 0xf1, 0xb8, 0xf3, 0x3d, 0xf2, 0xd5, 0x97, 0x66, 0x81, 0x32, 0xa0, 0x00,
  0x06, 0xce, 0xf6, 0xea, 0xb7, 0x17, 0xf7, 0x8c, 0x79, 0xd6, 0xa7, 0xbf, 0x8b, 0x3f, 0x1f, 0x53,
  0x63, 0x75, 0x35, 0x2c, 0x60, 0xfd, 0x27, 0xd3, 0x94, 0xa5, 0x7c, 0xa1, 0x05, 0x58, 0x2d, 0xbd,
  0xd9, 0xc7, 0xaf, 0x6b, 0x54, 0x0b, 0xe0, 0x38, 0x04, 0xc8, 0x9d, 0xe7, 0x14, 0xb1, 0x87, 0x9c,
  0xdf, 0x6f, 0xf9, 0xda, 0x2a, 0xc4, 0x59, 0x16, 0x74, 0x91, 0xab, 0x26, 0x61, 0x76, 0x34, 0x2b,
  0xad, 0x99, 0xfb, 0x72, 0xec, 0x33, 0x12, 0xde, 0x98, 0x3b, 0xc0, 0x9b, 0x3e, 0x18, 0x10, 0x3a,
  0x56, 0xe1, 0x77, 0xc9, 0x1e, 0x9e, 0x95, 0xa3, 0x90, 0x19, 0xa8, 0x6c, 0x09, 0xd0, 0xf0, 0x86,
]);

/** Multiply by x in GF(2^8) under a reduction byte the caller supplies. */
const mulX = (v: number, c: number): number =>
  (v & 0x80) !== 0 ? (((v << 1) & 0xff) ^ c) & 0xff : (v << 1) & 0xff;

const mulXPow = (v: number, times: number, c: number): number => {
  let r = v;
  for (let i = 0; i < times; i++) r = mulX(r, c);
  return r;
};

const pack = (a: number, b: number, c: number, d: number): number =>
  u32((a << 24) | (b << 16) | (c << 8) | d);

/** MULalpha and DIValpha, both derived. The field polynomial's low byte is 0xa9. */
const MUL_ALPHA = new Uint32Array(256);
const DIV_ALPHA = new Uint32Array(256);
for (let x = 0; x < 256; x++) {
  MUL_ALPHA[x] = pack(
    mulXPow(x, 23, 0xa9),
    mulXPow(x, 245, 0xa9),
    mulXPow(x, 48, 0xa9),
    mulXPow(x, 239, 0xa9),
  );
  DIV_ALPHA[x] = pack(
    mulXPow(x, 16, 0xa9),
    mulXPow(x, 39, 0xa9),
    mulXPow(x, 6, 0xa9),
    mulXPow(x, 64, 0xa9),
  );
}

/** Exported so a test can pin the two derivations, and the stored table, against a reference. */
export const SNOW3G_TABLE_FIRST: readonly number[] = [
  MUL_ALPHA[1]!,
  DIV_ALPHA[1]!,
  SQ[0]!,
  SQ[255]!,
];

/** The stored S-box, exported so a test can require it to be a permutation. */
export const SNOW3G_SQ: Readonly<Uint8Array> = SQ;

/**
 * One of the two 32-to-32-bit S-boxes: substitute each byte, then an AES-style MixColumns.
 *
 * The two differ only in the byte table and the reduction constant, so they are one function here --
 * which is also the statement that the *matrix* is shared between them, and it is.
 */
function sbox32(word: number, table: Readonly<Uint8Array>, reduction: number): number {
  const a = table[(word >>> 24) & 0xff]!;
  const b = table[(word >>> 16) & 0xff]!;
  const c = table[(word >>> 8) & 0xff]!;
  const d = table[word & 0xff]!;
  const m = (v: number): number => mulX(v, reduction);
  return pack(
    (m(a) ^ b ^ c ^ m(d) ^ d) & 0xff,
    (m(a) ^ a ^ m(b) ^ c ^ d) & 0xff,
    (a ^ m(b) ^ b ^ m(c) ^ d) & 0xff,
    (a ^ b ^ m(c) ^ c ^ m(d)) & 0xff,
  );
}

const s1 = (word: number): number => sbox32(word, AES_SBOX, 0x1b);
const s2 = (word: number): number => sbox32(word, SQ, 0x69);

export interface Snow3gGenerator {
  /** The next `n` bytes of keystream. Successive calls continue where the last left off. */
  keystream(n: number): Uint8Array;
}

/** SNOW 3G's keystream generator. Key and IV are both exactly 16 bytes. */
export function createSnow3g(key: Uint8Array, iv: Uint8Array): Snow3gGenerator {
  if (key.length !== 16) {
    throw new Error(`SNOW 3G's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  if (iv.length !== 16) {
    throw new Error(`SNOW 3G's IV is exactly 16 bytes; this one is ${iv.length}.`);
  }
  const word = (bytes: Uint8Array, i: number): number =>
    u32(
      (bytes[4 * i]! << 24) |
        (bytes[4 * i + 1]! << 16) |
        (bytes[4 * i + 2]! << 8) |
        bytes[4 * i + 3]!,
    );
  const k = [0, 1, 2, 3].map((i) => word(key, i));
  const v = [0, 1, 2, 3].map((i) => word(iv, i));

  // The LFSR is loaded from the key, its complement, and the IV in four of the sixteen slots.
  const s = new Uint32Array(16);
  s[15] = u32(k[3]! ^ v[0]!);
  s[14] = k[2]!;
  s[13] = k[1]!;
  s[12] = u32(k[0]! ^ v[1]!);
  s[11] = u32(k[3]! ^ 0xffffffff);
  s[10] = u32(k[2]! ^ 0xffffffff ^ v[2]!);
  s[9] = u32(k[1]! ^ 0xffffffff ^ v[3]!);
  s[8] = u32(k[0]! ^ 0xffffffff);
  s[7] = k[3]!;
  s[6] = k[2]!;
  s[5] = k[1]!;
  s[4] = k[0]!;
  s[3] = u32(k[3]! ^ 0xffffffff);
  s[2] = u32(k[2]! ^ 0xffffffff);
  s[1] = u32(k[1]! ^ 0xffffffff);
  s[0] = u32(k[0]! ^ 0xffffffff);

  let r1 = 0;
  let r2 = 0;
  let r3 = 0;

  /** One FSM step, returning the word it contributes. */
  const clockFsm = (): number => {
    const f = u32(u32(s[15]! + r1) ^ r2);
    const next = u32(r2 + u32(r3 ^ s[5]!));
    r3 = s2(r2);
    r2 = s1(r1);
    r1 = next;
    return f;
  };

  /**
   * One LFSR step. `feedback` is the FSM's output during initialisation and zero afterwards, which is
   * the *only* difference between the two modes.
   */
  const clockLfsr = (feedback: number): void => {
    const next = u32(
      u32((s[0]! << 8) & 0xffffff00) ^
        MUL_ALPHA[(s[0]! >>> 24) & 0xff]! ^
        s[2]! ^
        u32((s[11]! >>> 8) & 0x00ffffff) ^
        DIV_ALPHA[s[11]! & 0xff]! ^
        feedback,
    );
    for (let i = 0; i < 15; i++) s[i] = s[i + 1]!;
    s[15] = next;
  };

  for (let round = 0; round < 32; round++) clockLfsr(clockFsm());
  // The discarded output: one step in keystream mode before anything is emitted.
  clockFsm();
  clockLfsr(0);

  let held = new Uint8Array(0);
  let heldAt = 0;
  return {
    keystream(n) {
      const out = new Uint8Array(n);
      let at = 0;
      while (at < n) {
        if (heldAt >= held.length) {
          const ks = u32(clockFsm() ^ s[0]!);
          clockLfsr(0);
          held = new Uint8Array([
            (ks >>> 24) & 0xff,
            (ks >>> 16) & 0xff,
            (ks >>> 8) & 0xff,
            ks & 0xff,
          ]);
          heldAt = 0;
        }
        out[at++] = held[heldAt++]!;
      }
      return out;
    },
  };
}

/** Encrypt or decrypt -- the same operation, as for every stream cipher. */
export function snow3gCrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const ks = createSnow3g(key, iv).keystream(data.length);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i]! ^ ks[i]!;
  return out;
}
