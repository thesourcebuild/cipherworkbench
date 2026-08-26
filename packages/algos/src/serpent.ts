/**
 * Serpent, the AES finalist that came second, over the shared `BlockCipher` interface.
 *
 * Thirty-two rounds where Rijndael has ten, and a security margin nobody has come close to eroding --
 * the best published attack still reaches 12 rounds. It lost on speed, and it is here because it is
 * the conservative choice people reach for when AES's margin worries them: VeraCrypt, TrueCrypt's
 * cascades and several disk-encryption tools offer it, and GnuPG lists it.
 *
 * Four things to know.
 *
 * **This is the bitslice representation, which is not how the paper describes the cipher.** Serpent
 * has two equivalent descriptions -- a "standard" one over bit-permuted nibbles and a bitsliced one
 * over four 32-bit words -- and every real implementation uses the second, because the first exists
 * only to explain the design. The two agree on the ciphertext and on nothing in between.
 *
 * **The S-box is applied across the words, not within them.** For each of the 32 bit positions the
 * four words contribute one bit each, least significant word first, and that nibble is substituted.
 * Reversing the word order gives a cipher that round-trips and matches nothing.
 *
 * **The key is padded with a single one bit.** A key shorter than 256 bits gets a `1` immediately
 * after it and zeros to the end -- not zeros alone. So a 128-bit key of all zeros is *not* the same
 * as a 256-bit key of all zeros, which is exactly what Bouncy Castle's vector pair checks.
 *
 * **The subkeys are S-boxed too, in a different order from the rounds.** Round `i` uses S-box
 * `i mod 8`; subkey `i` is produced with S-box `(3 - i) mod 8`. Using the same order for both is a
 * mistake that leaves the first four subkeys correct.
 *
 * The S-boxes below were parsed from Frank Stajano's reference implementation, which is the
 * `SBoxDecimalTable` the submission itself shipped. There is no oracle -- OpenSSL has never
 * implemented Serpent -- so Bouncy Castle's published vectors are the check.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 16;
/** The golden-ratio constant the key schedule mixes in, as every ARX design of that era used. */
const PHI = 0x9e3779b9;

/**
 * The eight S-boxes, and their inverses derived at load.
 *
 * Exported because SOSEMANUK's output transform is Serpent's S2 applied bitsliced, and its IV
 * injection is this cipher reduced to 24 rounds -- so `sosemanuk.ts` reuses the table, the
 * substitution and the linear transform rather than keeping a second copy of any of them. That
 * matters more than saving lines: these are already pinned by Bouncy Castle's Serpent vectors, so a
 * SOSEMANUK failure points at SOSEMANUK.
 */
export const SERPENT_SBOX: readonly (readonly number[])[] = [
  [0x3, 0x8, 0xf, 0x1, 0xa, 0x6, 0x5, 0xb, 0xe, 0xd, 0x4, 0x2, 0x7, 0x0, 0x9, 0xc],
  [0xf, 0xc, 0x2, 0x7, 0x9, 0x0, 0x5, 0xa, 0x1, 0xb, 0xe, 0x8, 0x6, 0xd, 0x3, 0x4],
  [0x8, 0x6, 0x7, 0x9, 0x3, 0xc, 0xa, 0xf, 0xd, 0x1, 0xe, 0x4, 0x0, 0xb, 0x5, 0x2],
  [0x0, 0xf, 0xb, 0x8, 0xc, 0x9, 0x6, 0x3, 0xd, 0x1, 0x2, 0x4, 0xa, 0x7, 0x5, 0xe],
  [0x1, 0xf, 0x8, 0x3, 0xc, 0x0, 0xb, 0x6, 0x2, 0x5, 0x4, 0xa, 0x9, 0xe, 0x7, 0xd],
  [0xf, 0x5, 0x2, 0xb, 0x4, 0xa, 0x9, 0xc, 0x0, 0x3, 0xe, 0x8, 0xd, 0x6, 0x7, 0x1],
  [0x7, 0x2, 0xc, 0x5, 0x8, 0x4, 0x6, 0xb, 0xe, 0x9, 0x1, 0xf, 0xd, 0x3, 0xa, 0x0],
  [0x1, 0xd, 0xf, 0x0, 0xe, 0x8, 0x2, 0xb, 0x7, 0x4, 0xc, 0xa, 0x9, 0x3, 0x5, 0x6],
];

/** The private alias the rest of this file was written against. */
const SBOX = SERPENT_SBOX;

const SBOX_INV: readonly (readonly number[])[] = SBOX.map((box) => {
  const inverse = new Array<number>(16).fill(-1);
  for (let i = 0; i < 16; i++) inverse[box[i]!] = i;
  if (inverse.some((v) => v < 0)) throw new Error("A Serpent S-box is not a permutation.");
  return inverse;
});

const u32 = (x: number): number => x >>> 0;
const rol = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));
const ror = (x: number, n: number): number => u32((x >>> n) | (x << (32 - n)));

/** Substitutes all 32 nibbles that the four words spell out, bit position by bit position. */
function substitute(box: readonly number[], words: readonly number[]): number[] {
  const out = [0, 0, 0, 0];
  for (let bit = 0; bit < 32; bit++) {
    let nibble = 0;
    for (let w = 0; w < 4; w++) nibble |= ((words[w]! >>> bit) & 1) << w;
    const value = box[nibble]!;
    for (let w = 0; w < 4; w++) out[w] = u32(out[w]! | (((value >>> w) & 1) << bit));
  }
  return out;
}

/** The linear transformation, and its inverse. */
function linear(x: readonly number[]): number[] {
  let [a, b, c, d] = x as [number, number, number, number];
  a = rol(a, 13);
  c = rol(c, 3);
  b = u32(b ^ a ^ c);
  d = u32(d ^ c ^ u32(a << 3));
  b = rol(b, 1);
  d = rol(d, 7);
  a = u32(a ^ b ^ d);
  c = u32(c ^ d ^ u32(b << 7));
  a = rol(a, 5);
  c = rol(c, 22);
  return [a, b, c, d];
}

function linearInverse(x: readonly number[]): number[] {
  let [a, b, c, d] = x as [number, number, number, number];
  c = ror(c, 22);
  a = ror(a, 5);
  c = u32(c ^ d ^ u32(b << 7));
  a = u32(a ^ b ^ d);
  d = ror(d, 7);
  b = ror(b, 1);
  d = u32(d ^ c ^ u32(a << 3));
  b = u32(b ^ a ^ c);
  c = ror(c, 3);
  a = ror(a, 13);
  return [a, b, c, d];
}

/**
 * The subkeys, four words each, `rounds + 1` of them.
 *
 * The round count is a parameter because SOSEMANUK keys Serpent reduced to 24 rounds and therefore
 * wants 25 subkeys where the cipher wants 33. The recurrence, the padding bit and the box order are
 * identical; only how far the word array is extended differs, so there is one implementation.
 */
export function serpentSubkeys(key: Uint8Array, rounds = 32): number[][] {
  /**
   * Any length up to 32 is accepted *here*, and the cipher's own 16/24/32 is enforced in
   * `createSerpent` instead.
   *
   * The padding bit makes every shorter length well defined, and SOSEMANUK's reference vector keys
   * this schedule with five bytes -- so the constraint belongs to Serpent-the-cipher rather than to
   * Serpent-the-key-schedule, and putting it here would make a published value unreachable.
   */
  if (key.length < 1 || key.length > 32) {
    throw new Error(`A Serpent key schedule takes 1 to 32 bytes; this one is ${key.length}.`);
  }
  const padded = new Uint8Array(32);
  padded.set(key);
  // The single one bit, which is what makes a short key different from the same key zero-extended.
  if (key.length < 32) padded[key.length] = 0x01;

  const words = 4 * (rounds + 1);
  const w = new Array<number>(8 + words).fill(0);
  for (let i = 0; i < 8; i++) {
    w[i] = u32(
      padded[4 * i]! | (padded[4 * i + 1]! << 8) | (padded[4 * i + 2]! << 16) | (padded[4 * i + 3]! << 24),
    );
  }
  for (let i = 8; i < 8 + words; i++) {
    w[i] = rol(u32(w[i - 8]! ^ w[i - 5]! ^ w[i - 3]! ^ w[i - 1]! ^ PHI ^ (i - 8)), 11);
  }

  const keys: number[][] = [];
  for (let i = 0; i <= rounds; i++) {
    // S-box (3 - i) mod 8, not i mod 8: the subkeys and the rounds walk the boxes differently.
    keys.push(substitute(SBOX[(((3 - i) % 8) + 8) % 8]!, w.slice(8 + i * 4, 12 + i * 4)));
  }
  return keys;
}

const load = (src: Uint8Array): number[] =>
  [0, 1, 2, 3].map((i) =>
    u32(src[4 * i]! | (src[4 * i + 1]! << 8) | (src[4 * i + 2]! << 16) | (src[4 * i + 3]! << 24)),
  );

function store(x: readonly number[], dst: Uint8Array): void {
  for (let i = 0; i < 4; i++) {
    dst[4 * i] = x[i]! & 0xff;
    dst[4 * i + 1] = (x[i]! >>> 8) & 0xff;
    dst[4 * i + 2] = (x[i]! >>> 16) & 0xff;
    dst[4 * i + 3] = (x[i]! >>> 24) & 0xff;
  }
}

const xorKey = (x: readonly number[], key: readonly number[]): number[] =>
  x.map((word, i) => u32(word ^ key[i]!));

/**
 * The bitsliced substitution and the linear transform, under names that survive a flat barrel.
 *
 * `substitute` and `linear` are far too generic to export from `@ocs/algos` directly; these aliases
 * are what `sosemanuk.ts` imports, so there is one implementation of each rather than two.
 */
export const serpentSubstitute = substitute;
export const serpentLinear = linear;

/** Serpent as a `BlockCipher`. */
export function createSerpent(key: Uint8Array): BlockCipher {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(`Serpent's key is 16, 24 or 32 bytes; this one is ${key.length}.`);
  }
  const rk = serpentSubkeys(key);

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      let x = load(src);
      for (let round = 0; round < 31; round++) {
        x = linear(substitute(SBOX[round % 8]!, xorKey(x, rk[round]!)));
      }
      // The last round substitutes and then XORs the extra subkey instead of applying the transform.
      x = xorKey(substitute(SBOX[7]!, xorKey(x, rk[31]!)), rk[32]!);
      store(x, dst);
    },
    decryptBlock: (src, dst) => {
      let x = load(src);
      x = substitute(SBOX_INV[7]!, xorKey(x, rk[32]!));
      x = xorKey(x, rk[31]!);
      for (let round = 30; round >= 0; round--) {
        x = xorKey(substitute(SBOX_INV[round % 8]!, linearInverse(x)), rk[round]!);
      }
      store(x, dst);
    },
  };
}
