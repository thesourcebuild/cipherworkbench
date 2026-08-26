/**
 * Threefish-256, -512 and -1024: Skein's block cipher, and the only *tweakable* cipher here.
 *
 * It is the primitive Skein is built from -- this repo already has Skein, whose UBI mode runs
 * Threefish over a chaining value with the tweak carrying the position and type. What was missing was
 * Threefish itself, as a cipher you can hand a block to. It is worth having on its own terms: a
 * 1024-bit block is the widest anything in this app offers, the key is the same size as the block, and
 * it is table-free -- add, rotate, XOR and nothing else.
 *
 * **The tweak is a third input, and it is not an IV.** Sixteen bytes, mixed into every fourth round's
 * subkey, and it is neither secret nor required to be unique. Its purpose is to make one key into a
 * family of independent permutations indexed by the tweak -- which is what disk encryption wants (the
 * sector number) and what Skein uses for domain separation. This implementation takes it as a
 * parameter and defaults it to zero, which is what the published vectors for the all-zero case use.
 *
 * Four things to preserve.
 *
 * **`bigint`, deliberately, for the same reason `xxhash3.ts` is.** The state is 64-bit words with
 * wrapping addition, and the only alternative is 32-bit limbs with carry propagation written by hand.
 * That would be perhaps five times faster and far more than five times easier to get wrong, on a
 * cipher whose whole risk profile is arithmetic.
 *
 * **The rotation and permutation tables differ per width and are not derivable from each other.** Each
 * of the three sizes has its own eight rows of rotation constants and its own word permutation; the
 * 1024-bit permutation is not the 512-bit one extended. They were checked against a reference rather
 * than recalled -- and then against the published vectors, which is what actually settles it.
 *
 * **The key schedule extends the key by one word.** `k[Nw] = C240 XOR (all key words)` where C240 is
 * 0x1BD11BDAA9FC1A22, and the tweak is extended the same way: `t[2] = t[0] XOR t[1]`. Subkey `s` takes
 * key words starting at `s`, wrapping modulo `Nw + 1` -- so the extra word is what makes the schedule
 * cycle through all of them instead of repeating the key every round.
 *
 * **A subkey is injected every fourth round, and the tweak lands in the top three words.** Words
 * `Nw - 3` and `Nw - 2` take tweak words, and word `Nw - 1` takes the subkey counter `s`. Putting the
 * counter anywhere else, or the tweak words the other way round, gives a cipher that inverts perfectly
 * and reproduces nothing -- which is why the vectors in `tests/algos-threefish.test.ts` include a case
 * with a *non-zero* tweak at every width. An all-zero tweak cannot tell those mistakes apart.
 */

import type { BlockCipher } from "./blockmodes";

const MASK = (1n << 64n) - 1n;
/** 2^64 / phi, and the constant that makes the extended key word depend on all the others. */
const C240 = 0x1bd11bdaa9fc1a22n;

const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const sub = (a: bigint, b: bigint): bigint => (a - b) & MASK;
const rotl = (x: bigint, n: number): bigint =>
  ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK;
const rotr = (x: bigint, n: number): bigint =>
  ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK;

/**
 * Rotation constants, eight rows of `Nw / 2`, indexed by round mod 8.
 *
 * Read off a reference implementation rather than recalled, then confirmed by the published vectors --
 * which is the only check that matters, since a wrong constant here gives a cipher that still inverts.
 */
const ROTATIONS: Record<number, readonly (readonly number[])[]> = {
  4: [
    [14, 16],
    [52, 57],
    [23, 40],
    [5, 37],
    [25, 33],
    [46, 12],
    [58, 22],
    [32, 32],
  ],
  8: [
    [46, 36, 19, 37],
    [33, 27, 14, 42],
    [17, 49, 36, 39],
    [44, 9, 54, 56],
    [39, 30, 34, 24],
    [13, 50, 10, 17],
    [25, 29, 39, 43],
    [8, 35, 56, 22],
  ],
  16: [
    [24, 13, 8, 47, 8, 17, 22, 37],
    [38, 19, 10, 55, 49, 18, 23, 52],
    [33, 4, 51, 13, 34, 41, 59, 17],
    [5, 20, 48, 41, 47, 28, 16, 25],
    [41, 9, 37, 31, 12, 47, 44, 30],
    [16, 34, 56, 51, 4, 53, 42, 41],
    [31, 44, 47, 46, 19, 42, 44, 25],
    [9, 48, 35, 52, 23, 31, 37, 20],
  ],
};

/**
 * The word permutation per width, as "word i of the output comes from word PERM[i] of the input".
 *
 * Not derivable from each other: the 1024-bit permutation is its own, and the 256-bit one is the
 * involution (0 3 2 1) while the other two are not involutions at all. Which is why the inverse is
 * computed below rather than assumed to be the same table.
 */
const PERMUTATIONS: Record<number, readonly number[]> = {
  4: [0, 3, 2, 1],
  8: [2, 1, 4, 7, 6, 5, 0, 3],
  16: [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1],
};

const ROUNDS: Record<number, number> = { 4: 72, 8: 72, 16: 80 };

function invert(permutation: readonly number[]): number[] {
  const inverse = new Array<number>(permutation.length);
  for (let i = 0; i < permutation.length; i++) inverse[permutation[i]!] = i;
  return inverse;
}

const loadLE = (src: Uint8Array, at: number): bigint => {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(src[at + i]!);
  return value;
};

function storeLE(value: bigint, dst: Uint8Array, at: number): void {
  let v = value;
  for (let i = 0; i < 8; i++) {
    dst[at + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

/** 32, 64 or 128 bytes -- the block and the key are always the same size. */
export type ThreefishSize = 32 | 64 | 128;

/**
 * Threefish at one of its three sizes.
 *
 * `tweak` is 16 bytes and defaults to zero. Passing a short one is refused rather than padded: a tweak
 * is an input to the permutation, so silently zero-extending a 12-byte one would encrypt under a
 * different tweak from the one asked for and say nothing.
 */
export function createThreefish(key: Uint8Array, tweak?: Uint8Array): BlockCipher {
  if (key.length !== 32 && key.length !== 64 && key.length !== 128) {
    throw new Error(`Threefish's key is 32, 64 or 128 bytes; this one is ${key.length}.`);
  }
  if (tweak && tweak.length !== 16) {
    throw new Error(`Threefish's tweak is exactly 16 bytes; this one is ${tweak.length}.`);
  }

  const nw = key.length / 8;
  const rounds = ROUNDS[nw]!;
  const rotations = ROTATIONS[nw]!;
  const permutation = PERMUTATIONS[nw]!;
  const inverse = invert(permutation);

  // The key, extended by one word so the subkey schedule cycles through Nw + 1 rather than repeating.
  const k = new Array<bigint>(nw + 1);
  let parity = C240;
  for (let i = 0; i < nw; i++) {
    k[i] = loadLE(key, i * 8);
    parity ^= k[i]!;
  }
  k[nw] = parity;

  // The tweak, extended the same way.
  const t0 = tweak ? loadLE(tweak, 0) : 0n;
  const t1 = tweak ? loadLE(tweak, 8) : 0n;
  const t = [t0, t1, t0 ^ t1];

  /** Subkey `s`: key words from `s`, with the tweak in the top two and the counter in the last. */
  const subkey = (s: number): bigint[] => {
    const out = new Array<bigint>(nw);
    for (let i = 0; i < nw; i++) out[i] = k[(s + i) % (nw + 1)]!;
    out[nw - 3] = add(out[nw - 3]!, t[s % 3]!);
    out[nw - 2] = add(out[nw - 2]!, t[(s + 1) % 3]!);
    out[nw - 1] = add(out[nw - 1]!, BigInt(s));
    return out;
  };

  const subkeys: bigint[][] = [];
  for (let s = 0; s <= rounds / 4; s++) subkeys.push(subkey(s));

  return {
    blockSize: key.length,
    encryptBlock(src, dst) {
      const v = new Array<bigint>(nw);
      for (let i = 0; i < nw; i++) v[i] = loadLE(src, i * 8);

      for (let round = 0; round < rounds; round++) {
        if (round % 4 === 0) {
          const s = subkeys[round / 4]!;
          for (let i = 0; i < nw; i++) v[i] = add(v[i]!, s[i]!);
        }
        // MIX on each pair, then permute.
        const row = rotations[round % 8]!;
        for (let j = 0; j < nw / 2; j++) {
          const x = add(v[2 * j]!, v[2 * j + 1]!);
          v[2 * j] = x;
          v[2 * j + 1] = rotl(v[2 * j + 1]!, row[j]!) ^ x;
        }
        const permuted = new Array<bigint>(nw);
        for (let i = 0; i < nw; i++) permuted[i] = v[permutation[i]!]!;
        for (let i = 0; i < nw; i++) v[i] = permuted[i]!;
      }

      const last = subkeys[rounds / 4]!;
      for (let i = 0; i < nw; i++) storeLE(add(v[i]!, last[i]!), dst, i * 8);
    },
    decryptBlock(src, dst) {
      const v = new Array<bigint>(nw);
      const last = subkeys[rounds / 4]!;
      for (let i = 0; i < nw; i++) v[i] = sub(loadLE(src, i * 8), last[i]!);

      for (let round = rounds - 1; round >= 0; round--) {
        const unpermuted = new Array<bigint>(nw);
        for (let i = 0; i < nw; i++) unpermuted[i] = v[inverse[i]!]!;
        for (let i = 0; i < nw; i++) v[i] = unpermuted[i]!;

        const row = rotations[round % 8]!;
        for (let j = 0; j < nw / 2; j++) {
          const y = rotr(v[2 * j + 1]! ^ v[2 * j]!, row[j]!);
          v[2 * j + 1] = y;
          v[2 * j] = sub(v[2 * j]!, y);
        }

        if (round % 4 === 0) {
          const s = subkeys[round / 4]!;
          for (let i = 0; i < nw; i++) v[i] = sub(v[i]!, s[i]!);
        }
      }

      for (let i = 0; i < nw; i++) storeLE(v[i]!, dst, i * 8);
    },
  };
}
