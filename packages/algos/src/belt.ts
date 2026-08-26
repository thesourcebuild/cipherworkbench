/**
 * BelT -- the Belarusian national standard STB 34.101.31, block cipher and hash.
 *
 * One primitive underneath both. `belt-block` is a 128-bit block cipher with a 256-bit key and
 * eight rounds of an unusually wide round function -- seven substitution-box lookups per round, mixed
 * with addition, subtraction and XOR over four 32-bit words. `belt-hash` is a 256-bit hash built on
 * it by a Miyaguchi-Preneel-like compression that calls the cipher *three times per block*, keying it
 * with the message once and with the chaining value twice.
 *
 * Four things worth knowing.
 *
 * **The S-box is derived, not transcribed.** The standard's H-block is 256 bytes, and the reference
 * gives its generator in a comment: seed positions 10 and 11 with 0x00 and 0x8E, then each subsequent
 * entry is 116 steps of an 8-bit LFSR whose feedback is the parity of `t & 0x63`. That fills
 * positions 10..255 and then wraps to fill 0..9, which is why the loop runs to 265 rather than 256.
 * Same reasoning as ARIA's inverse S-boxes and Blowfish's tables from pi: 256 bytes is enough to
 * mistype, and a wrong entry gives a cipher that is perfectly self-consistent and matches nothing.
 * `tests/algos-belt.test.ts` checks the derivation against the standard's own published first row.
 *
 * **G is one rotation of one substitution.** The reference ships four 1 KB tables, `H5`/`H13`/`H21`/
 * `H29`, and the three G functions each read all four in a different order. All of that is the single
 * identity `G_r(x) = rotl(S(x), r)` where `S` applies H bytewise -- so the four tables are built here
 * from H at load and the ordering falls out rather than being restated.
 *
 * **The round-key schedule is the key words in a rotating order, and encryption and decryption
 * disagree about the direction.** `K[(7 * (i - 1) + j) % 8]` forward against `K[(7 * i - 1 - j) % 8]`
 * back. There is no schedule to compute -- the 256-bit key *is* the eight subkeys, used 56 times.
 *
 * **The register permutation between rounds is where this goes wrong.** Each round reads its four
 * words in a rotated order and the whole thing ends with a three-swap shuffle -- `abcd -> bdac`
 * forward, `abcd -> cadb` back. Both are written as index tables here rather than as swaps, because
 * the reference achieves them by permuting *macro arguments*, which does not survive translation
 * into a loop.
 *
 * The check is STB 34.101.31 Annex A: tests A.1 and A.4 for the cipher in both directions, and
 * A.23-1/2/3 for the hash at 13, 32 and 48 bytes -- a partial block, an exact block, and a block plus
 * a partial one, which between them cover every branch of the padding. There is no oracle: OpenSSL
 * has no BelT and no dependency here does either. Sources: the standard's test annex as carried by
 * the bee2 reference library.
 */

import type { BlockCipher } from "./blockmodes";

const u32 = (x: number): number => x >>> 0;
const rotl = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));

/**
 * The 256-byte H-block, derived from the standard's generator.
 *
 * Exported because it is also the hash's initial value -- STB specifies `h` as the first 32 bytes of
 * this very table -- and because the test checks the derivation against the published first row.
 */
export const BELT_H: Uint8Array = (() => {
  const parity = (v: number): number => {
    let t = v;
    t ^= t >>> 4;
    t ^= t >>> 2;
    t ^= t >>> 1;
    return t & 1;
  };
  const h = new Uint8Array(256);
  h[10] = 0x00;
  h[11] = 0x8e;
  for (let x = 12; x < 10 + 256; x++) {
    let t = h[(x - 1) % 256]!;
    for (let i = 0; i < 116; i++) t = ((t >>> 1) | (parity(t & 0x63) << 7)) & 0xff;
    h[x % 256] = t;
  }
  return h;
})();

/** `H << r` per byte, for r in 5, 13, 21, 29 -- the reference's four expanded tables. */
const H_ROT: readonly Uint32Array[] = [5, 13, 21, 29].map((r) => {
  const table = new Uint32Array(256);
  for (let b = 0; b < 256; b++) table[b] = rotl(BELT_H[b]!, r);
  return table;
});

/**
 * `G_r(x) = rotl(S(x), r)`, spelled as the reference's four-table lookup.
 *
 * `shift` selects which rotation this call wants: 0 for G5, 1 for G13, 2 for G21. The tables are then
 * read in ascending order from there, wrapping -- which is exactly what makes the three functions
 * three rotations of one substitution rather than three tables.
 */
function g(x: number, shift: number): number {
  return u32(
    H_ROT[shift]![x & 0xff]! ^
      H_ROT[(shift + 1) & 3]![(x >>> 8) & 0xff]! ^
      H_ROT[(shift + 2) & 3]![(x >>> 16) & 0xff]! ^
      H_ROT[(shift + 3) & 3]![x >>> 24]!,
  );
}

const G5 = 0;
const G13 = 1;
const G21 = 2;

/**
 * Which of the four words plays each of `a`, `b`, `c`, `d` in round `i`.
 *
 * The reference rotates the macro's arguments instead. Encryption walks rounds 1..8 through the first
 * table; decryption walks 8..1 through the second, and the two are *not* reverses of each other.
 */
const ORDER_ENCRYPT: readonly (readonly number[])[] = [
  [0, 1, 2, 3],
  [1, 3, 0, 2],
  [3, 2, 1, 0],
  [2, 0, 3, 1],
  [0, 1, 2, 3],
  [1, 3, 0, 2],
  [3, 2, 1, 0],
  [2, 0, 3, 1],
];

const ORDER_DECRYPT: readonly (readonly number[])[] = [
  [0, 1, 2, 3],
  [2, 0, 3, 1],
  [3, 2, 1, 0],
  [1, 3, 0, 2],
  [0, 1, 2, 3],
  [2, 0, 3, 1],
  [3, 2, 1, 0],
  [1, 3, 0, 2],
];

/**
 * One round, in place on `x`.
 *
 * `round` is the 1-based round number, and it appears twice: in the subkey index and XORed into the
 * fifth step. Passing a 0-based index would leave the cipher self-consistent and wrong.
 */
function round(
  x: Uint32Array,
  slots: readonly number[],
  key: Uint32Array,
  roundNumber: number,
  forward: boolean,
): void {
  const [a, b, c, d] = slots as [number, number, number, number];
  const k = (j: number): number =>
    key[
      forward ? (7 * (roundNumber - 1) + j) % 8 : (7 * roundNumber - 1 - j) % 8
    ]!;

  x[b] = u32(x[b]! ^ g(u32(x[a]! + k(0)), G5));
  x[c] = u32(x[c]! ^ g(u32(x[d]! + k(1)), G21));
  x[a] = u32(x[a]! - g(u32(x[b]! + k(2)), G13));
  x[c] = u32(x[c]! + x[b]!);
  x[b] = u32(x[b]! + (g(u32(x[c]! + k(3)), G21) ^ roundNumber));
  x[c] = u32(x[c]! - x[b]!);
  x[d] = u32(x[d]! + g(u32(x[c]! + k(4)), G13));
  x[b] = u32(x[b]! ^ g(u32(x[a]! + k(5)), G21));
  x[c] = u32(x[c]! ^ g(u32(x[d]! + k(6)), G5));
}

/** `abcd -> bdac` after encryption, `abcd -> cadb` after decryption. */
function shuffle(x: Uint32Array, forward: boolean): void {
  const [a, b, c, d] = [x[0]!, x[1]!, x[2]!, x[3]!];
  if (forward) {
    x[0] = b;
    x[1] = d;
    x[2] = a;
    x[3] = c;
  } else {
    x[0] = c;
    x[1] = a;
    x[2] = d;
    x[3] = b;
  }
}

/**
 * belt-block on four words in place. `key` is the 256-bit key as eight little-endian words.
 *
 * Exported because the hash keys the cipher directly with message and chaining words rather than
 * going through a key schedule -- there is no schedule to go through.
 */
export function beltBlockWords(x: Uint32Array, key: Uint32Array, forward: boolean): void {
  const orders = forward ? ORDER_ENCRYPT : ORDER_DECRYPT;
  for (let step = 0; step < 8; step++) {
    round(x, orders[step]!, key, forward ? step + 1 : 8 - step, forward);
  }
  shuffle(x, forward);
}

function wordsFromLe(bytes: Uint8Array, at: number, count: number): Uint32Array {
  const words = new Uint32Array(count);
  for (let i = 0; i < count; i++) {
    const o = at + 4 * i;
    words[i] = u32(
      bytes[o]! | (bytes[o + 1]! << 8) | (bytes[o + 2]! << 16) | (bytes[o + 3]! << 24),
    );
  }
  return words;
}

function wordsToLe(words: Uint32Array, count: number): Uint8Array {
  const out = new Uint8Array(4 * count);
  for (let i = 0; i < count; i++) {
    out[4 * i] = words[i]! & 0xff;
    out[4 * i + 1] = (words[i]! >>> 8) & 0xff;
    out[4 * i + 2] = (words[i]! >>> 16) & 0xff;
    out[4 * i + 3] = (words[i]! >>> 24) & 0xff;
  }
  return out;
}

/**
 * STB's key expansion: a 16- or 24-byte key is widened to 256 bits before use.
 *
 * A 128-bit key is simply repeated; a 192-bit key gains two words that are XORs of the first six.
 * That is the standard's rule, not a convenience -- the cipher itself takes 256 bits and nothing else.
 */
export function beltKeyExpand(key: Uint8Array): Uint32Array {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(`BelT's key is 16, 24 or 32 bytes; this one is ${key.length}.`);
  }
  const k = new Uint32Array(8);
  k.set(wordsFromLe(key, 0, key.length / 4));
  if (key.length === 16) {
    k[4] = k[0]!;
    k[5] = k[1]!;
    k[6] = k[2]!;
    k[7] = k[3]!;
  } else if (key.length === 24) {
    k[6] = u32(k[0]! ^ k[1]! ^ k[2]!);
    k[7] = u32(k[3]! ^ k[4]! ^ k[5]!);
  }
  return k;
}

/** belt-block as a `BlockCipher`, so it reaches the shared mode layer unchanged. */
export function createBelt(key: Uint8Array): BlockCipher {
  const k = beltKeyExpand(key);
  const run = (src: Uint8Array, dst: Uint8Array, forward: boolean): void => {
    const x = wordsFromLe(src, 0, 4);
    beltBlockWords(x, k, forward);
    dst.set(wordsToLe(x, 4));
  };
  return {
    blockSize: 16,
    encryptBlock: (src, dst) => run(src, dst, true),
    decryptBlock: (src, dst) => run(src, dst, false),
  };
}

const HASH_BLOCK = 32;

/**
 * belt-compress. `h` is eight words and is updated in place; `x` is the 256-bit input block.
 *
 * Three cipher calls, and the middle two take keys assembled from *both* halves of the incoming `h`,
 * which is why `h0` has to be saved before it is overwritten:
 *
 *     Y  = E(h0 ^ h1, key = X) ^ (h0 ^ h1)
 *     h0 = E(X0, key = Y || h1) ^ X0
 *     h1 = E(X1, key = ~Y || h0_old) ^ X1
 *
 * The returned `Y` is what the streaming variant accumulates into `s`; the final compression
 * discards it.
 */
function compress(h: Uint32Array, x: Uint32Array): Uint32Array {
  const h0 = h.subarray(0, 4);
  const h1 = h.subarray(4, 8);
  const savedH0 = Uint32Array.from(h0);
  const savedH1 = Uint32Array.from(h1);

  const y = new Uint32Array(4);
  for (let i = 0; i < 4; i++) y[i] = u32(h0[i]! ^ h1[i]!);
  const enc = Uint32Array.from(y);
  beltBlockWords(enc, x, true);
  for (let i = 0; i < 4; i++) y[i] = u32(enc[i]! ^ y[i]!);

  const key1 = new Uint32Array(8);
  key1.set(y, 0);
  key1.set(savedH1, 4);
  const low = x.slice(0, 4);
  beltBlockWords(low, key1, true);
  for (let i = 0; i < 4; i++) h[i] = u32(low[i]! ^ x[i]!);

  const key2 = new Uint32Array(8);
  for (let i = 0; i < 4; i++) key2[i] = u32(~y[i]!);
  key2.set(savedH0, 4);
  const high = x.slice(4, 8);
  beltBlockWords(high, key2, true);
  for (let i = 0; i < 4; i++) h[4 + i] = u32(high[i]! ^ x[4 + i]!);

  return y;
}

/**
 * belt-hash: a 256-bit digest.
 *
 * `digest()` is deliberately non-destructive -- it works on copies of `h` and `s` -- because STB's own
 * test A.23-3 takes a digest partway through a message and then keeps feeding it. An implementation
 * that finalised in place would pass the first two vectors and fail the third.
 */
class BeltHash {
  private readonly h = wordsFromLe(BELT_H, 0, 8);
  private readonly s = new Uint32Array(4);
  private readonly buffer = new Uint8Array(HASH_BLOCK);
  private filled = 0;
  private total = 0;

  update(chunk: Uint8Array): void {
    this.total += chunk.length;
    let at = 0;
    while (at < chunk.length) {
      const take = Math.min(HASH_BLOCK - this.filled, chunk.length - at);
      this.buffer.set(chunk.subarray(at, at + take), this.filled);
      this.filled += take;
      at += take;
      if (this.filled === HASH_BLOCK) {
        const x = wordsFromLe(this.buffer, 0, 8);
        const y = compress(this.h, x);
        for (let i = 0; i < 4; i++) this.s[i] = u32(this.s[i]! ^ y[i]!);
        this.filled = 0;
      }
    }
  }

  digest(): Uint8Array {
    const h = Uint32Array.from(this.h);
    const s = Uint32Array.from(this.s);

    if (this.filled > 0) {
      // A short final block is zero-filled. There is no padding byte at all: the bit length in the
      // last compression is what distinguishes a message from the same message plus zeros -- the
      // same arrangement Snefru and GOST R 34.11-94 have.
      const padded = new Uint8Array(HASH_BLOCK);
      padded.set(this.buffer.subarray(0, this.filled));
      const y = compress(h, wordsFromLe(padded, 0, 8));
      for (let i = 0; i < 4; i++) s[i] = u32(s[i]! ^ y[i]!);
    }

    // The last block is `len || s`, with the length in bits as a 128-bit little-endian integer.
    // BigInt only here: a browser cannot reach 2^53 bytes, but the field is 128 bits wide and
    // spelling it exactly costs nothing at finalisation.
    const bits = BigInt(this.total) * 8n;
    const last = new Uint32Array(8);
    for (let i = 0; i < 4; i++) last[i] = Number((bits >> BigInt(32 * i)) & 0xffffffffn) >>> 0;
    last.set(s, 4);
    compress(h, last);

    return wordsToLe(h, 8);
  }
}

export function beltHash(message: Uint8Array): Uint8Array {
  const state = new BeltHash();
  state.update(message);
  return state.digest();
}

/** An incremental belt-hash. Real streaming, and safe to digest more than once. */
export function createBeltHash(): {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
} {
  const state = new BeltHash();
  return { update: (chunk) => state.update(chunk), digest: () => state.digest() };
}
