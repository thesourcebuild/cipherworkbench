/**
 * HAS-160 -- the Korean TTA standard TTAS.KO-12.0011, and what KCDSA signs with.
 *
 * SHA-1's shape with two changes: a *wider* message expansion -- twenty extra words derived from the
 * sixteen, four per round, rather than SHA-1's rolling XOR -- and a per-round rotation of the B register
 * (10, 17, 25, 30) instead of SHA-1's fixed 30. There is no table.
 *
 * Verified against seven vectors from RHash's own test suite, which cites randombit.net's published set
 * and Jacksum as an independent check, including the million-'a' case. All passed first run.
 *
 * ## The recall that was wrong, and why it matters
 *
 * The digest of `"a"` is `4872bcbc4cd0f0a9dc7c2f7045e5b43b6c830db8`. A remembered value ending `6e830dbf`
 * was within two bytes of it and would have looked right in a review -- which is the same trap the IDEA
 * note in `## Fetching a specification` records. Every vector here was fetched.
 *
 * ## Three things to keep
 *
 * **The rotation table is shared by all four rounds** -- 5, 11, 7, 15, 6, ... per step -- while the round
 * function and the B rotation change. It reads as if it should be per round and it is not.
 *
 * **The extra message words are four different XOR patterns**, one per round, and the round's data words
 * are read at a stride: 1, 3, 7 and 5 respectively. Both tables are transcribed from the reference rather
 * than derived, because the stride pattern breaks at round four and a formula that fit three rounds would
 * be a formula that is wrong once.
 *
 * **The extra words come first in each group of five.** Each round reads `extra, d, d, d, d` four times
 * over, so word 18 is the very first thing the compression touches -- not word 0.
 */

import { eagerAbsorber, type LwcHasher } from "./lwc-hash";

/** The message-word index each step reads, per round. Indices 16..31 are the derived words. */
const IDX: readonly (readonly number[])[] = [
  [18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8, 9, 10, 11, 17, 12, 13, 14, 15],
  [22, 3, 6, 9, 12, 23, 15, 2, 5, 8, 20, 11, 14, 1, 4, 21, 7, 10, 13, 0],
  [26, 12, 5, 14, 7, 27, 0, 9, 2, 11, 24, 4, 13, 6, 15, 25, 8, 1, 10, 3],
  [30, 7, 2, 13, 8, 31, 3, 14, 9, 4, 28, 15, 10, 5, 0, 29, 11, 6, 1, 12],
];
/** One table for all four rounds -- see the header. */
const ROT = [5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13] as const;
/** B's rotation, which *is* per round. */
const B_ROT = [10, 17, 25, 30] as const;
const K = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc] as const;
/** Which four data words each derived word XORs together. Four groups per round. */
const EXTRA: readonly (readonly (readonly number[])[])[] = [
  [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]],
  [[3, 6, 9, 12], [2, 5, 8, 15], [1, 4, 11, 14], [0, 7, 10, 13]],
  [[5, 7, 12, 14], [0, 2, 9, 11], [4, 6, 13, 15], [1, 3, 8, 10]],
  [[2, 7, 8, 13], [3, 4, 9, 14], [0, 5, 10, 15], [1, 6, 11, 12]],
];

const rotl = (x: number, n: number): number => (n === 0 ? x >>> 0 : ((x << n) | (x >>> (32 - n))) >>> 0);

export function createHas160(): LwcHasher {
  const h = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
  const x = new Uint32Array(32);
  let total = 0n;

  const processBlock = (buf: Uint8Array, off: number): void => {
    for (let j = 0; j < 16; j++) {
      x[j] =
        (buf[off + 4 * j]! |
          (buf[off + 4 * j + 1]! << 8) |
          (buf[off + 4 * j + 2]! << 16) |
          (buf[off + 4 * j + 3]! << 24)) >>> 0;
    }
    for (let r = 0; r < 4; r++) {
      for (let g = 0; g < 4; g++) {
        const [a, b, c, d] = EXTRA[r]![g]! as [number, number, number, number];
        x[16 + 4 * r + g] = (x[a]! ^ x[b]! ^ x[c]! ^ x[d]!) >>> 0;
      }
    }
    let a = h[0]!;
    let b = h[1]!;
    let c = h[2]!;
    let d = h[3]!;
    let e = h[4]!;
    for (let r = 0; r < 4; r++) {
      for (let s = 0; s < 20; s++) {
        const f =
          r === 0
            ? (d ^ (b & (c ^ d))) >>> 0
            : r === 2
              ? (c ^ (b | ~d)) >>> 0
              : (b ^ c ^ d) >>> 0;
        const t = (e + rotl(a, ROT[s]!) + f + x[IDX[r]![s]!]! + K[r]!) >>> 0;
        const nextC = rotl(b, B_ROT[r]!);
        e = d;
        d = c;
        c = nextC;
        b = a;
        a = t;
      }
    }
    h[0] = (h[0]! + a) >>> 0;
    h[1] = (h[1]! + b) >>> 0;
    h[2] = (h[2]! + c) >>> 0;
    h[3] = (h[3]! + d) >>> 0;
    h[4] = (h[4]! + e) >>> 0;
  };

  return eagerAbsorber(
    64,
    (block, off) => {
      processBlock(block, off);
      total += 64n;
    },
    (tail, tailLen) => {
      total += BigInt(tailLen);
      const padded = new Uint8Array(tailLen < 56 ? 64 : 128);
      padded.set(tail.subarray(0, tailLen));
      padded[tailLen] = 0x80;
      const bits = total * 8n;
      for (let i = 0; i < 8; i++) {
        padded[padded.length - 8 + i] = Number((bits >> BigInt(8 * i)) & 0xffn);
      }
      for (let i = 0; i < padded.length; i += 64) processBlock(padded, i);

      const out = new Uint8Array(20);
      for (let i = 0; i < 5; i++) {
        out[4 * i] = h[i]! & 0xff;
        out[4 * i + 1] = (h[i]! >>> 8) & 0xff;
        out[4 * i + 2] = (h[i]! >>> 16) & 0xff;
        out[4 * i + 3] = (h[i]! >>> 24) & 0xff;
      }
      return out;
    },
  );
}

export function has160(message: Uint8Array): Uint8Array {
  const h = createHas160();
  h.update(message);
  return h.digest();
}
