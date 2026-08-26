/**
 * SKIPJACK: the NSA's Clipper cipher, declassified in 1998.
 *
 * 64-bit block, 80-bit key, 32 rounds, and one 256-byte table. Historically it is the interesting one
 * in this repo -- it was designed in 1987, classified, deployed in the Clipper and Capstone chips at
 * the centre of the crypto wars, and published only when the policy it existed for had failed. It is
 * also a genuinely unusual design: no key schedule at all, and two alternating round structures.
 *
 * Three things to keep.
 *
 * **There is no key schedule.** The ten key bytes are used directly, cycled: round `k` takes bytes
 * `4k`, `4k+1`, `4k+2`, `4k+3` modulo 10. Since 4 and 10 share a factor, the pattern repeats every
 * five rounds, so the 32 rounds see the key in a short cycle -- which is unusual and is the design.
 * There is nothing to precompute and nothing to get wrong except the indexing.
 *
 * **Two rules, four groups of eight.** Rule A for eight rounds, Rule B for eight, then A and B again.
 * They are not inverses of each other -- both are used in the forward direction -- and they differ in
 * *where* the round counter is XORed: Rule A folds `k + 1` into w1 along with the G output, Rule B
 * folds it into w3 from the pre-G w1. Getting them the same way round gives a cipher that inverts
 * against itself and reproduces nothing.
 *
 * **G is a four-round Feistel on the two halves of a 16-bit word**, keyed by four key bytes and using
 * the F table each time. Its inverse H runs the same four steps with the key bytes in the opposite
 * order and the halves swapped, which is why decryption needs its own function rather than reusing G.
 *
 * The single published vector -- key `00998877665544332211`, plaintext `33221100ddccbbaa`, ciphertext
 * `2587cae27a12d300` -- is the one from the specification, and it is what
 * `tests/algos-skipjack.test.ts` pins in both directions. One vector is thin, so the test also asserts
 * the F table is a permutation of all 256 bytes: a table that is not is the failure a single vector
 * would still catch, but the property says *why* it failed.
 *
 * Security: broken for 31 of its 32 rounds by impossible-differential cryptanalysis, and the full
 * cipher has no practical attack. An 80-bit key is the real problem -- that is within reach of a
 * dedicated machine, and has been for two decades.
 */

import type { BlockCipher } from "./blockmodes";

/**
 * The F table, parsed out of a reference implementation rather than typed.
 *
 * 256 bytes with no structure anybody has published -- it is not derived from a field inverse the way
 * AES's is, and the design rationale for it was never declassified. So there is nothing to derive it
 * from, which makes it the one table in this file and the reason the test checks it is a permutation.
 */
const F_TABLE = new Uint8Array([
  0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
  0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
  0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
  0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
  0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
  0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
  0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
  0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
  0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
  0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
  0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
  0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
  0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
  0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
  0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
  0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46,
]);

const BLOCK = 8;
const ROUNDS = 32;

/** SKIPJACK as a `BlockCipher`. The key is exactly ten bytes. */
export function createSkipjack(key: Uint8Array): BlockCipher {
  if (key.length !== 10) {
    throw new Error(`SKIPJACK's key is exactly 10 bytes; this one is ${key.length}.`);
  }

  /**
   * The four key bytes each round uses, precomputed.
   *
   * Not a key schedule -- there is none -- just the modulo arithmetic done once instead of 128 times.
   * Written as four arrays rather than one 2-D one because that is how G and H index them, and the
   * only difference between the two functions is the order these are read in.
   */
  const k0 = new Uint8Array(ROUNDS);
  const k1 = new Uint8Array(ROUNDS);
  const k2 = new Uint8Array(ROUNDS);
  const k3 = new Uint8Array(ROUNDS);
  for (let i = 0; i < ROUNDS; i++) {
    k0[i] = key[(i * 4) % 10]!;
    k1[i] = key[(i * 4 + 1) % 10]!;
    k2[i] = key[(i * 4 + 2) % 10]!;
    k3[i] = key[(i * 4 + 3) % 10]!;
  }

  /** The G permutation: four Feistel steps over the two bytes of `w`, keyed by round `k`. */
  const g = (k: number, w: number): number => {
    const g1 = (w >> 8) & 0xff;
    const g2 = w & 0xff;
    const g3 = F_TABLE[g2 ^ k0[k]!]! ^ g1;
    const g4 = F_TABLE[g3 ^ k1[k]!]! ^ g2;
    const g5 = F_TABLE[g4 ^ k2[k]!]! ^ g3;
    const g6 = F_TABLE[g5 ^ k3[k]!]! ^ g4;
    return ((g5 << 8) | g6) & 0xffff;
  };

  /** G's inverse: the same four steps, key bytes reversed, halves swapped on the way out. */
  const h = (k: number, w: number): number => {
    const h1 = w & 0xff;
    const h2 = (w >> 8) & 0xff;
    const h3 = F_TABLE[h2 ^ k3[k]!]! ^ h1;
    const h4 = F_TABLE[h3 ^ k2[k]!]! ^ h2;
    const h5 = F_TABLE[h4 ^ k1[k]!]! ^ h3;
    const h6 = F_TABLE[h5 ^ k0[k]!]! ^ h4;
    return ((h6 << 8) | h5) & 0xffff;
  };

  const word = (src: Uint8Array, at: number): number => ((src[at]! << 8) | src[at + 1]!) & 0xffff;
  const put = (value: number, dst: Uint8Array, at: number): void => {
    dst[at] = (value >>> 8) & 0xff;
    dst[at + 1] = value & 0xff;
  };

  return {
    blockSize: BLOCK,
    encryptBlock(src, dst) {
      let w1 = word(src, 0);
      let w2 = word(src, 2);
      let w3 = word(src, 4);
      let w4 = word(src, 6);
      let k = 0;

      for (let pass = 0; pass < 2; pass++) {
        // Rule A: the counter goes into w1, alongside the G output.
        for (let i = 0; i < 8; i++) {
          const tmp = w4;
          w4 = w3;
          w3 = w2;
          w2 = g(k, w1);
          w1 = (w2 ^ tmp ^ (k + 1)) & 0xffff;
          k++;
        }
        // Rule B: the counter goes into w3, from w1 *before* G runs on it.
        for (let i = 0; i < 8; i++) {
          const tmp = w4;
          w4 = w3;
          w3 = (w1 ^ w2 ^ (k + 1)) & 0xffff;
          w2 = g(k, w1);
          w1 = tmp;
          k++;
        }
      }

      put(w1, dst, 0);
      put(w2, dst, 2);
      put(w3, dst, 4);
      put(w4, dst, 6);
    },
    decryptBlock(src, dst) {
      // The register mapping is not the identity on the way in: decryption reads w2, w1, w4, w3.
      let w2 = word(src, 0);
      let w1 = word(src, 2);
      let w4 = word(src, 4);
      let w3 = word(src, 6);
      let k = ROUNDS - 1;

      for (let pass = 0; pass < 2; pass++) {
        for (let i = 0; i < 8; i++) {
          const tmp = w4;
          w4 = w3;
          w3 = w2;
          w2 = h(k, w1);
          w1 = (w2 ^ tmp ^ (k + 1)) & 0xffff;
          k--;
        }
        for (let i = 0; i < 8; i++) {
          const tmp = w4;
          w4 = w3;
          w3 = (w1 ^ w2 ^ (k + 1)) & 0xffff;
          w2 = h(k, w1);
          w1 = tmp;
          k--;
        }
      }

      put(w2, dst, 0);
      put(w1, dst, 2);
      put(w4, dst, 4);
      put(w3, dst, 6);
    },
  };
}

/** Exported so the test can assert the table is a permutation, which is all its structure amounts to. */
export const SKIPJACK_F_TABLE: Readonly<Uint8Array> = F_TABLE;
