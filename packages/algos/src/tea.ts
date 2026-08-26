/**
 * TEA and XTEA: two ciphers, 64-bit block, 128-bit key, and no tables at all.
 *
 * Wheeler and Needham's Tiny Encryption Algorithm is famous for being about ten lines, and XTEA is
 * their own repair of it -- same block, same key, same 32 rounds, a different key schedule and a
 * different round function. Both are here because both are deployed: TEA in the original Xbox's boot
 * ROM and in a great deal of embedded firmware, XTEA anywhere someone wanted TEA and read the
 * literature first.
 *
 * **The interesting thing about a cipher with no tables is that there is nothing to mistype**, which
 * moves the whole risk to the arithmetic and the byte order. That is not a smaller risk. TEA and XTEA
 * differ by *one line* in the round function -- TEA's is
 * `((v1 << 4) + a) ^ (v1 + sum) ^ ((v1 >>> 5) + b)` and XTEA's is
 * `(((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + key[...])` -- so an implementation of either is a
 * plausible implementation of the other, and each round-trips against itself perfectly. Only a
 * published vector separates them, which is why `tests/algos-tea.test.ts` carries four of each.
 *
 * Both read their key and their block as **big-endian** words. That is a convention rather than a
 * consequence: the papers write the words without saying, and implementations went both ways. These
 * follow Bouncy Castle, whose vectors are the ones people compare against.
 *
 * Security, since these are offered as tools: TEA has a related-key attack that recovers the key with
 * about 2^23 chosen plaintexts, and its effective key size is 126 bits rather than 128 because every
 * key has three equivalents. XTEA fixes the schedule and is not broken outright, but it is a 64-bit
 * block cipher, so a birthday collision arrives after about 32 GB under one key. Neither is a choice
 * for new work; both are what the firmware in front of you used.
 */

import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
const ROUNDS = 32;
const DELTA = 0x9e3779b9;

const u32 = (x: number): number => x >>> 0;

const load = (src: Uint8Array, at: number): number =>
  u32((src[at]! << 24) | (src[at + 1]! << 16) | (src[at + 2]! << 8) | src[at + 3]!);

function store(value: number, dst: Uint8Array, at: number): void {
  dst[at] = (value >>> 24) & 0xff;
  dst[at + 1] = (value >>> 16) & 0xff;
  dst[at + 2] = (value >>> 8) & 0xff;
  dst[at + 3] = value & 0xff;
}

function requireKey(key: Uint8Array, name: string): void {
  if (key.length !== 16) {
    throw new Error(`${name}'s key is exactly 16 bytes; this one is ${key.length}.`);
  }
}

/** TEA, from Wheeler and Needham's 1994 note. */
export function createTea(key: Uint8Array): BlockCipher {
  requireKey(key, "TEA");
  const a = load(key, 0);
  const b = load(key, 4);
  const c = load(key, 8);
  const d = load(key, 12);

  return {
    blockSize: BLOCK,
    encryptBlock(src, dst) {
      let v0 = load(src, 0);
      let v1 = load(src, 4);
      let sum = 0;
      for (let i = 0; i < ROUNDS; i++) {
        sum = u32(sum + DELTA);
        v0 = u32(v0 + (u32(u32(v1 << 4) + a) ^ u32(v1 + sum) ^ u32((v1 >>> 5) + b)));
        v1 = u32(v1 + (u32(u32(v0 << 4) + c) ^ u32(v0 + sum) ^ u32((v0 >>> 5) + d)));
      }
      store(v0, dst, 0);
      store(v1, dst, 4);
    },
    decryptBlock(src, dst) {
      let v0 = load(src, 0);
      let v1 = load(src, 4);
      // 32 * delta, which is where the sum ends up. Written as the product rather than as the
      // constant 0xC6EF3720 that implementations usually hardcode, so it follows from ROUNDS.
      let sum = u32(DELTA * ROUNDS);
      for (let i = 0; i < ROUNDS; i++) {
        v1 = u32(v1 - (u32(u32(v0 << 4) + c) ^ u32(v0 + sum) ^ u32((v0 >>> 5) + d)));
        v0 = u32(v0 - (u32(u32(v1 << 4) + a) ^ u32(v1 + sum) ^ u32((v1 >>> 5) + b)));
        sum = u32(sum - DELTA);
      }
      store(v0, dst, 0);
      store(v1, dst, 4);
    },
  };
}

/**
 * XTEA, the same authors' correction.
 *
 * The schedule is precomputed into two arrays of 32 because that is the only part that differs
 * between the two halves of each round: `sum + key[sum & 3]` before the delta is added, and
 * `sum + key[(sum >>> 11) & 3]` after. Selecting a key word by bits of the running sum is the whole
 * repair -- TEA uses the same four words in the same order in every round, which is what the
 * related-key attack exploits.
 */
export function createXtea(key: Uint8Array): BlockCipher {
  requireKey(key, "XTEA");
  const k = [load(key, 0), load(key, 4), load(key, 8), load(key, 12)];

  const sum0 = new Array<number>(ROUNDS);
  const sum1 = new Array<number>(ROUNDS);
  let sum = 0;
  for (let i = 0; i < ROUNDS; i++) {
    sum0[i] = u32(sum + k[sum & 3]!);
    sum = u32(sum + DELTA);
    sum1[i] = u32(sum + k[(sum >>> 11) & 3]!);
  }

  const mix = (v: number): number => u32(u32(u32(v << 4) ^ (v >>> 5)) + v);

  return {
    blockSize: BLOCK,
    encryptBlock(src, dst) {
      let v0 = load(src, 0);
      let v1 = load(src, 4);
      for (let i = 0; i < ROUNDS; i++) {
        v0 = u32(v0 + (mix(v1) ^ sum0[i]!));
        v1 = u32(v1 + (mix(v0) ^ sum1[i]!));
      }
      store(v0, dst, 0);
      store(v1, dst, 4);
    },
    decryptBlock(src, dst) {
      let v0 = load(src, 0);
      let v1 = load(src, 4);
      for (let i = ROUNDS - 1; i >= 0; i--) {
        v1 = u32(v1 - (mix(v0) ^ sum1[i]!));
        v0 = u32(v0 - (mix(v1) ^ sum0[i]!));
      }
      store(v0, dst, 0);
      store(v1, dst, 4);
    },
  };
}

/**
 * XXTEA -- "Corrected Block TEA", Needham and Wheeler's 1998 follow-up to XTEA.
 *
 * `legacy`. No published break of the full cipher; unstandardised.
 *
 * **It has no published test vector, and that is why it was left out of this repo for several rounds.**
 * There is no standard: XXTEA appears only in Needham and Wheeler's two-page note, which prints the
 * reference C and no values. Crypto++ carries TEA and XTEA and not this. The `xxtea.io` family of
 * libraries looks like a source and is not -- its own README says it "is different from the original
 * XXTEA encryption algorithm", because it wraps the primitive in a length header and a string codec, so
 * its outputs are not XXTEA outputs. So this rests on a transcription of the reference `btea` and
 * nothing else. It is offered on the user's explicit instruction; do not describe it as verified.
 *
 * What partly covers it: XXTEA's `MX` expression is checked against TEA's and XTEA's *shape* by
 * sharing this file's word loading and delta, and `tests/algos-legacy-ciphers.test.ts` pins that all
 * three of TEA, XTEA and XXTEA disagree -- which is the failure this trio is most exposed to, since any
 * one of the three is a plausible implementation of the others.
 *
 * **XXTEA is really a variable-length cipher, and this is the 64-bit instantiation of it.** `btea`
 * takes `n` 32-bit words and runs `6 + 52/n` rounds over all of them, so the "block" is however much
 * data you hand it. At `n = 2` that is 32 rounds over eight bytes -- the same block, key and round count
 * as TEA and XTEA -- which is the only form that fits this repo's mode layer and the only form in which
 * comparing it against its two predecessors means anything. Larger `n` is a different function per
 * length and would need a mode of its own; `xxteaWords` exposes it for anyone who needs that.
 */
const XXTEA_DELTA = 0x9e3779b9;

/** The reference's `MX` macro, with the key word selected by `(p & 3) ^ e`. */
const xxteaMix = (y: number, z: number, sum: number, e: number, p: number, k: readonly number[]): number =>
  u32(
    u32(u32(u32(z >>> 5) ^ u32(y << 2)) + u32(u32(y >>> 3) ^ u32(z << 4))) ^
      u32(u32(sum ^ y) + u32(k[(p & 3) ^ e]! ^ z)),
  );

/**
 * `btea` over an arbitrary word array, in place. Encrypts when `encrypt`, decrypts otherwise.
 *
 * Exposed because XXTEA's round count depends on the word count, so this is the whole cipher rather
 * than a helper: at two words it is the block cipher below, and at more it is a different function for
 * every length.
 */
export function xxteaWords(v: number[], key: readonly number[], encrypt: boolean): void {
  const n = v.length;
  if (n < 2) throw new Error("XXTEA needs at least two 32-bit words (eight bytes).");
  const rounds = 6 + Math.floor(52 / n);
  if (encrypt) {
    let sum = 0;
    let z = v[n - 1]!;
    for (let round = 0; round < rounds; round++) {
      sum = u32(sum + XXTEA_DELTA);
      const e = (sum >>> 2) & 3;
      let y: number;
      for (let p = 0; p < n - 1; p++) {
        y = v[p + 1]!;
        z = v[p] = u32(v[p]! + xxteaMix(y, z, sum, e, p, key));
      }
      y = v[0]!;
      z = v[n - 1] = u32(v[n - 1]! + xxteaMix(y, z, sum, e, n - 1, key));
    }
  } else {
    let sum = u32(rounds * XXTEA_DELTA);
    let y = v[0]!;
    for (let round = 0; round < rounds; round++) {
      const e = (sum >>> 2) & 3;
      let z: number;
      for (let p = n - 1; p > 0; p--) {
        z = v[p - 1]!;
        y = v[p] = u32(v[p]! - xxteaMix(y, z, sum, e, p, key));
      }
      z = v[n - 1]!;
      y = v[0] = u32(v[0]! - xxteaMix(y, z, sum, e, 0, key));
      sum = u32(sum - XXTEA_DELTA);
    }
  }
}

/** XXTEA at two words: a 64-bit block, 128-bit key, 32 rounds. See the note above. */
export function createXxtea(key: Uint8Array): BlockCipher {
  requireKey(key, "XXTEA");
  const k = [load(key, 0), load(key, 4), load(key, 8), load(key, 12)];
  return {
    blockSize: BLOCK,
    encryptBlock(src, dst) {
      const v = [load(src, 0), load(src, 4)];
      xxteaWords(v, k, true);
      store(v[0]!, dst, 0);
      store(v[1]!, dst, 4);
    },
    decryptBlock(src, dst) {
      const v = [load(src, 0), load(src, 4)];
      xxteaWords(v, k, false);
      store(v[0]!, dst, 0);
      store(v[1]!, dst, 4);
    },
  };
}
