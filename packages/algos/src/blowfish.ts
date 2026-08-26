/**
 * Blowfish, from Schneier's 1993 paper, over the shared `BlockCipher` interface.
 *
 * Still everywhere despite its age: `bcrypt` is Blowfish's key schedule run 2^cost times, OpenPGP
 * lists it as an optional cipher, and a great deal of stored data from the 1990s and 2000s is
 * encrypted with it. A 64-bit block is what dates it -- see the security note on the tool -- not any
 * weakness in the cipher itself.
 *
 * **The tables are derived from pi, not transcribed.** The 18-word P-array and the four 256-word
 * S-boxes are, by definition, the first 8336 hexadecimal digits of the fractional part of pi. That is
 * 4168 bytes of constants, and this repo's rule is to derive whatever a specification says is
 * derivable: a mistyped word in a table that size produces a cipher which is perfectly
 * self-consistent, round-trips, and matches nothing in existence. So Machin's formula runs at module
 * load -- `pi = 16*atan(1/5) - 4*atan(1/239)`, in `bigint`, scaled by a power of sixteen -- and the
 * digits are read straight off. It costs about 35 milliseconds, once, inside a lazily-loaded chunk,
 * and `tests/algos-blowfish.test.ts` checks both that the first words are the published
 * `243f6a88 85a308d3 13198a2e 03707344` and that the cipher reproduces three of Eric Young's vectors.
 *
 * Three more things to know.
 *
 * **The key schedule is the expensive part, and deliberately so.** Setting a key runs the cipher 521
 * times to rewrite the P-array and all four S-boxes. That is what makes Blowfish slow to key and is
 * exactly the property `bcrypt` exploits. It also means a `BlockCipher` here must not re-derive the
 * schedule per block, which is why `createBlowfish` does the work once and closes over the result.
 *
 * **The key is 4 to 56 bytes, and short keys are cycled rather than padded.** The schedule XORs the
 * key into the P-array byte by byte, wrapping around when it runs out -- so a 4-byte key repeats
 * itself four and a half times across the eighteen words. That is the specification, not a shortcut.
 *
 * **`F` adds mod 2^32 and XORs, in that order.** `((S0[a] + S1[b]) ^ S2[c]) + S3[d]`. Getting the
 * mixture of additions and XORs wrong is the classic Blowfish bug and it survives a round trip
 * untouched.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
/** 18 P-array words plus 4 x 256 S-box words. */
const WORD_COUNT = 18 + 4 * 256;

/**
 * The hexadecimal digits of pi's fractional part, as 32-bit words.
 *
 * Machin's formula converges about one hex digit per two terms for the `atan(1/5)` half, so a few
 * thousand `bigint` divisions produce the eight thousand digits needed. The scale carries 32 digits of
 * slack so the last word is not affected by truncation error.
 */
function piWords(count: number): Uint32Array {
  const hexDigits = count * 8 + 32;
  const scale = 16n ** BigInt(hexDigits);

  /** `atan(1/x)`, scaled. The alternating series, truncated when a term reaches zero. */
  const atanInv = (x: bigint): bigint => {
    const squared = x * x;
    let term = scale / x;
    let sum = 0n;
    let k = 0n;
    while (term !== 0n) {
      const contribution = term / (2n * k + 1n);
      sum += k % 2n === 0n ? contribution : -contribution;
      term /= squared;
      k += 1n;
    }
    return sum;
  };

  const pi = 16n * atanInv(5n) - 4n * atanInv(239n);
  // Only the fractional part carries the table; the leading 3 is not a digit of it.
  const digits = (pi - 3n * scale).toString(16).padStart(hexDigits, "0");

  const words = new Uint32Array(count);
  for (let i = 0; i < count; i++) {
    words[i] = Number.parseInt(digits.slice(i * 8, i * 8 + 8), 16) >>> 0;
  }
  return words;
}

const PI_WORDS = piWords(WORD_COUNT);
/** The initial P-array, before any key is mixed in. Exported for the table test. */
export const BLOWFISH_P_INIT: readonly number[] = Array.from(PI_WORDS.subarray(0, 18));
const S_INIT: readonly Uint32Array[] = [0, 1, 2, 3].map((i) =>
  PI_WORDS.slice(18 + i * 256, 18 + (i + 1) * 256),
);

const EMPTY = new Uint8Array(0);

/**
 * The 1042 words of Blowfish key state: eighteen subkeys and four 256-entry S-boxes.
 *
 * Exposed because bcrypt's key derivation drives the schedule directly rather than calling a
 * cipher. See `bcrypt-pbkdf.ts`.
 */
export interface BlowfishState {
  p: Uint32Array;
  s: Uint32Array[];
}

/** P and S set to pi's digits -- OpenBSD's `Blowfish_initstate`. */
export function blowfishInitState(): BlowfishState {
  return { p: PI_WORDS.slice(0, 18), s: S_INIT.map((table) => table.slice()) };
}

function sboxF(s: Uint32Array[], x: number): number {
  return (
    ((((s[0]![x >>> 24]! + s[1]![(x >>> 16) & 0xff]!) >>> 0) ^ s[2]![(x >>> 8) & 0xff]!) +
      s[3]![x & 0xff]!) >>>
    0
  );
}

/**
 * Encrypt `words` in place as consecutive pairs -- OpenBSD's `blf_enc`.
 *
 * The schedule is read live, which is what the expansion below depends on: each pair is enciphered
 * under the subkeys the previous pairs have already replaced.
 */
export function blowfishEncryptWords(state: BlowfishState, words: Uint32Array): void {
  const { p, s } = state;
  for (let i = 0; i + 1 < words.length; i += 2) {
    let left = words[i]!;
    let right = words[i + 1]!;
    for (let round = 0; round < 16; round++) {
      left = (left ^ p[round]!) >>> 0;
      const next = (right ^ sboxF(s, left)) >>> 0;
      right = left;
      left = next;
    }
    // The final swap, with the two remaining subkeys applied in the opposite order.
    words[i] = (right ^ p[17]!) >>> 0;
    words[i + 1] = (left ^ p[16]!) >>> 0;
  }
}

/**
 * OpenBSD's `Blowfish_expandstate`, and its `Blowfish_expand0state` when `data` is empty.
 *
 * The key is XORed into P as a big-endian word stream that cycles -- a 4-byte key wraps four and a
 * half times across the eighteen words -- and then every word of P and S is replaced by the
 * encryption of a running pair, starting from zero. That is the 521 encryptions that make keying
 * expensive, and why every word depends on every key byte and on every word before it.
 *
 * `data` is bcrypt's salt. It is XORed into the pair before each encryption from a *second* cursor
 * that runs continuously across all 1042 words, so with a 64-byte salt it wraps 65 times and lands
 * eight bytes in. Standard Blowfish keying is this with no data at all.
 */
export function blowfishExpandState(
  state: BlowfishState,
  key: Uint8Array,
  data: Uint8Array = EMPTY,
): void {
  const { p, s } = state;

  let cursor = 0;
  const streamWord = (src: Uint8Array): number => {
    let word = 0;
    for (let j = 0; j < 4; j++) {
      word = ((word << 8) | src[cursor % src.length]!) >>> 0;
      cursor++;
    }
    return word;
  };

  for (let i = 0; i < 18; i++) p[i] = (p[i]! ^ streamWord(key)) >>> 0;

  cursor = 0;
  const pair = new Uint32Array(2);
  const step = (): void => {
    if (data.length > 0) {
      pair[0] = (pair[0]! ^ streamWord(data)) >>> 0;
      pair[1] = (pair[1]! ^ streamWord(data)) >>> 0;
    }
    blowfishEncryptWords(state, pair);
  };

  for (let i = 0; i < 18; i += 2) {
    step();
    p[i] = pair[0]!;
    p[i + 1] = pair[1]!;
  }
  for (let box = 0; box < 4; box++) {
    for (let i = 0; i < 256; i += 2) {
      step();
      s[box]![i] = pair[0]!;
      s[box]![i + 1] = pair[1]!;
    }
  }
}

function expandKey(key: Uint8Array): BlowfishState {
  if (key.length < 4 || key.length > 56) {
    throw new Error(`Blowfish's key is 4 to 56 bytes; this one is ${key.length}.`);
  }

  const state = blowfishInitState();
  blowfishExpandState(state, key);
  return state;
}

/** Blowfish as a `BlockCipher`. The key schedule runs once, here. */
export function createBlowfish(key: Uint8Array): BlockCipher {
  const state = expandKey(key);
  const { p, s } = state;

  const run = (src: Uint8Array, dst: Uint8Array, forward: boolean): void => {
    let left = ((src[0]! << 24) | (src[1]! << 16) | (src[2]! << 8) | src[3]!) >>> 0;
    let right = ((src[4]! << 24) | (src[5]! << 16) | (src[6]! << 8) | src[7]!) >>> 0;

    for (let round = 0; round < 16; round++) {
      left = (left ^ p[forward ? round : 17 - round]!) >>> 0;
      const next = (right ^ sboxF(s, left)) >>> 0;
      right = left;
      left = next;
    }
    // The final swap, with the two remaining subkeys applied in the opposite order.
    const swap = left;
    left = (right ^ p[forward ? 17 : 0]!) >>> 0;
    right = (swap ^ p[forward ? 16 : 1]!) >>> 0;

    dst[0] = (left >>> 24) & 0xff;
    dst[1] = (left >>> 16) & 0xff;
    dst[2] = (left >>> 8) & 0xff;
    dst[3] = left & 0xff;
    dst[4] = (right >>> 24) & 0xff;
    dst[5] = (right >>> 16) & 0xff;
    dst[6] = (right >>> 8) & 0xff;
    dst[7] = right & 0xff;
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => run(src, dst, true),
    decryptBlock: (src, dst) => run(src, dst, false),
  };
}
