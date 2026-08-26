/**
 * HAVAL, all fifteen variants: 3, 4 or 5 passes at 128, 160, 192, 224 or 256 bits.
 *
 * A 1992 design from Zheng, Pieprzyk and Seberry, and the reason it is here is PHP: `hash_algos()`
 * lists all fifteen, so anything that ever stored a `haval160,4` needs a tool that can reproduce one.
 * Nothing else in this project's dependency tree implements it.
 *
 * Five things to know before touching this.
 *
 * **It is broken, and the metadata says so per variant.** Wang's 2004 attack produces collisions in
 * HAVAL-128 (3 pass) by hand; later work reaches 4-pass HAVAL and weakens 5-pass. The tool entries
 * carry that distinction rather than flattening it, because "broken" and "weakened" are different
 * claims and this repo does not overstate either.
 *
 * **Everything is little-endian**, including the 64-bit length and the digest.
 *
 * **The pass count changes the round functions' argument order, not just how many rounds run.** The
 * HAVAL specification gives a different permutation phi for 3-, 4- and 5-pass HAVAL, so `haval256,4`
 * is not `haval256,5` stopped early. `PHI` below is those permutations as data -- get one wrong and
 * only that pass count is affected, which is exactly the sort of failure a single vector would miss.
 *
 * **The digest length is not a truncation.** Below 256 bits the state is folded down by a
 * length-specific "tailoring" function -- overlapping bit fields of the top words added into the lower
 * ones -- so HAVAL-128 is a genuinely different value from the first 16 bytes of HAVAL-256. It is
 * `parameterized` in this repo's taxonomy, like BLAKE2 and Skein.
 *
 * **The padding carries the parameters.** HAVAL pads to 118 mod 128 bytes and then appends ten bytes:
 * a version number, the pass count, the digest length and the 64-bit message length. Two variants of
 * the same message therefore differ from the last block onwards, which is what makes them distinct
 * functions rather than different truncations. That is also why the length is captured *before*
 * padding begins.
 *
 * The values checked against are PHP's, from `ext/hash/tests/haval.phpt` (all fifteen at three
 * messages) and `hash_copy_001.phpt`.
 */

/** The initial state: the first 32 hex digits of pi's fractional part, as eight words. */
const D0 = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
];

/** Round constants for passes 2 to 5 -- further digits of pi, 32 words each. */
const K2 = [
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
  0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
  0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
  0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5,
];
const K3 = [
  0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
  0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94,
  0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993,
  0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
];
const K4 = [
  0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991,
  0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
  0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
  0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4,
];
const K5 = [
  0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4,
  0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
  0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b,
  0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4,
];

/** The word order each pass reads the message in. Pass 1 reads it straight through. */
const WORD_ORDER: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31],
  [5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8, 30, 3, 21, 9, 17, 24, 29, 6, 19, 12,
    15, 13, 2, 25, 31, 27],
  [19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26, 31, 15, 7, 3, 1, 0, 18, 27, 13, 6,
    21, 10, 23, 11, 5, 2],
  [24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3, 22, 11, 31, 21, 8, 27, 12, 9, 1, 29,
    5, 15, 17, 10, 16, 13],
  [27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10, 5, 9, 14, 30, 18, 6, 28, 24, 2, 23,
    16, 22, 4, 1, 25, 15],
];

/** The constants each pass adds. Pass 1 adds none. */
const PASS_CONSTANTS: readonly (readonly number[] | null)[] = [null, K2, K3, K4, K5];

/**
 * The permutation phi, as the seven state slots each pass feeds to its round function.
 *
 * Indexed by pass count then by pass. Each entry lists the slot offsets supplying the round
 * function's arguments in the order the specification writes them, x6 first. The offsets are relative:
 * slot `k` at step `i` means state word `(k - i) mod 8`, which is the rotating window HAVAL walks.
 */
const PHI: Record<number, readonly (readonly number[])[]> = {
  3: [
    [1, 0, 3, 5, 6, 2, 4],
    [4, 2, 1, 0, 5, 3, 6],
    [6, 1, 2, 3, 4, 5, 0],
  ],
  4: [
    [2, 6, 1, 4, 5, 3, 0],
    [3, 5, 2, 0, 1, 6, 4],
    [1, 4, 3, 6, 0, 2, 5],
    [6, 4, 0, 5, 2, 1, 3],
  ],
  5: [
    [3, 4, 1, 0, 5, 2, 6],
    [6, 2, 1, 0, 3, 4, 5],
    [2, 6, 0, 4, 3, 1, 5],
    [1, 5, 3, 2, 0, 4, 6],
    [2, 5, 0, 6, 4, 3, 1],
  ],
};

/**
 * The five boolean round functions, arguments named as the specification names them.
 *
 * Transcribed from the specification's Boolean expressions rather than from a table, because that is
 * how they are published -- and because the sixteen AND terms of F4 are far easier to check against
 * the paper in this form than as a truth table.
 */
const F: readonly ((
  x6: number,
  x5: number,
  x4: number,
  x3: number,
  x2: number,
  x1: number,
  x0: number,
) => number)[] = [
  (x6, x5, x4, x3, x2, x1, x0) => (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1) ^ x0,
  (x6, x5, x4, x3, x2, x1, x0) =>
    (x1 & x2 & x3) ^
    (x2 & x4 & x5) ^
    (x1 & x2) ^
    (x1 & x4) ^
    (x2 & x6) ^
    (x3 & x5) ^
    (x4 & x5) ^
    (x0 & x2) ^
    x0,
  (x6, x5, x4, x3, x2, x1, x0) =>
    (x1 & x2 & x3) ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x3) ^ x0,
  (x6, x5, x4, x3, x2, x1, x0) =>
    (x1 & x2 & x3) ^
    (x2 & x4 & x5) ^
    (x3 & x4 & x6) ^
    (x1 & x4) ^
    (x2 & x6) ^
    (x3 & x4) ^
    (x3 & x5) ^
    (x3 & x6) ^
    (x4 & x5) ^
    (x4 & x6) ^
    (x0 & x4) ^
    x0,
  (x6, x5, x4, x3, x2, x1, x0) =>
    (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1 & x2 & x3) ^ (x0 & x5) ^ x0,
];

const rotr32 = (x: number, n: number): number => ((x >>> n) | (x << (32 - n))) >>> 0;

export const HAVAL_BLOCK_LEN = 128;
export const HAVAL_PASSES: readonly number[] = [3, 4, 5];
/** In bytes. */
export const HAVAL_OUTPUT_LENS: readonly number[] = [16, 20, 24, 28, 32];

export interface HavalHasher {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

class Haval implements HavalHasher {
  private readonly state = Uint32Array.from(D0);
  private readonly words = new Uint32Array(32);
  private readonly buffer = new Uint8Array(HAVAL_BLOCK_LEN);
  private buffered = 0;
  private length = 0;
  private done = false;

  constructor(
    private readonly passes: number,
    private readonly outputLen: number,
  ) {
    if (!HAVAL_PASSES.includes(passes)) {
      throw new Error(`HAVAL runs 3, 4 or 5 passes; ${passes} was requested.`);
    }
    if (!HAVAL_OUTPUT_LENS.includes(outputLen)) {
      throw new Error(`HAVAL produces 16, 20, 24, 28 or 32 bytes; ${outputLen} was requested.`);
    }
  }

  /**
   * One 128-byte block: `passes` sweeps of 32 steps over a rotating eight-word window.
   *
   * `(k - i) mod 8` is the whole trick. The specification writes the step as an assignment to a
   * rotating slot with its inputs named relative to that slot, and PHP spells the same thing out as
   * eight precomputed index tables; computing the index is one expression and cannot fall out of step
   * with itself.
   */
  private processBlock(bytes: Uint8Array, at: number): void {
    for (let i = 0; i < 32; i++) {
      const j = at + i * 4;
      this.words[i] =
        (bytes[j]! | (bytes[j + 1]! << 8) | (bytes[j + 2]! << 16) | (bytes[j + 3]! << 24)) >>> 0;
    }

    const e = new Uint32Array(this.state);
    const phi = PHI[this.passes]!;

    for (let pass = 0; pass < this.passes; pass++) {
      const slots = phi[pass]!;
      const order = WORD_ORDER[pass]!;
      const constants = PASS_CONSTANTS[pass];
      const fn = F[pass]!;

      for (let i = 0; i < 32; i++) {
        const slot = (k: number) => e[(((k - i) % 8) + 8) % 8]!;
        const mixed = fn(
          slot(slots[0]!),
          slot(slots[1]!),
          slot(slots[2]!),
          slot(slots[3]!),
          slot(slots[4]!),
          slot(slots[5]!),
          slot(slots[6]!),
        );
        let value = (rotr32(mixed >>> 0, 7) + rotr32(slot(7), 11)) >>> 0;
        value = (value + this.words[order[i]!]!) >>> 0;
        if (constants) value = (value + constants[i]!) >>> 0;
        e[7 - (i % 8)] = value >>> 0;
      }
    }

    for (let i = 0; i < 8; i++) this.state[i] = (this.state[i]! + e[i]!) >>> 0;
  }

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("HAVAL: update after digest");
    this.length += chunk.length;

    let offset = 0;
    while (offset < chunk.length) {
      const take = Math.min(HAVAL_BLOCK_LEN - this.buffered, chunk.length - offset);
      this.buffer.set(chunk.subarray(offset, offset + take), this.buffered);
      this.buffered += take;
      offset += take;
      if (this.buffered === HAVAL_BLOCK_LEN) {
        this.processBlock(this.buffer, 0);
        this.buffered = 0;
      }
    }
  }

  /** Absorbs padding without disturbing the recorded message length. */
  private absorb(bytes: Uint8Array): void {
    let offset = 0;
    while (offset < bytes.length) {
      const take = Math.min(HAVAL_BLOCK_LEN - this.buffered, bytes.length - offset);
      this.buffer.set(bytes.subarray(offset, offset + take), this.buffered);
      this.buffered += take;
      offset += take;
      if (this.buffered === HAVAL_BLOCK_LEN) {
        this.processBlock(this.buffer, 0);
        this.buffered = 0;
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("HAVAL: digest called twice");
    this.done = true;

    /**
     * The ten-byte trailer, built before any padding is absorbed.
     *
     * Version 1, the pass count and the digest length in bits go in the first two bytes, and the
     * message length in bits fills the remaining eight -- little-endian, like everything else here.
     */
    const outputBits = this.outputLen * 8;
    const trailer = new Uint8Array(10);
    trailer[0] = (1 & 0x07) | ((this.passes & 0x07) << 3) | ((outputBits & 0x03) << 6);
    trailer[1] = outputBits >> 2;
    let bits = this.length * 8;
    for (let i = 0; i < 8; i++) {
      trailer[2 + i] = bits % 256;
      bits = Math.floor(bits / 256);
    }

    // Pad to 118 mod 128 with a single 1 bit followed by zeros, then append the trailer.
    const index = this.length % HAVAL_BLOCK_LEN;
    const padLen = index < 118 ? 118 - index : 246 - index;
    const padding = new Uint8Array(padLen);
    padding[0] = 1;
    this.absorb(padding);
    this.absorb(trailer);

    this.tailor();

    const out = new Uint8Array(this.outputLen);
    for (let i = 0; i < this.outputLen / 4; i++) {
      const word = this.state[i]!;
      out[i * 4] = word & 0xff;
      out[i * 4 + 1] = (word >>> 8) & 0xff;
      out[i * 4 + 2] = (word >>> 16) & 0xff;
      out[i * 4 + 3] = (word >>> 24) & 0xff;
    }
    return out;
  }

  /**
   * The tailoring function: folds the 256-bit state down to the requested width.
   *
   * Each shorter length has its own arrangement of overlapping bit fields taken from the top words
   * and added into the words that will be output. This is what makes HAVAL-128 a different function
   * from a truncated HAVAL-256 rather than a prefix of it, and it is transcribed from the
   * specification's own expressions -- there is no pattern to derive it from.
   */
  private tailor(): void {
    const s = this.state;
    const add = (index: number, value: number) => {
      s[index] = (s[index]! + (value >>> 0)) >>> 0;
    };

    switch (this.outputLen) {
      case 16:
        add(3, (s[7]! & 0xff000000) | (s[6]! & 0x00ff0000) | (s[5]! & 0x0000ff00) | (s[4]! & 0xff));
        add(
          2,
          (((s[7]! & 0x00ff0000) | (s[6]! & 0x0000ff00) | (s[5]! & 0xff)) << 8) |
            ((s[4]! & 0xff000000) >>> 24),
        );
        add(
          1,
          (((s[7]! & 0x0000ff00) | (s[6]! & 0xff)) << 16) |
            (((s[5]! & 0xff000000) | (s[4]! & 0x00ff0000)) >>> 16),
        );
        add(
          0,
          ((s[7]! & 0xff) << 24) |
            (((s[6]! & 0xff000000) | (s[5]! & 0x00ff0000) | (s[4]! & 0x0000ff00)) >>> 8),
        );
        break;
      case 20:
        add(4, ((s[7]! & 0xfe000000) | (s[6]! & 0x01f80000) | (s[5]! & 0x0007f000)) >>> 12);
        add(3, ((s[7]! & 0x01f80000) | (s[6]! & 0x0007f000) | (s[5]! & 0x00000fc0)) >>> 6);
        add(2, (s[7]! & 0x0007f000) | (s[6]! & 0x00000fc0) | (s[5]! & 0x0000003f));
        add(
          1,
          rotr32(((s[7]! & 0x00000fc0) | (s[6]! & 0x0000003f) | (s[5]! & 0xfe000000)) >>> 0, 25),
        );
        add(
          0,
          rotr32(((s[7]! & 0x0000003f) | (s[6]! & 0xfe000000) | (s[5]! & 0x01f80000)) >>> 0, 19),
        );
        break;
      case 24:
        add(5, ((s[7]! & 0xfc000000) | (s[6]! & 0x03e00000)) >>> 21);
        add(4, ((s[7]! & 0x03e00000) | (s[6]! & 0x001f0000)) >>> 16);
        add(3, ((s[7]! & 0x001f0000) | (s[6]! & 0x0000fc00)) >>> 10);
        add(2, ((s[7]! & 0x0000fc00) | (s[6]! & 0x000003e0)) >>> 5);
        add(1, (s[7]! & 0x000003e0) | (s[6]! & 0x0000001f));
        add(0, rotr32(((s[7]! & 0x0000001f) | (s[6]! & 0xfc000000)) >>> 0, 26));
        break;
      case 28:
        add(6, s[7]! & 0x0000000f);
        add(5, (s[7]! >>> 4) & 0x0000001f);
        add(4, (s[7]! >>> 9) & 0x0000000f);
        add(3, (s[7]! >>> 13) & 0x0000001f);
        add(2, (s[7]! >>> 18) & 0x0000000f);
        add(1, (s[7]! >>> 22) & 0x0000001f);
        add(0, (s[7]! >>> 27) & 0x0000001f);
        break;
      default:
        // 256 bits is the full state; nothing to fold.
        break;
    }
  }
}

export function createHaval(passes: number, outputLen: number): HavalHasher {
  return new Haval(passes, outputLen);
}

export function haval(data: Uint8Array, passes: number, outputLen: number): Uint8Array {
  const h = createHaval(passes, outputLen);
  h.update(data);
  return h.digest();
}
