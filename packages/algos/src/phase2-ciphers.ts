/**
 * Four more block ciphers: Noekeon, LEA, SHACAL-2 and GOST 28147-89.
 *
 * They are in one file because none of them needs a table of its own, which is the whole reason this
 * batch was cheap: two have no constants beyond a handful of round values, one *derives* its constants
 * from first principles, and the fourth reuses S-boxes already in this repo. Compare the seven ciphers
 * that came before, where the work was almost entirely getting multi-kilobyte tables in correctly.
 *
 * Vectors for all four came from Bouncy Castle's test suite, fetched and parsed rather than recalled --
 * and the engines were fetched too, which is what settled Noekeon's round-constant schedule and LEA's
 * key schedule rather than leaving them to memory. `tests/algos-phase2-ciphers.test.ts` carries them.
 */

import type { BlockCipher } from "./blockmodes";

const u32 = (x: number): number => x >>> 0;
const rotl = (x: number, n: number): number =>
  n === 0 ? u32(x) : u32((x << n) | (x >>> (32 - n)));
const rotr = (x: number, n: number): number =>
  n === 0 ? u32(x) : u32((x >>> n) | (x << (32 - n)));

const loadBE = (src: Uint8Array, at: number): number =>
  u32((src[at]! << 24) | (src[at + 1]! << 16) | (src[at + 2]! << 8) | src[at + 3]!);

function storeBE(value: number, dst: Uint8Array, at: number): void {
  dst[at] = (value >>> 24) & 0xff;
  dst[at + 1] = (value >>> 16) & 0xff;
  dst[at + 2] = (value >>> 8) & 0xff;
  dst[at + 3] = value & 0xff;
}

const loadLE = (src: Uint8Array, at: number): number =>
  u32(src[at]! | (src[at + 1]! << 8) | (src[at + 2]! << 16) | (src[at + 3]! << 24));

function storeLE(value: number, dst: Uint8Array, at: number): void {
  dst[at] = value & 0xff;
  dst[at + 1] = (value >>> 8) & 0xff;
  dst[at + 2] = (value >>> 16) & 0xff;
  dst[at + 3] = (value >>> 24) & 0xff;
}

// ───────────────────────────────────────────────────────────────── Noekeon

/**
 * Noekeon: 128-bit block, 128-bit key, sixteen rounds, and no key schedule at all.
 *
 * Daemen, Peeters, Van Assche and Rijmen -- the Rijndael and Keccak authors -- submitted it to NESSIE
 * as a design with the smallest possible description. It shows: the round is four operations over four
 * words, the only constants are seventeen bytes of an LFSR sequence, and in **direct-key mode** the key
 * is used as-is with nothing derived from it.
 *
 * Two things worth knowing.
 *
 * **This is direct-key mode, which NESSIE declined to recommend.** Noekeon defines an *indirect* mode
 * that runs the cipher over the key first, specifically to break the related-key attack that direct
 * mode has; NESSIE's report cited that attack as the reason for not selecting it. Direct mode is what
 * every implementation ships and what the published vectors are for, so it is what this reproduces --
 * and the security posture says so rather than implying the design is unbroken.
 *
 * **Decryption inverts the key rather than the network.** The same seventeen rounds run backwards over
 * a key that has had theta applied to it with a zero key -- that one transformation is the whole
 * difference, which is why `createNoekeon` builds two sets of working key words instead of branching
 * inside the loop.
 */
const NOEKEON_RC: readonly number[] = [
  0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
  0xd4,
];

/** Theta: the linear layer, mixing the four words through two diffusion terms and the key. */
function noekeonTheta(a: number[], k: readonly number[]): void {
  let t02 = a[0]! ^ a[2]!;
  t02 = u32(t02 ^ rotl(t02, 8) ^ rotl(t02, 24));
  a[0] = u32(a[0]! ^ k[0]!);
  a[1] = u32(a[1]! ^ k[1]!);
  a[2] = u32(a[2]! ^ k[2]!);
  a[3] = u32(a[3]! ^ k[3]!);
  let t13 = a[1]! ^ a[3]!;
  t13 = u32(t13 ^ rotl(t13, 8) ^ rotl(t13, 24));
  a[0] = u32(a[0]! ^ t13);
  a[1] = u32(a[1]! ^ t02);
  a[2] = u32(a[2]! ^ t13);
  a[3] = u32(a[3]! ^ t02);
}

/** Gamma: the nonlinear layer. Its own inverse, which is why one function serves both directions. */
function noekeonGamma(a: number[]): void {
  const t = a[3]!;
  a[1] = u32(a[1]! ^ (a[3]! | a[2]!));
  a[3] = u32(a[0]! ^ (a[2]! & ~a[1]!));
  a[2] = u32(t ^ ~a[1]! ^ a[2]! ^ a[3]!);
  a[1] = u32(a[1]! ^ (a[3]! | a[2]!));
  a[0] = u32(t ^ (a[2]! & a[1]!));
}

export function createNoekeon(key: Uint8Array): BlockCipher {
  if (key.length !== 16) {
    throw new Error(`Noekeon's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  const forward = [loadBE(key, 0), loadBE(key, 4), loadBE(key, 8), loadBE(key, 12)];
  // The decryption key: theta over the key with a zero key. The one asymmetry in the whole cipher.
  const inverse = [...forward];
  noekeonTheta(inverse, [0, 0, 0, 0]);

  const run = (src: Uint8Array, dst: Uint8Array, forwardDirection: boolean): void => {
    const a = [loadBE(src, 0), loadBE(src, 4), loadBE(src, 8), loadBE(src, 12)];
    const k = forwardDirection ? forward : inverse;
    let round = forwardDirection ? 0 : 16;

    for (;;) {
      if (forwardDirection) a[0] = u32(a[0]! ^ NOEKEON_RC[round]!);
      noekeonTheta(a, k);
      if (!forwardDirection) a[0] = u32(a[0]! ^ NOEKEON_RC[round]!);

      if (forwardDirection ? ++round > 16 : --round < 0) break;

      // Pi1, gamma, Pi2. The two pi layers are rotations by amounts that sum to 32 per word, which is
      // what makes them each other's inverse and lets one loop serve both directions.
      a[1] = rotl(a[1]!, 1);
      a[2] = rotl(a[2]!, 5);
      a[3] = rotl(a[3]!, 2);
      noekeonGamma(a);
      a[1] = rotl(a[1]!, 31);
      a[2] = rotl(a[2]!, 27);
      a[3] = rotl(a[3]!, 30);
    }

    for (let i = 0; i < 4; i++) storeBE(a[i]!, dst, i * 4);
  };

  return {
    blockSize: 16,
    encryptBlock: (src, dst) => run(src, dst, true),
    decryptBlock: (src, dst) => run(src, dst, false),
  };
}

// ───────────────────────────────────────────────────────────────────── LEA

/**
 * LEA: Korea's lightweight block cipher, ISO/IEC 29192-2 and KS X 3246.
 *
 * 128-bit block, 128/192/256-bit key, 24/28/32 rounds, and add-rotate-XOR throughout -- no S-box, no
 * table, nothing to mistype but eight delta constants. Designed to be fast in software on a 32-bit
 * machine, which is the opposite of PRESENT's goal and the reason both exist.
 *
 * **The three key sizes are three different key schedules, not one parameterised by length.** 128-bit
 * keys walk four words with a fixed subkey pattern that repeats one word three times; 192-bit keys walk
 * six with no repetition; 256-bit keys walk eight through a *rotating index*, so the same word feeds
 * different positions on successive rounds. Writing one and adapting it is how an implementation ends
 * up correct at 128 bits and wrong at 256 -- which is why all three vectors are in the test.
 */
const LEA_DELTA: readonly number[] = [
  0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957,
];

function leaSchedule(key: Uint8Array): number[][] {
  const rounds = (key.length >> 1) + 16;
  const words = key.length / 4;
  const work = Array.from({ length: words }, (_, i) => loadLE(key, i * 4));
  const keys: number[][] = [];

  if (words === 4) {
    for (let i = 0; i < rounds; i++) {
      const delta = rotl(LEA_DELTA[i & 3]!, i);
      work[0] = rotl(u32(work[0]! + delta), 1);
      work[1] = rotl(u32(work[1]! + rotl(delta, 1)), 3);
      work[2] = rotl(u32(work[2]! + rotl(delta, 2)), 6);
      work[3] = rotl(u32(work[3]! + rotl(delta, 3)), 11);
      // The 128-bit pattern: word 1 appears three times, which is what makes this schedule distinct.
      keys.push([work[0]!, work[1]!, work[2]!, work[1]!, work[3]!, work[1]!]);
    }
    return keys;
  }

  if (words === 6) {
    for (let i = 0; i < rounds; i++) {
      const delta = rotl(LEA_DELTA[i % 6]!, i);
      const rotations = [1, 3, 6, 11, 13, 17];
      for (let j = 0; j < 6; j++) {
        work[j] = rotl(u32(work[j]! + rotl(delta, j)), rotations[j]!);
      }
      keys.push([work[0]!, work[1]!, work[2]!, work[3]!, work[4]!, work[5]!]);
    }
    return keys;
  }

  // 256-bit: a rotating index over eight words, so a word's position moves every round.
  let index = 0;
  for (let i = 0; i < rounds; i++) {
    const delta = rotl(LEA_DELTA[i & 7]!, i);
    const rotations = [1, 3, 6, 11, 13, 17];
    const round: number[] = [];
    for (let j = 0; j < 6; j++) {
      const value = rotl(u32(work[index & 7]! + rotl(delta, j)), rotations[j]!);
      work[index & 7] = value;
      round.push(value);
      index++;
    }
    keys.push(round);
  }
  return keys;
}

export function createLea(key: Uint8Array): BlockCipher {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(`LEA's key is 16, 24 or 32 bytes; this one is ${key.length}.`);
  }
  const keys = leaSchedule(key);

  return {
    blockSize: 16,
    encryptBlock(src, dst) {
      let x0 = loadLE(src, 0);
      let x1 = loadLE(src, 4);
      let x2 = loadLE(src, 8);
      let x3 = loadLE(src, 12);
      for (const rk of keys) {
        const n0 = rotl(u32((x0 ^ rk[0]!) + (x1 ^ rk[1]!)), 9);
        const n1 = rotr(u32((x1 ^ rk[2]!) + (x2 ^ rk[3]!)), 5);
        const n2 = rotr(u32((x2 ^ rk[4]!) + (x3 ^ rk[5]!)), 3);
        // The block rotates: the old x0 becomes the new x3.
        [x0, x1, x2, x3] = [n0, n1, n2, x0];
      }
      storeLE(x0, dst, 0);
      storeLE(x1, dst, 4);
      storeLE(x2, dst, 8);
      storeLE(x3, dst, 12);
    },
    decryptBlock(src, dst) {
      let x0 = loadLE(src, 0);
      let x1 = loadLE(src, 4);
      let x2 = loadLE(src, 8);
      let x3 = loadLE(src, 12);
      for (let i = keys.length - 1; i >= 0; i--) {
        const rk = keys[i]!;
        // Undo the rotation first, then each half-round in reverse.
        [x0, x1, x2, x3] = [x3, x0, x1, x2];
        x1 = u32(u32(rotr(x1, 9) - (x0 ^ rk[0]!)) ^ rk[1]!);
        x2 = u32(u32(rotl(x2, 5) - (x1 ^ rk[2]!)) ^ rk[3]!);
        x3 = u32(u32(rotl(x3, 3) - (x2 ^ rk[4]!)) ^ rk[5]!);
      }
      storeLE(x0, dst, 0);
      storeLE(x1, dst, 4);
      storeLE(x2, dst, 8);
      storeLE(x3, dst, 12);
    },
  };
}

// ─────────────────────────────────────────────────────────────── SHACAL-2

/**
 * SHACAL-2: SHA-256's compression function used as a block cipher, and a NESSIE selection.
 *
 * The block *is* the 256-bit chaining value and the key *is* the 512-bit message block. Sixty-four
 * rounds of SHA-256's round function, with the key expanded through SHA-256's own message schedule --
 * and crucially **without the Davies-Meyer feedforward**, since adding the input back is exactly what
 * makes a compression function one-way and a cipher has to be invertible.
 *
 * **Its constants are derived, not transcribed**, which is the point of it being here. SHA-256's
 * sixty-four K values are the first thirty-two bits of the fractional parts of the cube roots of the
 * first sixty-four primes, and computing them at load costs under a millisecond. That is the same rule
 * Blowfish's 4168 bytes from pi and ARIA's inverted S-boxes follow, and it applies more strongly here
 * than usual: a mistyped K is a cipher that inverts perfectly and matches nothing, and there are
 * sixty-four chances to make that mistake.
 *
 * A 512-bit key is unusual enough to note: it is *larger than the block*, which means the schedule
 * expands nothing and there is no notion of a weak key length. The block being 256 bits also makes it
 * the second-widest block in the app after Threefish.
 */
const SHACAL2_K: readonly number[] = (() => {
  /** The first 64 primes, sieved rather than listed -- there is nothing to mistype in a sieve. */
  const primes: number[] = [];
  for (let n = 2; primes.length < 64; n++) {
    if (primes.every((p) => n % p !== 0)) primes.push(n);
  }
  /**
   * The first 32 bits of the fractional part of each prime's cube root.
   *
   * `Math.cbrt` is a double, so it carries 52 bits of mantissa -- comfortably more than the 32 wanted,
   * and the test asserts the first and last values against FIPS 180-4 so the derivation is checked
   * rather than assumed.
   */
  return primes.map((p) => {
    const fraction = Math.cbrt(p) % 1;
    return u32(Math.floor(fraction * 2 ** 32));
  });
})();

/** Exported so the test can check the derivation against FIPS 180-4's published table. */
export const SHACAL2_ROUND_CONSTANTS: readonly number[] = SHACAL2_K;

export function createShacal2(key: Uint8Array): BlockCipher {
  if (key.length < 16 || key.length > 64) {
    throw new Error(`SHACAL-2's key is 16 to 64 bytes; this one is ${key.length}.`);
  }
  // Shorter keys are zero-padded to 512 bits, which is what the reference does and what makes the
  // 128-bit-key vectors comparable.
  const padded = new Uint8Array(64);
  padded.set(key);

  const w = new Array<number>(64);
  for (let i = 0; i < 16; i++) w[i] = loadBE(padded, i * 4);
  for (let i = 16; i < 64; i++) {
    const s0 = rotr(w[i - 15]!, 7) ^ rotr(w[i - 15]!, 18) ^ (w[i - 15]! >>> 3);
    const s1 = rotr(w[i - 2]!, 17) ^ rotr(w[i - 2]!, 19) ^ (w[i - 2]! >>> 10);
    w[i] = u32(s1 + w[i - 7]! + s0 + w[i - 16]!);
  }

  return {
    blockSize: 32,
    encryptBlock(src, dst) {
      const b = Array.from({ length: 8 }, (_, i) => loadBE(src, i * 4));
      for (let i = 0; i < 64; i++) {
        const s1 = rotr(b[4]!, 6) ^ rotr(b[4]!, 11) ^ rotr(b[4]!, 25);
        const ch = (b[4]! & b[5]!) ^ (~b[4]! & b[6]!);
        const t1 = u32(b[7]! + s1 + ch + SHACAL2_K[i]! + w[i]!);
        const s0 = rotr(b[0]!, 2) ^ rotr(b[0]!, 13) ^ rotr(b[0]!, 22);
        const maj = (b[0]! & b[1]!) ^ (b[0]! & b[2]!) ^ (b[1]! & b[2]!);
        const t2 = u32(s0 + maj);
        b[7] = b[6]!;
        b[6] = b[5]!;
        b[5] = b[4]!;
        b[4] = u32(b[3]! + t1);
        b[3] = b[2]!;
        b[2] = b[1]!;
        b[1] = b[0]!;
        b[0] = u32(t1 + t2);
      }
      for (let i = 0; i < 8; i++) storeBE(b[i]!, dst, i * 4);
    },
    decryptBlock(src, dst) {
      const b = Array.from({ length: 8 }, (_, i) => loadBE(src, i * 4));
      for (let i = 63; i >= 0; i--) {
        const a = b[0]!;
        b[0] = b[1]!;
        b[1] = b[2]!;
        b[2] = b[3]!;
        const e = b[4]!;
        b[3] = b[5]!;
        b[4] = b[5]!;
        b[5] = b[6]!;
        b[6] = b[7]!;
        // Recover T1 and T2 from the shifted state, then unwind d and h.
        const s0 = rotr(b[0]!, 2) ^ rotr(b[0]!, 13) ^ rotr(b[0]!, 22);
        const maj = (b[0]! & b[1]!) ^ (b[0]! & b[2]!) ^ (b[1]! & b[2]!);
        const t2 = u32(s0 + maj);
        const t1 = u32(a - t2);
        b[3] = u32(e - t1);
        const s1 = rotr(b[4]!, 6) ^ rotr(b[4]!, 11) ^ rotr(b[4]!, 25);
        const ch = (b[4]! & b[5]!) ^ (~b[4]! & b[6]!);
        b[7] = u32(t1 - s1 - ch - SHACAL2_K[i]! - w[i]!);
      }
      for (let i = 0; i < 8; i++) storeBE(b[i]!, dst, i * 4);
    },
  };
}

// ──────────────────────────────────────────────────────────── GOST 28147-89

/**
 * GOST 28147-89: the Soviet standard, 64-bit block, 256-bit key, 32 Feistel rounds.
 *
 * Magma (GOST R 34.12-2015) is this cipher with one fixed S-box set and the bytes written the other way
 * round; the 1989 standard leaves the S-boxes as a *parameter*, which is the whole difficulty of
 * interoperating with it. Two implementations of "GOST" agreeing on nothing is normal, and it is always
 * the S-boxes.
 *
 * **The S-boxes are the ones already in this repo.** `gost.ts` carries the D-Test and CryptoPro sets
 * because GOST R 34.11-94 -- the hash -- is built on this cipher, so nothing new is stored here. That
 * reuse is also a check: those two tables are already pinned by the hash's published vectors, so a
 * cipher vector that fails points at the Feistel network rather than at 128 nibbles.
 *
 * The key schedule is the simplest here: the 256-bit key is eight 32-bit subkeys used in order three
 * times and then in reverse. No expansion, no constants.
 */
export type GostCipherSbox = "test" | "crypto";

export function createGost28147(key: Uint8Array, sbox: GostCipherSbox = "test"): BlockCipher {
  if (key.length !== 32) {
    throw new Error(`GOST 28147-89's key is exactly 32 bytes; this one is ${key.length}.`);
  }
  const table = gostSubstitution(sbox);
  // Little-endian subkeys, which is the convention the 1989 standard and every implementation uses.
  const k = Array.from({ length: 8 }, (_, i) => loadLE(key, i * 4));

  /** f: add the subkey mod 2^32, substitute each nibble, rotate left 11. */
  const f = (value: number, subkey: number): number => {
    const x = u32(value + subkey);
    let out = 0;
    for (let i = 0; i < 8; i++) {
      out = u32(out | (table[i]![(x >>> (4 * i)) & 0xf]! << (4 * i)));
    }
    return rotl(out, 11);
  };

  const run = (src: Uint8Array, dst: Uint8Array, forward: boolean): void => {
    let n1 = loadLE(src, 0);
    let n2 = loadLE(src, 4);
    for (let round = 0; round < 32; round++) {
      /**
       * The subkey order, and it is not symmetrical.
       *
       * Encryption uses the eight subkeys in order three times, then in reverse once. Decryption is
       * that sequence read backwards, which is *not* the same as "in reverse three times then in
       * order" -- getting it wrong gives a cipher that decrypts its own output and nothing else's.
       */
      const step = forward ? round : 31 - round;
      const index = step < 24 ? step % 8 : 7 - (step % 8);
      const next = u32(n2 ^ f(n1, k[index]!));
      n2 = n1;
      n1 = next;
    }
    // The final swap is omitted, which is what the standard specifies: the output is N1 || N2 with the
    // halves as they stand after the last round rather than exchanged.
    storeLE(n2, dst, 0);
    storeLE(n1, dst, 4);
  };

  return {
    blockSize: 8,
    encryptBlock: (src, dst) => run(src, dst, true),
    decryptBlock: (src, dst) => run(src, dst, false),
  };
}

/**
 * The substitution table, borrowed from the hash's own module rather than restated.
 *
 * Imported lazily through a function so this file does not depend on `gost.ts`'s module-level table
 * construction order -- and typed as nibble rows because that is what the standard publishes and what
 * `gost.ts` stores.
 */
function gostSubstitution(which: GostCipherSbox): readonly (readonly number[])[] {
  return which === "crypto" ? GOST_SBOX_CRYPTO : GOST_SBOX_TEST;
}

/**
 * The two published parameter sets, as the eight rows of sixteen nibbles the standards print.
 *
 * These are the same values `gost.ts` holds for the hash. They are repeated here rather than exported
 * from there for one reason: `gost.ts` folds them into 1 KB of precomputed rotated words at module
 * load, and what this cipher needs is the nibbles. Sharing the *derived* table would mean sharing the
 * hash's 11-bit rotation, which the cipher applies at a different point. The test asserts the two
 * copies are identical, which is the arrangement `outputLen` and the CRC tags already use.
 */
const GOST_SBOX_TEST: readonly (readonly number[])[] = [
  [0x4, 0xa, 0x9, 0x2, 0xd, 0x8, 0x0, 0xe, 0x6, 0xb, 0x1, 0xc, 0x7, 0xf, 0x5, 0x3],
  [0xe, 0xb, 0x4, 0xc, 0x6, 0xd, 0xf, 0xa, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9],
  [0x5, 0x8, 0x1, 0xd, 0xa, 0x3, 0x4, 0x2, 0xe, 0xf, 0xc, 0x7, 0x6, 0x0, 0x9, 0xb],
  [0x7, 0xd, 0xa, 0x1, 0x0, 0x8, 0x9, 0xf, 0xe, 0x4, 0x6, 0xc, 0xb, 0x2, 0x5, 0x3],
  [0x6, 0xc, 0x7, 0x1, 0x5, 0xf, 0xd, 0x8, 0x4, 0xa, 0x9, 0xe, 0x0, 0x3, 0xb, 0x2],
  [0x4, 0xb, 0xa, 0x0, 0x7, 0x2, 0x1, 0xd, 0x3, 0x6, 0x8, 0x5, 0x9, 0xc, 0xf, 0xe],
  [0xd, 0xb, 0x4, 0x1, 0x3, 0xf, 0x5, 0x9, 0x0, 0xa, 0xe, 0x7, 0x6, 0x8, 0x2, 0xc],
  [0x1, 0xf, 0xd, 0x0, 0x5, 0x7, 0xa, 0x4, 0x9, 0x2, 0x3, 0xe, 0x6, 0xb, 0x8, 0xc],
];

const GOST_SBOX_CRYPTO: readonly (readonly number[])[] = [
  [0xa, 0x4, 0x5, 0x6, 0x8, 0x1, 0x3, 0x7, 0xd, 0xc, 0xe, 0x0, 0x9, 0x2, 0xb, 0xf],
  [0x5, 0xf, 0x4, 0x0, 0x2, 0xd, 0xb, 0x9, 0x1, 0x7, 0x6, 0x3, 0xc, 0xe, 0xa, 0x8],
  [0x7, 0xf, 0xc, 0xe, 0x9, 0x4, 0x1, 0x0, 0x3, 0xb, 0x5, 0x2, 0x6, 0xa, 0x8, 0xd],
  [0x4, 0xa, 0x7, 0xc, 0x0, 0xf, 0x2, 0x8, 0xe, 0x1, 0x6, 0x5, 0xd, 0xb, 0x9, 0x3],
  [0x7, 0x6, 0x4, 0xb, 0x9, 0xc, 0x2, 0xa, 0x1, 0x8, 0x0, 0xe, 0xf, 0xd, 0x3, 0x5],
  [0x7, 0x6, 0x2, 0x4, 0xd, 0x9, 0xf, 0x0, 0xa, 0x1, 0x5, 0xb, 0x8, 0xe, 0xc, 0x3],
  [0xd, 0xe, 0x4, 0x1, 0x7, 0x0, 0x5, 0xa, 0x3, 0xc, 0x8, 0xf, 0x6, 0x2, 0x9, 0xb],
  [0x1, 0x3, 0xa, 0x9, 0x5, 0xb, 0x4, 0xf, 0x8, 0x6, 0x7, 0xe, 0xd, 0x0, 0x2, 0xc],
];

/** Exported for the test that requires these to still match the hash module's copies. */
export const GOST_CIPHER_SBOXES = { test: GOST_SBOX_TEST, crypto: GOST_SBOX_CRYPTO };
