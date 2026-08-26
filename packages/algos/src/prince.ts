/**
 * PRINCE, the low-latency block cipher (Borghoff et al., ASIACRYPT 2012).
 *
 * `legacy`. There is no break of the full twelve rounds, but the design's own claim is only 126 - n bits
 * of security against an attacker with 2^n plaintexts, and biclique and meet-in-the-middle results sit
 * close to that -- so it does not get `modern`. PRINCE-v2 exists and changes the key schedule, which is a
 * different cipher; this is the original, which is what every published vector uses.
 *
 * It is here for one property that nothing else in this repo has: **alpha-reflection**. Decryption is
 * encryption under a key derived by swapping two words and XORing a single 64-bit constant, so a hardware
 * implementation gets the inverse for the cost of one XOR. That is why PRINCE exists -- single-cycle
 * decryption in the same circuit -- and it is what makes the decrypt path here three lines instead of a
 * mirror image of the encrypt path.
 *
 * Four things to preserve.
 *
 * **The middle is not a round.** Five forward rounds, then substitute, mix, and substitute *back*, then
 * five inverse rounds. That middle sandwich is what makes the cipher an involution up to the key, and it
 * is where an implementation written as "twelve identical rounds" goes wrong.
 *
 * **`M'` is four 4-by-4 binary matrices in disguise.** Every reference writes the mix layer as
 * AND-with-a-mask then XOR, over the four masks 0x7, 0xb, 0xd, 0xe -- each of which drops one bit. That
 * *is* the matrix product for a matrix whose blocks zero one bit each, and the two arrangements M0 and M1
 * differ only by rotating which mask starts the row. Reading it as arithmetic rather than as a matrix is
 * what makes it short.
 *
 * **`M` is `M'` followed by ShiftRows, and the middle layer uses `M'` alone.** Using the full `M` in the
 * middle breaks the reflection while leaving the cipher perfectly invertible against itself.
 *
 * **`k0'` is a one-bit rotation, not a shift.** `(k0 >>> 1) ^ (k0 >> 63)` over the whole 64-bit word --
 * so the bit that falls off the bottom comes back at the top *and* is XORed into the low bit. Both halves
 * of that matter, and dropping the second is right for every key whose last bit is zero.
 *
 * No oracle -- OpenSSL has never implemented PRINCE. What stands behind it is the six vectors from the
 * paper's appendix, as carried by FELICS's benchmarking suite, each checked in both directions.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
const KEY = 16;

/** The 4-bit S-box and its inverse, both as the specification tabulates them. */
const SBOX = [0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4] as const;
const SBOX_INVERSE = [0xb, 0x7, 0x3, 0x2, 0xf, 0xd, 0x8, 0x9, 0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1] as const;

{
  // Each must invert the other; a mistyped entry would leave the middle layer subtly asymmetric.
  for (let i = 0; i < 16; i++) {
    if (SBOX_INVERSE[SBOX[i]!] !== i) throw new Error("PRINCE's S-box pair does not invert.");
  }
}

/**
 * The twelve 64-bit round constants.
 *
 * Stored in the *reference's* byte order, which writes each 64-bit value least significant byte first --
 * the same convention the block uses here. The paper prints the second constant as `13198a2e03707344`
 * and it appears below as `447370032e8a1913`; those are the same number.
 *
 * `RC[0]` is zero and `RC[i] ^ RC[11 - i]` is the same value for every `i` -- that value is alpha, and
 * that identity *is* the alpha-reflection property. The tests assert it rather than trusting it, because
 * a single wrong byte here breaks decryption while leaving encryption reproducing its own output.
 */
const ROUND_CONSTANTS: readonly Uint8Array[] = [
  "0000000000000000",
  "447370032e8a1913",
  "d0319f29223809a4",
  "896c4eec98fa2e08",
  "7713d038e6212845",
  "6c0ce934cf6654be",
  "b15c95fd784ff87e",
  "aa43acf151088485",
  "543c32252fd382c8",
  "0d61e3e09511a564",
  "99230cca99a3b5d3",
  "dd507cc9b729acc0",
].map((hex) => Uint8Array.from(hex.match(/../g)!.map((p) => parseInt(p, 16))));

/** Alpha, which is also `RC[11]`. Decryption XORs it into `k1`. */
const ALPHA = ROUND_CONSTANTS[11]!;

const substitute = (b: Uint8Array, box: readonly number[]): void => {
  for (let i = 0; i < BLOCK; i++) b[i] = ((box[b[i]! >> 4]! << 4) ^ box[b[i]! & 0xf]!) & 0xff;
};

/** The four masks the mix layer is built from: each drops one bit of a nibble. */
const MASKS = [0x7, 0xb, 0xd, 0xe] as const;

/**
 * One 16-bit block of the mix layer, over two bytes.
 *
 * `offset` selects M0 or M1: the masks are read starting one position along, which is the whole
 * difference between the two arrangements.
 */
function mixPair(b: Uint8Array, at: number, offset: number): void {
  const nibbles = [(b[at + 1]! >> 4) & 0xf, b[at + 1]! & 0xf, (b[at]! >> 4) & 0xf, b[at]! & 0xf];
  const out = [0, 0, 0, 0];
  for (let row = 0; row < 4; row++) {
    let value = 0;
    for (let col = 0; col < 4; col++) value ^= MASKS[(row + col + offset) % 4]! & nibbles[col]!;
    out[row] = value & 0xf;
  }
  b[at + 1] = ((out[0]! << 4) ^ out[1]!) & 0xff;
  b[at] = ((out[2]! << 4) ^ out[3]!) & 0xff;
}

/** `M'`: M0 on the outer pairs, M1 on the inner two. */
function mix(b: Uint8Array): void {
  mixPair(b, 6, 0);
  mixPair(b, 4, 1);
  mixPair(b, 2, 1);
  mixPair(b, 0, 0);
}

/** ShiftRows over the nibble matrix, and its inverse. */
function shiftRows(b: Uint8Array): void {
  const o = Uint8Array.from(b);
  b[7] = (o[7]! & 0xf0) ^ (o[5]! & 0x0f);
  b[5] = (o[5]! & 0xf0) ^ (o[3]! & 0x0f);
  b[3] = (o[3]! & 0xf0) ^ (o[1]! & 0x0f);
  b[1] = (o[1]! & 0xf0) ^ (o[7]! & 0x0f);
  b[0] = (o[4]! & 0xf0) ^ (o[2]! & 0x0f);
  b[2] = (o[6]! & 0xf0) ^ (o[4]! & 0x0f);
  b[4] = (o[0]! & 0xf0) ^ (o[6]! & 0x0f);
  b[6] = (o[2]! & 0xf0) ^ (o[0]! & 0x0f);
}

function shiftRowsInverse(b: Uint8Array): void {
  const o = Uint8Array.from(b);
  b[1] = (o[1]! & 0xf0) ^ (o[3]! & 0x0f);
  b[3] = (o[3]! & 0xf0) ^ (o[5]! & 0x0f);
  b[5] = (o[5]! & 0xf0) ^ (o[7]! & 0x0f);
  b[7] = (o[7]! & 0xf0) ^ (o[1]! & 0x0f);
  b[6] = (o[2]! & 0xf0) ^ (o[4]! & 0x0f);
  b[4] = (o[0]! & 0xf0) ^ (o[2]! & 0x0f);
  b[2] = (o[6]! & 0xf0) ^ (o[0]! & 0x0f);
  b[0] = (o[4]! & 0xf0) ^ (o[6]! & 0x0f);
}

/** `k0'`, a one-bit right rotation of the whole 64-bit word. */
function derivePrime(k0: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK);
  for (let i = 0; i < 7; i++) out[i] = (((k0[i + 1]! << 7) & 0x80) ^ (k0[i]! >> 1)) & 0xff;
  out[7] = (((k0[0]! << 7) & 0x80) ^ (k0[7]! >> 1)) & 0xff;
  // And the bit that fell off the bottom comes back into the low byte as well.
  out[0] = out[0]! ^ ((k0[7]! >> 7) & 0x01);
  return out;
}

/** The core, which is the same function in both directions -- only the three key words change. */
function core(block: Uint8Array, whitenIn: Uint8Array, whitenOut: Uint8Array, k1: Uint8Array): Uint8Array {
  const b = Uint8Array.from(block.subarray(0, BLOCK));
  const addRoundKey = (round: number): void => {
    for (let i = 0; i < BLOCK; i++) b[i] = (b[i]! ^ ROUND_CONSTANTS[round]![i]! ^ k1[i]!) & 0xff;
  };

  for (let i = 0; i < BLOCK; i++) b[i] = b[i]! ^ whitenIn[i]!;
  addRoundKey(0);
  for (let round = 1; round < 6; round++) {
    substitute(b, SBOX);
    mix(b);
    shiftRows(b);
    addRoundKey(round);
  }
  // The middle: substitute, mix, substitute back. No shift, and not a round.
  substitute(b, SBOX);
  mix(b);
  substitute(b, SBOX_INVERSE);
  for (let round = 6; round < 11; round++) {
    addRoundKey(round);
    shiftRowsInverse(b);
    mix(b);
    substitute(b, SBOX_INVERSE);
  }
  addRoundKey(11);
  for (let i = 0; i < BLOCK; i++) b[i] = b[i]! ^ whitenOut[i]!;
  return b;
}

/** Exported so a test can assert the alpha-reflection identity the round constants encode. */
export const PRINCE_ROUND_CONSTANTS: readonly Uint8Array[] = ROUND_CONSTANTS;
export const PRINCE_ALPHA: Readonly<Uint8Array> = ALPHA;

/** PRINCE as a `BlockCipher`. The 128-bit key is two 64-bit halves. */
export function createPrince(key: Uint8Array): BlockCipher {
  if (key.length !== KEY) {
    throw new Error(`PRINCE's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  const k0 = key.slice(0, 8);
  const k1 = key.slice(8, 16);
  const k0prime = derivePrime(k0);
  /**
   * Decryption's `k1`, which is the whole of alpha-reflection: swap the two whitening words and XOR
   * alpha into the round key. No inverse schedule, and no inverse core.
   */
  const k1alpha = Uint8Array.from(k1, (b, i) => b ^ ALPHA[i]!);

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => dst.set(core(src, k0, k0prime, k1)),
    decryptBlock: (src, dst) => dst.set(core(src, k0prime, k0, k1alpha)),
  };
}
