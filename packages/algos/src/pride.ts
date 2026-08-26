/**
 * PRIDE, the lightweight cipher built for a *linear layer* rather than around one (Albrecht, Driessen,
 * Kavun, Leander, Paar and Yalcin, CRYPTO 2014).
 *
 * `legacy`. No break of the full 20 rounds, but differential attacks reach 19 and related-key work
 * reaches the full cipher, so it is here to reproduce values.
 *
 * Its contribution is the reason to have it: PRIDE's authors searched for the best *linear layer* that a
 * bit-sliced 8-bit-microcontroller implementation could afford, and built the cipher round it -- the
 * opposite order from every other design in this family, which pick a permutation and accept the software
 * cost. The result is four different linear maps, L0 to L3, applied to four different byte pairs, where an
 * SPN would apply one matrix to everything.
 *
 * Four things to preserve.
 *
 * **The state is bit-sliced across eight bytes and the S-box is an involution.** `substitute` is sixteen
 * AND-and-XOR operations over the eight bytes, and applying it twice is the identity -- which is asserted
 * at load, and which is why decryption reuses it rather than needing an inverse.
 *
 * **L0 and L3 are involutions; L1 and L2 are not.** So `linearInverse` is `L0, L1inv, L2inv, L3` -- two
 * of the four reused and two written out. Assuming all four invert themselves gives a cipher whose
 * encryption is correct and whose decryption is not.
 *
 * **There is no key schedule.** The 128-bit key is two halves: the first whitens at both ends, unchanged,
 * and the second is the round key for every round -- with a *round constant added to its odd bytes*, which
 * is the only thing distinguishing one round from the next. And it is added, not XORed.
 *
 * **The last round has no linear layer**, and the round key before it uses the final four constants rather
 * than continuing the sequence. That is 19 full rounds plus a key add plus a bare substitution.
 *
 * No oracle -- OpenSSL has never implemented PRIDE. What stands behind it is the vectors FELICS's
 * benchmarking suite carries, checked in both directions.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
const KEY = 16;
const ROUNDS = 20;

/**
 * Eighty round constants, four per round.
 *
 * They are the specification's own table and there is nothing to derive them from -- but note that they
 * are *added* to the odd state bytes rather than XORed, which is unusual enough to be worth stating twice.
 */
const ROUND_CONSTANTS = Uint8Array.from(
  (
    "c1a551c5824aa28a43eff34f04944414c53995d986dee69e4783376308288828" +
    "c9cdd9ed8a722ab24b177b770cbccc3ccd611d018e066ec64fabbf8b10501050" +
    "d1f56115929ab2da533f039f14e45464"
  )
    .match(/../g)!
    .map((p) => parseInt(p, 16)),
);

const swapNibbles = (x: number): number => ((x >> 4) ^ (x << 4)) & 0xff;
const rotl8 = (x: number): number => ((x << 1) ^ (x >> 7)) & 0xff;
const rotr8 = (x: number): number => ((x >> 1) ^ (x << 7)) & 0xff;

/** The bit-sliced S-box, which is its own inverse. */
function substitute(s: number[]): void {
  const t = [s[0]!, s[1]!, s[2]!, s[3]!];
  s[0] = (s[0]! & s[2]!) ^ s[4]!;
  s[2] = (s[2]! & s[4]!) ^ s[6]!;
  s[1] = (s[1]! & s[3]!) ^ s[5]!;
  s[3] = (s[3]! & s[5]!) ^ s[7]!;
  s[4] = s[0]!;
  s[5] = s[1]!;
  s[6] = s[2]!;
  s[7] = s[3]!;
  s[4] = (s[4]! & s[6]!) ^ t[0]!;
  s[6] = (s[6]! & s[4]!) ^ t[2]!;
  s[5] = (s[5]! & s[7]!) ^ t[1]!;
  s[7] = (s[7]! & s[5]!) ^ t[3]!;
  for (let i = 0; i < 8; i++) s[i] = s[i]! & 0xff;
}

{
  // The involution property, checked rather than trusted: it is what lets decryption reuse the function.
  const probe = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
  const copy = probe.slice();
  substitute(copy);
  substitute(copy);
  if (copy.join(",") !== probe.join(",")) throw new Error("PRIDE's S-box is not an involution.");
}

/** L0 and L3, each its own inverse, over bytes `at` and `at + 1`. */
function involutiveLinear(s: number[], at: number, swapBoth: boolean): void {
  const t0 = s[at]!;
  const t1 = s[at + 1]!;
  s[at] = swapNibbles(s[at]!);
  s[at + 1] = swapNibbles(s[at + 1]!);
  s[at] = s[at]! ^ s[at + 1]!;
  if (swapBoth) {
    // L3: the second byte takes the accumulated value.
    s[at + 1] = (t1 ^ s[at]!) & 0xff;
    s[at] = (s[at]! ^ t0) & 0xff;
  } else {
    // L0: the first does.
    const acc = (t0 ^ s[at]!) & 0xff;
    s[at + 1] = acc;
    s[at] = (s[at]! ^ t1) & 0xff;
  }
}

/** L1 and L2, which share a shape and differ in where the nibble swap sits. */
function shiftLinear(s: number[], at: number, swapFirst: boolean): void {
  if (swapFirst) s[at] = swapNibbles(s[at]!);
  else s[at + 1] = swapNibbles(s[at + 1]!);
  const a = rotl8(s[at]!);
  const b = rotr8(s[at + 1]!);
  s[at] = (s[at]! ^ b) & 0xff;
  const carried = s[at]!;
  s[at] = (s[at]! ^ a) & 0xff;
  s[at + 1] = (s[at + 1]! ^ carried) & 0xff;
}

function shiftLinearInverse(s: number[], at: number, swapFirst: boolean): void {
  const a = rotr8(s[at]!);
  let b = rotr8(s[at + 1]!);
  b = (b ^ a) & 0xff;
  if (swapFirst) {
    s[at + 1] = (s[at + 1]! ^ b) & 0xff;
    s[at] = rotr8(b) ^ a;
    s[at] = swapNibbles(s[at]! & 0xff);
  } else {
    s[at + 1] = (s[at + 1]! ^ b) & 0xff;
    s[at + 1] = swapNibbles(s[at + 1]!);
    s[at] = (rotr8(b) ^ a) & 0xff;
  }
}

const linear = (s: number[]): void => {
  involutiveLinear(s, 0, false);
  shiftLinear(s, 2, false);
  shiftLinear(s, 4, true);
  involutiveLinear(s, 6, true);
};

const linearInverse = (s: number[]): void => {
  involutiveLinear(s, 0, false);
  shiftLinearInverse(s, 2, false);
  shiftLinearInverse(s, 4, true);
  involutiveLinear(s, 6, true);
};

/** PRIDE as a `BlockCipher`. */
export function createPride(key: Uint8Array): BlockCipher {
  if (key.length !== KEY) {
    throw new Error(`PRIDE's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  const whitening = key.subarray(0, 8);
  const roundKey = key.subarray(8, 16);

  /** The round key, with four constants *added* to the odd bytes. */
  const addRoundKey = (s: number[], at: number): void => {
    for (let i = 0; i < 4; i++) {
      s[2 * i] = (s[2 * i]! ^ roundKey[2 * i]!) & 0xff;
      s[2 * i + 1] = (s[2 * i + 1]! ^ ((roundKey[2 * i + 1]! + ROUND_CONSTANTS[at + i]!) & 0xff)) & 0xff;
    }
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      const s = Array.from(src.subarray(0, BLOCK));
      for (let i = 0; i < BLOCK; i++) s[i] = s[i]! ^ whitening[i]!;
      for (let round = 0; round < ROUNDS - 1; round++) {
        addRoundKey(s, round * 4);
        substitute(s);
        linear(s);
      }
      addRoundKey(s, (ROUNDS - 1) * 4);
      substitute(s);
      for (let i = 0; i < BLOCK; i++) s[i] = (s[i]! ^ whitening[i]!) & 0xff;
      dst.set(s);
    },
    decryptBlock: (src, dst) => {
      const s = Array.from(src.subarray(0, BLOCK));
      for (let i = 0; i < BLOCK; i++) s[i] = s[i]! ^ whitening[i]!;
      substitute(s);
      addRoundKey(s, (ROUNDS - 1) * 4);
      for (let round = ROUNDS - 2; round >= 0; round--) {
        linearInverse(s);
        substitute(s);
        addRoundKey(s, round * 4);
      }
      for (let i = 0; i < BLOCK; i++) s[i] = (s[i]! ^ whitening[i]!) & 0xff;
      dst.set(s);
    },
  };
}
