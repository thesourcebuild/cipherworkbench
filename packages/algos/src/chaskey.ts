/**
 * Chaskey-LTS, the block cipher underneath the ISO/IEC 29192-6 lightweight MAC.
 *
 * `modern`. Chaskey itself -- the MAC -- runs eight rounds; **LTS is "long term security", the same
 * permutation at sixteen**, proposed by the designers after a differential-linear attack reached seven
 * of the eight. So this tool is the conservative member of the pair, and the round count is the whole
 * difference between them.
 *
 * It is the only **Even-Mansour** construction in this repo: there is no key schedule at all, just the
 * key XORed in before the permutation and again after. That is the cheapest possible way to turn a
 * permutation into a block cipher, and it is why Chaskey is a MAC rather than a cipher in its intended
 * use -- what this tool exposes is the primitive underneath.
 *
 * Three things to preserve.
 *
 * **The permutation is a bare ARX quarter-round with no constants.** Four 32-bit words, add-rotate-xor,
 * and *nothing* else -- no round constant, no counter, no S-box. So all sixteen rounds are identical,
 * which is safe here only because Even-Mansour's whitening is what breaks the symmetry; a permutation
 * used this way needs no round separation.
 *
 * **The words are little-endian.** Chaskey reads and writes least significant byte first, which is
 * unusual among the ciphers here and is what the published vectors assume.
 *
 * **The inverse is not the forward round read backwards.** Each step's three operations undo in reverse
 * order *and* the two halves of the round swap which one goes first -- so `v[2]` un-rotates before
 * `v[1]` un-xors, where the forward direction has them the other way round. Writing one from the other
 * by hand is the usual way a decrypt path ends up self-consistent and wrong.
 *
 * No oracle -- OpenSSL has never implemented Chaskey. What stands behind it is the vector FELICS's
 * benchmarking suite carries, checked in both directions.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 16;
/** Sixteen for LTS, where the MAC's permutation runs eight. */
const ROUNDS = 16;

const u32 = (x: number): number => x >>> 0;
const rotl = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));
const rotr = (x: number, n: number): number => u32((x >>> n) | (x << (32 - n)));

const load = (bytes: Uint8Array, i: number): number =>
  u32(bytes[4 * i]! | (bytes[4 * i + 1]! << 8) | (bytes[4 * i + 2]! << 16) | (bytes[4 * i + 3]! << 24));

function store(word: number, out: Uint8Array, i: number): void {
  out[4 * i] = word & 0xff;
  out[4 * i + 1] = (word >>> 8) & 0xff;
  out[4 * i + 2] = (word >>> 16) & 0xff;
  out[4 * i + 3] = (word >>> 24) & 0xff;
}

/** One round of the Chaskey permutation, in place. */
function permuteRound(v: number[]): void {
  v[0] = u32(v[0]! + v[1]!);
  v[1] = rotl(v[1]!, 5);
  v[1] = u32(v[1]! ^ v[0]!);
  v[0] = rotl(v[0]!, 16);

  v[2] = u32(v[2]! + v[3]!);
  v[3] = rotl(v[3]!, 8);
  v[3] = u32(v[3]! ^ v[2]!);

  v[0] = u32(v[0]! + v[3]!);
  v[3] = rotl(v[3]!, 13);
  v[3] = u32(v[3]! ^ v[0]!);

  v[2] = u32(v[2]! + v[1]!);
  v[1] = rotl(v[1]!, 7);
  v[1] = u32(v[1]! ^ v[2]!);
  v[2] = rotl(v[2]!, 16);
}

/** And its inverse. Note the two halves swap order, which is what makes this not a mirror image. */
function inverseRound(v: number[]): void {
  v[2] = rotr(v[2]!, 16);
  v[1] = u32(v[1]! ^ v[2]!);
  v[1] = rotr(v[1]!, 7);
  v[2] = u32(v[2]! - v[1]!);

  v[3] = u32(v[3]! ^ v[0]!);
  v[3] = rotr(v[3]!, 13);
  v[0] = u32(v[0]! - v[3]!);

  v[3] = u32(v[3]! ^ v[2]!);
  v[3] = rotr(v[3]!, 8);
  v[2] = u32(v[2]! - v[3]!);

  v[0] = rotr(v[0]!, 16);
  v[1] = u32(v[1]! ^ v[0]!);
  v[1] = rotr(v[1]!, 5);
  v[0] = u32(v[0]! - v[1]!);
}

/** Chaskey-LTS as a `BlockCipher`. Key and block are both 128 bits. */
export function createChaskeyLts(key: Uint8Array): BlockCipher {
  if (key.length !== BLOCK) {
    throw new Error(`Chaskey-LTS's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  const k = [0, 1, 2, 3].map((i) => load(key, i));

  const run = (src: Uint8Array, dst: Uint8Array, inverse: boolean): void => {
    const v = [0, 1, 2, 3].map((i) => u32(load(src, i) ^ k[i]!));
    for (let r = 0; r < ROUNDS; r++) {
      if (inverse) inverseRound(v);
      else permuteRound(v);
    }
    for (let i = 0; i < 4; i++) store(u32(v[i]! ^ k[i]!), dst, i);
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => run(src, dst, false),
    decryptBlock: (src, dst) => run(src, dst, true),
  };
}

function doubleSubkey(k: number[]): number[] {
  const msb = (k[3]! >>> 31) & 1;
  const out = [
    u32((k[0]! << 1) | (k[1]! >>> 31)),
    u32((k[1]! << 1) | (k[2]! >>> 31)),
    u32((k[2]! << 1) | (k[3]! >>> 31)),
    u32(k[3]! << 1),
  ];
  if (msb) out[0] = u32(out[0]! ^ 0x87);
  return out;
}

/**
 * Computes Chaskey MAC (ISO/IEC 29192-6).
 *
 * @param rounds Number of permutation rounds (8 for standard Chaskey, 16 for Chaskey-LTS).
 */
export function chaskeyMac(key: Uint8Array, message: Uint8Array, rounds: 8 | 16 = 8): Uint8Array {
  if (key.length !== BLOCK) throw new Error("Chaskey MAC key must be 16 bytes.");
  const k = [0, 1, 2, 3].map((i) => load(key, i));
  const k1 = doubleSubkey(k);
  const k2 = doubleSubkey(k1);

  const v = [...k];
  const fullBlocks = Math.floor(message.length / BLOCK);
  const remaining = message.length % BLOCK;
  const isPadded = remaining !== 0 || message.length === 0;
  const numBlocks = isPadded ? fullBlocks + 1 : fullBlocks;

  for (let b = 0; b < numBlocks - 1; b++) {
    for (let i = 0; i < 4; i++) {
      v[i] = u32(v[i]! ^ load(message.subarray(b * BLOCK), i));
    }
    for (let r = 0; r < rounds; r++) permuteRound(v);
  }

  // Last block
  const lastBlock = new Uint8Array(BLOCK);
  if (isPadded) {
    if (remaining > 0) {
      lastBlock.set(message.subarray(fullBlocks * BLOCK));
    }
    lastBlock[remaining] = 0x01; // pad with 0x01 followed by 0x00
    for (let i = 0; i < 4; i++) {
      const mWord = load(lastBlock, i);
      v[i] = u32(v[i]! ^ mWord ^ k2[i]!);
    }
  } else {
    for (let i = 0; i < 4; i++) {
      const mWord = load(message.subarray((numBlocks - 1) * BLOCK), i);
      v[i] = u32(v[i]! ^ mWord ^ k1[i]!);
    }
  }

  for (let r = 0; r < rounds; r++) permuteRound(v);

  const tag = new Uint8Array(BLOCK);
  for (let i = 0; i < 4; i++) {
    store(u32(v[i]! ^ k[i]!), tag, i);
  }
  return tag;
}

