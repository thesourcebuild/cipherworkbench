/**
 * SPARX-64/128, the first ARX design with **provable** bounds against differential and linear
 * cryptanalysis (Dinu, Perrin, Udovenko, Velichkov, Grossschadl and Biryukov, ASIACRYPT 2016).
 *
 * `modern`: no attack on the full cipher. Its interest is methodological rather than practical, and it
 * is the reason to have it beside Simon, Speck and CHAM. Every other ARX cipher here rests on an
 * *argument* that its round function diffuses well; SPARX was built by the "long trail strategy" so that
 * the bound could be computed the way an S-box-based SPN's can. It is what you point at when someone
 * asks why ARX designs usually cannot prove what AES-like ones prove.
 *
 * The structure is an SPN whose S-box is **Speck's round function on 32 bits** -- `speckey` below -- and
 * whose linear layer is a Feistel-ish mix of the two 32-bit branches. Three of those ARX steps make one
 * "step"; eight steps make the cipher. So there are no tables, and the only constants are the round
 * numbers the key schedule adds.
 *
 * Three things to preserve.
 *
 * **Everything is little-endian, at both widths.** The block is two 32-bit words read least significant
 * byte first, and each is split into two 16-bit halves the same way -- so the low half of the low word is
 * byte 0. Reading either level big-endian gives a cipher that is entirely self-consistent and reproduces
 * nothing.
 *
 * **The key schedule is 16-bit and the cipher is 32-bit.** The schedule produces six 16-bit words per
 * iteration over sixteen iterations; encryption consumes them as six *32-bit* words per step over eight
 * steps. Those are the same 96 words viewed at two widths, which is why the schedule's loop bound is
 * twice the step count -- and reading the schedule at 32 bits gives half a key.
 *
 * **The round counter enters the schedule, not the cipher.** `temp[1] + i` is the only constant in the
 * whole design; there is no round-constant table anywhere.
 *
 * No oracle -- OpenSSL has never implemented SPARX. What stands behind it is the two vectors FELICS's
 * benchmarking suite carries, at an all-zero and an all-ones key, checked in both directions.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
const KEY = 16;
/** Eight steps of three ARX rounds per branch. */
const STEPS = 8;

const u32 = (x: number): number => x >>> 0;
const u16 = (x: number): number => x & 0xffff;
const rotl32 = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));
const rotr32 = (x: number, n: number): number => u32((x >>> n) | (x << (32 - n)));
const rotl16 = (x: number, n: number): number => u16((x << n) | (x >>> (16 - n)));
const rotr16 = (x: number, n: number): number => u16((x >>> n) | (x << (16 - n)));

/** Speck's round function on a 32-bit branch, which is SPARX's S-box. */
function speckey(left: number, right: number): [number, number] {
  let l = rotr16(left, 7);
  l = u16(l + right);
  let r = rotl16(right, 2);
  r = u16(r ^ l);
  return [l, r];
}

/** And its inverse. */
function speckeyInverse(left: number, right: number): [number, number] {
  let r = u16(right ^ left);
  r = rotr16(r, 2);
  let l = u16(left - r);
  l = rotl16(l, 7);
  return [l, r];
}

/** The 50 round-key words, as little-endian 32-bit pairs of the schedule's 100 16-bit words. */
function schedule(key: Uint8Array): number[] {
  const k: number[] = [];
  for (let i = 0; i < 8; i++) k.push(u16(key[2 * i]! | (key[2 * i + 1]! << 8)));

  const rk = new Array<number>(100).fill(0);
  for (let i = 0; i < 6; i++) rk[i] = k[i]!;
  let t0 = k[6]!;
  let t1 = k[7]!;
  for (let i = 1; i < 2 * STEPS; i++) {
    rk[6 * i] = t0;
    rk[6 * i + 1] = u16(t1 + i);
    [t0, t1] = speckey(rk[6 * (i - 1)]!, rk[6 * (i - 1) + 1]!);
    rk[6 * i + 2] = t0;
    rk[6 * i + 3] = t1;
    rk[6 * i + 4] = u16(t0 + rk[6 * (i - 1) + 2]!);
    rk[6 * i + 5] = u16(t1 + rk[6 * (i - 1) + 3]!);
    t0 = rk[6 * (i - 1) + 4]!;
    t1 = rk[6 * (i - 1) + 5]!;
  }
  const last = 6 * 2 * STEPS;
  rk[last] = t0;
  rk[last + 1] = u16(t1 + 2 * STEPS);
  [t0, t1] = speckey(rk[6 * (2 * STEPS - 1)]!, rk[6 * (2 * STEPS - 1) + 1]!);
  rk[last + 2] = t0;
  rk[last + 3] = t1;

  const wide: number[] = [];
  for (let i = 0; i < 50; i++) wide.push(u32(rk[2 * i]! | (rk[2 * i + 1]! << 16)));
  return wide;
}

const load = (bytes: Uint8Array, i: number): number =>
  u32(bytes[4 * i]! | (bytes[4 * i + 1]! << 8) | (bytes[4 * i + 2]! << 16) | (bytes[4 * i + 3]! << 24));

function store(word: number, out: Uint8Array, i: number): void {
  out[4 * i] = word & 0xff;
  out[4 * i + 1] = (word >>> 8) & 0xff;
  out[4 * i + 2] = (word >>> 16) & 0xff;
  out[4 * i + 3] = (word >>> 24) & 0xff;
}

/** Three ARX rounds over one branch, each preceded by a key XOR. */
function branchForward(word: number, keys: readonly number[]): number {
  let value = word;
  for (const k of keys) {
    const mixed = u32(value ^ k);
    const [lo, hi] = speckey(u16(mixed & 0xffff), u16(mixed >>> 16));
    value = u32((hi << 16) | lo);
  }
  return value;
}

function branchInverse(word: number, keys: readonly number[]): number {
  let value = word;
  for (let i = keys.length - 1; i >= 0; i--) {
    const [lo, hi] = speckeyInverse(u16(value & 0xffff), u16(value >>> 16));
    value = u32((u32((hi << 16) | lo)) ^ keys[i]!);
  }
  return value;
}

/** SPARX-64/128 as a `BlockCipher`. */
export function createSparx(key: Uint8Array): BlockCipher {
  if (key.length !== KEY) {
    throw new Error(`SPARX-64/128's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  const rk = schedule(key);

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      let left = load(src, 0);
      let right = load(src, 1);
      for (let s = 0; s < STEPS; s++) {
        left = branchForward(left, [rk[6 * s]!, rk[6 * s + 1]!, rk[6 * s + 2]!]);
        right = branchForward(right, [rk[6 * s + 3]!, rk[6 * s + 4]!, rk[6 * s + 5]!]);
        // The linear layer, which also swaps the branches.
        const previous = left;
        right = u32(right ^ left ^ rotl32(left, 8) ^ rotr32(left, 8));
        left = right;
        right = previous;
      }
      store(u32(left ^ rk[6 * STEPS]!), dst, 0);
      store(u32(right ^ rk[6 * STEPS + 1]!), dst, 1);
    },
    decryptBlock: (src, dst) => {
      let left = u32(load(src, 0) ^ rk[6 * STEPS]!);
      let right = u32(load(src, 1) ^ rk[6 * STEPS + 1]!);
      for (let s = STEPS - 1; s >= 0; s--) {
        // Undo the swap first, then the mix -- `left` after the step held the mixed value.
        const mixed = left;
        left = right;
        right = u32(mixed ^ left ^ rotl32(left, 8) ^ rotr32(left, 8));
        left = branchInverse(left, [rk[6 * s]!, rk[6 * s + 1]!, rk[6 * s + 2]!]);
        right = branchInverse(right, [rk[6 * s + 3]!, rk[6 * s + 4]!, rk[6 * s + 5]!]);
      }
      store(left, dst, 0);
      store(right, dst, 1);
    },
  };
}
