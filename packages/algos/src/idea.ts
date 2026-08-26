/**
 * IDEA, from Lai and Massey's 1991 design, over the shared `BlockCipher` interface.
 *
 * PGP 2.x's cipher, and the reason anyone still needs it: a message encrypted with PGP before 1997 is
 * almost certainly IDEA, and nothing else will read it. It was patented until 2012, which is why it
 * never spread further and why OpenSSL keeps it in the legacy provider -- not loaded here, so the
 * check is Bouncy Castle's published vectors.
 *
 * Three things to know.
 *
 * **The non-linearity is multiplication modulo 65537, and zero means 65536.** That convention is the
 * whole cipher: the group being used is the multiplicative group of the prime field GF(65537), whose
 * 65536 elements are represented by the 16-bit words with 0 standing in for 65536. An implementation
 * that treats 0 as 0 produces a cipher that inverts perfectly and matches nothing.
 *
 * **The key schedule is a 25-bit rotation.** The first eight subkeys are the key's own words; then the
 * 128-bit key is rotated left 25 bits and the next eight are read off, and so on for 52 subkeys. 25
 * is chosen because it is coprime to both 16 and 128, so the subkeys do not repeat a bit pattern.
 *
 * **The output transform is not a round, and the halves stay swapped.** Eight rounds each end by
 * exchanging the two middle words; the final transform reads them back in the *unswapped* order,
 * which is the classic off-by-one here -- and the one that produced a near-miss on the first attempt
 * at this file, matching the published vector for five bytes.
 *
 * No tables at all, which puts IDEA in the same small group as Speck and Simon: nothing here could be
 * mistyped, so what the vectors pin down is the arithmetic and the word order.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
const MASK = 0xffff;
const KEY_LEN = 16;
const SUBKEYS = 52;

/** Multiplication in GF(65537), with 0 representing 65536. */
function mul(a: number, b: number): number {
  const x = (a & MASK) === 0 ? 0x10000 : a & MASK;
  const y = (b & MASK) === 0 ? 0x10000 : b & MASK;
  const product = (x * y) % 0x10001;
  return product === 0x10000 ? 0 : product;
}

const add = (a: number, b: number): number => (a + b) & MASK;

/** The multiplicative inverse in GF(65537), for decryption. */
function mulInverse(value: number): number {
  const x = (value & MASK) === 0 ? 0x10000 : value & MASK;
  // Fermat: x^(p-2) mod p. Cheap enough at four calls per block, and avoids an extended-Euclid slip.
  let result = 1;
  let base = x;
  let exponent = 0x10001 - 2;
  while (exponent > 0) {
    if (exponent & 1) result = (result * base) % 0x10001;
    base = (base * base) % 0x10001;
    exponent >>>= 1;
  }
  return result === 0x10000 ? 0 : result;
}

const sub = (a: number, b: number): number => (a - b) & MASK;

/** 52 encryption subkeys: eight from the key, then eight more per 25-bit rotation. */
function encryptionSubkeys(key: Uint8Array): number[] {
  if (key.length !== KEY_LEN) {
    throw new Error(`IDEA's key is 16 bytes; this one is ${key.length}.`);
  }
  let value = 0n;
  for (const byte of key) value = (value << 8n) | BigInt(byte);
  const wrap = (1n << 128n) - 1n;

  const out: number[] = [];
  while (out.length < SUBKEYS) {
    for (let i = 7; i >= 0 && out.length < SUBKEYS; i--) {
      out.push(Number((value >> BigInt(16 * i)) & 0xffffn));
    }
    // 25 is coprime to both 16 and 128, so no bit pattern repeats across the 52 subkeys.
    value = ((value << 25n) | (value >> 103n)) & wrap;
  }
  return out;
}

function run(subkeys: readonly number[], src: Uint8Array, dst: Uint8Array): void {
  let x1 = ((src[0]! << 8) | src[1]!) & MASK;
  let x2 = ((src[2]! << 8) | src[3]!) & MASK;
  let x3 = ((src[4]! << 8) | src[5]!) & MASK;
  let x4 = ((src[6]! << 8) | src[7]!) & MASK;

  let k = 0;
  for (let round = 0; round < 8; round++) {
    x1 = mul(x1, subkeys[k++]!);
    x2 = add(x2, subkeys[k++]!);
    x3 = add(x3, subkeys[k++]!);
    x4 = mul(x4, subkeys[k++]!);

    // The multiplication-addition structure, which is where the two halves interact.
    const t0 = mul(x1 ^ x3, subkeys[k++]!);
    const t1 = mul(add(t0, x2 ^ x4), subkeys[k++]!);
    const t2 = add(t0, t1);
    x1 ^= t1;
    x4 ^= t2;
    const swap = x2 ^ t2;
    x2 = x3 ^ t1;
    x3 = swap;
  }

  // The output transform reads x3 before x2: the last round's exchange is not undone.
  const y = [mul(x1, subkeys[k++]!), add(x3, subkeys[k++]!), add(x2, subkeys[k++]!), mul(x4, subkeys[k++]!)];
  for (let i = 0; i < 4; i++) {
    dst[2 * i] = (y[i]! >>> 8) & 0xff;
    dst[2 * i + 1] = y[i]! & 0xff;
  }
}

/**
 * Decryption by inverting each step, rather than by transforming the schedule.
 *
 * Most implementations build a second set of 52 subkeys -- multiplicative ones inverted, additive ones
 * negated, the whole thing reversed with two positions swapped per round. That table is easy to get
 * subtly wrong and impossible to check without a vector, and it *was* wrong here first: the forward
 * direction reproduced every published vector while the inverse returned noise.
 *
 * Undoing the operations in reverse order needs no table at all. The trick that makes it work is that
 * the multiplication-addition structure can be recovered from its own output: `y1 ^ y2` is
 * `x1' ^ x3'` and `y3 ^ y4` is `x2' ^ x4'`, so `t0`, `t1` and `t2` come straight back out.
 */
function runInverse(subkeys: readonly number[], src: Uint8Array, dst: Uint8Array): void {
  let x1 = ((src[0]! << 8) | src[1]!) & MASK;
  let x2 = ((src[2]! << 8) | src[3]!) & MASK;
  let x3 = ((src[4]! << 8) | src[5]!) & MASK;
  let x4 = ((src[6]! << 8) | src[7]!) & MASK;

  // Undo the output transform. It read x3 before x2, so this writes them back that way.
  let k = 48;
  const o1 = mul(x1, mulInverse(subkeys[k]!));
  const o3 = sub(x2, subkeys[k + 1]!);
  const o2 = sub(x3, subkeys[k + 2]!);
  const o4 = mul(x4, mulInverse(subkeys[k + 3]!));
  x1 = o1;
  x2 = o2;
  x3 = o3;
  x4 = o4;

  for (let round = 7; round >= 0; round--) {
    k = round * 6;
    /**
     * Named rather than assigned in place, because the forward round's exchange of the middle words
     * means slot 2 holds what was `x3` and slot 3 what was `x2`. Doing this with in-place assignment
     * and a leading swap is how the first version of this function went wrong: it computed the right
     * four values and left two of them in each other's slots, which round-trips to noise.
     */
    const y1 = x1;
    const y2 = x2;
    const y3 = x3;
    const y4 = x4;

    // `y1 ^ y2` is `x1' ^ x3'` and `y3 ^ y4` is `x2' ^ x4'`, which is what lets t0..t2 be recovered.
    const t0 = mul(y1 ^ y2, subkeys[k + 4]!);
    const t1 = mul(add(t0, y3 ^ y4), subkeys[k + 5]!);
    const t2 = add(t0, t1);

    const a1 = y1 ^ t1;
    const a3 = y2 ^ t1;
    const a2 = y3 ^ t2;
    const a4 = y4 ^ t2;

    x1 = mul(a1, mulInverse(subkeys[k]!));
    x2 = sub(a2, subkeys[k + 1]!);
    x3 = sub(a3, subkeys[k + 2]!);
    x4 = mul(a4, mulInverse(subkeys[k + 3]!));
  }

  const y = [x1, x2, x3, x4];
  for (let i = 0; i < 4; i++) {
    dst[2 * i] = (y[i]! >>> 8) & 0xff;
    dst[2 * i + 1] = y[i]! & 0xff;
  }
}

/** IDEA as a `BlockCipher`. The schedule is built once, here. */
export function createIdea(key: Uint8Array): BlockCipher {
  const subkeys = encryptionSubkeys(key);
  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => run(subkeys, src, dst),
    decryptBlock: (src, dst) => runInverse(subkeys, src, dst),
  };
}
