/**
 * SpookyHash V2, at 32, 64 and 128 bits. Non-cryptographic.
 *
 * Bob Jenkins' 2012 design. One 128-bit computation underneath: `Hash64` is its first word and
 * `Hash32` the low half of that, so at little-endian output the three widths are genuine prefixes of
 * each other -- which is why the hash family's metadata marks it `truncation: true`, unusually for a
 * merged tool here.
 *
 * Two paths, and the boundary between them is the thing to get right. Under 192 bytes `Short` runs a
 * four-word state over 32-byte chunks; at 192 and above the full twelve-word `Mix` runs over 96-byte
 * blocks and `End` finalises with three passes of `EndPartial`. There is no length field: the *last
 * byte* of the final padded block holds the remainder, which is why a 96-byte message and a 96-byte
 * message padded with a zero byte differ.
 *
 * Three things worth knowing.
 *
 * **`Mix` and `EndPartial` are written here as loops over an index pattern, not as twelve longhand
 * lines.** The reference spells all twelve out; each is the same shape at rotating offsets
 * (`i`, `i+10`, `i+11`, `i+1` mod 12 for Mix; `i+11`, `i+1`, `i+2` for EndPartial), and the rotation
 * constants are the only per-step data. That derivation was checked against all 512 published values
 * rather than by eye.
 *
 * **The short path's tail is a plain little-endian read, not an out-of-order gather.** This is worth
 * stating because two of its neighbours in this repo do the opposite: HighwayHash's under-16 remainder
 * and CityHash's 1-to-3-byte case both take `p[0]`, `p[len>>1]` and `p[len-1]`, double-counting a byte
 * for a two-byte tail. SpookyHash's is the ordinary reading -- `p[0]`, `p[1] << 8`, `p[2] << 16`,
 * expressed upstream as a fall-through switch. Porting one family's gather into another's tail is
 * correct for every length that is a multiple of four and wrong for the other three, which is exactly
 * what a length-by-length fixture catches.
 *
 * **`ShortMix` and `ShortEnd` are different functions**, not one applied twice with different
 * constants: ShortMix rotates then adds then XORs, ShortEnd XORs then rotates then adds. Getting them
 * the same way round is self-consistent and matches nothing.
 *
 * No oracle: SpookyHash is in no dependency here. What stands behind it is the author's own 512
 * published `Hash32` values -- every message length from 0 to 511 over `buf[i] = i + 128`, with no
 * gaps, which crosses both the 192-byte path boundary and five 96-byte block boundaries.
 *
 * The coverage limit is worth stating rather than leaving implied: those 512 values pin the *low 32
 * bits of the first word*. A fault confined to the high half of word 0, or to word 1, would not show
 * -- the author published no `Hash128` vectors, and smhasher's numbers for the wider outputs are
 * derived verification codes rather than hashes of a stated input.
 */

const MASK = (1n << 64n) - 1n;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const rotl = (x: bigint, n: number): bigint => ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK;

const CONST = 0xdeadbeefdeadbeefn;
const NUM_VARS = 12;
const BLOCK = NUM_VARS * 8;
/** Under two blocks the short path runs instead. */
const SHORT_LIMIT = 2 * BLOCK;

const rd64 = (b: Uint8Array, o: number): bigint => {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]!);
  return v;
};
const rd32 = (b: Uint8Array, o: number): bigint =>
  BigInt((b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0);

/** (target, addend, xor-target, rotation) -- rotate, add, XOR. */
const SHORT_MIX: readonly (readonly [number, number, number, number])[] = [
  [2, 3, 0, 50], [3, 0, 1, 52], [0, 1, 2, 30], [1, 2, 3, 41],
  [2, 3, 0, 54], [3, 0, 1, 48], [0, 1, 2, 38], [1, 2, 3, 37],
  [2, 3, 0, 62], [3, 0, 1, 34], [0, 1, 2, 5], [1, 2, 3, 36],
];
/** (target, other, rotation) -- XOR, rotate, add. The opposite order from ShortMix. */
const SHORT_END: readonly (readonly [number, number, number])[] = [
  [3, 2, 15], [0, 3, 52], [1, 0, 26], [2, 1, 51], [3, 2, 28], [0, 3, 9],
  [1, 0, 47], [2, 1, 54], [3, 2, 32], [0, 3, 25], [1, 0, 63],
];

const MIX_ROT = [11, 32, 43, 31, 17, 28, 39, 57, 55, 54, 22, 46];
const END_ROT = [44, 15, 34, 21, 38, 33, 10, 13, 38, 53, 42, 54];

function shortMix(h: bigint[]): void {
  for (const [a, b, c, r] of SHORT_MIX) {
    h[a] = rotl(h[a]!, r);
    h[a] = add(h[a]!, h[b]!);
    h[c] = h[c]! ^ h[a]!;
  }
}

function shortEnd(h: bigint[]): void {
  for (const [a, b, r] of SHORT_END) {
    h[a] = h[a]! ^ h[b]!;
    h[b] = rotl(h[b]!, r);
    h[a] = add(h[a]!, h[b]!);
  }
}

function mix(s: bigint[], data: Uint8Array, off: number): void {
  for (let i = 0; i < 12; i++) {
    const c = (i + 11) % 12;
    s[i] = add(s[i]!, rd64(data, off + 8 * i));
    s[(i + 2) % 12] = s[(i + 2) % 12]! ^ s[(i + 10) % 12]!;
    s[c] = s[c]! ^ s[i]!;
    s[i] = rotl(s[i]!, MIX_ROT[i]!);
    s[c] = add(s[c]!, s[(i + 1) % 12]!);
  }
}

function endPartial(h: bigint[]): void {
  for (let i = 0; i < 12; i++) {
    const a = (i + 11) % 12;
    const b = (i + 1) % 12;
    h[a] = add(h[a]!, h[b]!);
    h[(i + 2) % 12] = h[(i + 2) % 12]! ^ h[a]!;
    h[b] = rotl(h[b]!, END_ROT[i]!);
  }
}

/** Under 192 bytes: a four-word state over 32-byte chunks, with a byte-gathering tail. */
function short(message: Uint8Array, h1: bigint, h2: bigint): [bigint, bigint] {
  const length = message.length;
  let p = 0;
  let remainder = length % 32;
  const h = [h1, h2, CONST, CONST];
  if (length > 15) {
    const whole = Math.floor(length / 32) * 32;
    for (; p < whole; p += 32) {
      h[2] = add(h[2]!, rd64(message, p));
      h[3] = add(h[3]!, rd64(message, p + 8));
      shortMix(h);
      h[0] = add(h[0]!, rd64(message, p + 16));
      h[1] = add(h[1]!, rd64(message, p + 24));
    }
    if (remainder >= 16) {
      h[2] = add(h[2]!, rd64(message, p));
      h[3] = add(h[3]!, rd64(message, p + 8));
      shortMix(h);
      p += 16;
      remainder -= 16;
    }
  }
  h[3] = add(h[3]!, BigInt(length) << 56n);
  const r = remainder;
  if (r >= 12) {
    if (r === 15) h[3] = add(h[3]!, BigInt(message[p + 14]!) << 48n);
    if (r >= 14) h[3] = add(h[3]!, BigInt(message[p + 13]!) << 40n);
    if (r >= 13) h[3] = add(h[3]!, BigInt(message[p + 12]!) << 32n);
    h[3] = add(h[3]!, rd32(message, p + 8));
    h[2] = add(h[2]!, rd64(message, p));
  } else if (r >= 8) {
    if (r === 11) h[3] = add(h[3]!, BigInt(message[p + 10]!) << 16n);
    if (r >= 10) h[3] = add(h[3]!, BigInt(message[p + 9]!) << 8n);
    if (r >= 9) h[3] = add(h[3]!, BigInt(message[p + 8]!));
    h[2] = add(h[2]!, rd64(message, p));
  } else if (r >= 4) {
    if (r === 7) h[2] = add(h[2]!, BigInt(message[p + 6]!) << 48n);
    if (r >= 6) h[2] = add(h[2]!, BigInt(message[p + 5]!) << 40n);
    if (r >= 5) h[2] = add(h[2]!, BigInt(message[p + 4]!) << 32n);
    h[2] = add(h[2]!, rd32(message, p));
  } else if (r >= 1) {
    // A plain little-endian read of the remaining one to three bytes -- see the header.
    if (r === 3) h[2] = add(h[2]!, BigInt(message[p + 2]!) << 16n);
    if (r >= 2) h[2] = add(h[2]!, BigInt(message[p + 1]!) << 8n);
    h[2] = add(h[2]!, BigInt(message[p]!));
  } else {
    h[2] = add(h[2]!, CONST);
    h[3] = add(h[3]!, CONST);
  }
  shortEnd(h);
  return [h[0]!, h[1]!];
}

/** SpookyHash V2's full 128-bit result, given two seed words. */
export function spookyhash128(message: Uint8Array, seed1: bigint, seed2: bigint): [bigint, bigint] {
  const length = message.length;
  if (length < SHORT_LIMIT) return short(message, seed1, seed2);
  const h: bigint[] = [];
  for (let i = 0; i < 12; i++) h.push(i % 3 === 0 ? seed1 : i % 3 === 1 ? seed2 : CONST);
  const blocks = Math.floor(length / BLOCK);
  let p = 0;
  for (let b = 0; b < blocks; b++, p += BLOCK) mix(h, message, p);
  const remainder = length - p;
  const buf = new Uint8Array(BLOCK);
  buf.set(message.subarray(p, p + remainder));
  // No length field: the last byte of the padded block is the remainder.
  buf[BLOCK - 1] = remainder;
  for (let i = 0; i < 12; i++) h[i] = add(h[i]!, rd64(buf, 8 * i));
  endPartial(h);
  endPartial(h);
  endPartial(h);
  return [h[0]!, h[1]!];
}

export const spookyhash64 = (message: Uint8Array, seed: bigint): bigint =>
  spookyhash128(message, seed, seed)[0];

export type SpookyLength = 4 | 8 | 16;

/**
 * SpookyHash at 4, 8 or 16 bytes, little-endian -- so the shorter outputs are prefixes of the longer.
 *
 * `Hash32` in the reference takes a 32-bit seed and widens it, which is the same thing as passing the
 * value here.
 */
export function spookyhash(outputLen: SpookyLength, message: Uint8Array, seed = 0n): Uint8Array {
  const [w0, w1] = spookyhash128(message, seed & MASK, seed & MASK);
  const out = new Uint8Array(outputLen);
  for (let i = 0; i < outputLen; i++) {
    const word = i < 8 ? w0 : w1;
    out[i] = Number((word >> BigInt(8 * (i % 8))) & 0xffn);
  }
  return out;
}
