/**
 * CityHashCrc128 and CityHashCrc256 -- the two CityHash variants that use the CRC-32C *instruction* as
 * a mixing primitive.
 *
 * `not-a-mac`, like the rest of the family.
 *
 * **These are different functions from CityHash128, not faster implementations of it.** That is the
 * whole reason they are worth having and the whole reason they were left out for a while: `citycrc.h`
 * is guarded by `#ifdef __SSE4_2__`, so a reader can easily take it for a hardware-accelerated path to
 * the same answer. It is not. `_mm_crc32_u64` is used inside the compression loop as a nonlinear mix,
 * so the output has no relationship to CityHash128's -- and CityHash's own self-test checks them in
 * separate columns for exactly that reason.
 *
 * There is no CPU dependence here, unlike FarmHash's `Hash64`: `CityHashCrc*` is one function, merely
 * one that the reference only compiles when the instruction exists. Reproducing the instruction in
 * software gives the identical answer, which is what makes this offerable where FarmHash's dispatcher
 * is not.
 *
 * ## Three things to preserve
 *
 * **`PERMUTE3(a, b, c)` is `swap(a, b); swap(a, c)`, which is the rotation `(a, b, c) <- (c, a, b)`.**
 * Written as a destructuring assignment it is very easy to get the direction wrong, and the wrong
 * direction is still a permutation -- so the loop still runs, the output still looks random, and every
 * one of the 1,200 expected values is wrong. It cost one debugging cycle here; the check at the bottom
 * of this file's test asserts the direction directly rather than only through a digest.
 *
 * **`_mm_crc32_u64` is CRC-32C with no initial value and no final xor.** It is *not* the CRC-32C a
 * checksum tool computes: the instruction takes a running accumulator and returns the raw register, so
 * `crc32Word` below deliberately has neither of the `init`/`xorOut` steps that
 * `CRC_CATALOGUE`'s `CRC-32/ISCSI` model applies. Its table is nonetheless derived from that model's
 * own polynomial, so the 113 published check values behind the CRC family pin the polynomial here too.
 *
 * **Short inputs are zero-padded to 240 bytes and hashed with `~len` as the seed.** Not "hashed
 * directly with a shorter loop" -- the loop has a 240-byte minimum, so `CityHashCrc256` of a 5-byte
 * message is a 240-byte computation. That is why the 256-bit form is slow on short inputs and why it
 * has no short-circuit path at all.
 *
 * Verified against `city-test.cc`'s own `testdata` table: columns 7 to 10 for the two 128-bit forms and
 * 11 to 14 for the 256-bit one, over all 300 cases -- 1,800 values.
 */

import { cityhash128, cityhash128WithSeed } from "./cityhash";
import { crc32Word } from "./crc32c";

const MASK = (1n << 64n) - 1n;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const mul = (a: bigint, b: bigint): bigint => (a * b) & MASK;
const ror = (x: bigint, n: number): bigint =>
  n === 0 ? x : ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK;

const K0 = 0xc3a5c85c97cb3127n;
const KMUL = 0x9ddfea08eb382d69n;

const f64 = (s: Uint8Array, o: number): bigint => {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(s[o + i]!);
  return v;
};

const shiftMix = (v: bigint): bigint => v ^ (v >> 47n);

const hashLen16 = (u: bigint, v: bigint): bigint => {
  let a = mul(u ^ v, KMUL);
  a ^= a >> 47n;
  let b = mul(v ^ a, KMUL);
  b ^= b >> 47n;
  return mul(b, KMUL);
};

/** The 240-byte core. `result` is filled with four words. */
function crc256Long(s: Uint8Array, o: number, len: number, seed: bigint, result: bigint[]): void {
  let a = add(f64(s, o + 56), K0);
  let b = add(f64(s, o + 96), K0);
  let c = hashLen16(b, BigInt(len));
  result[0] = c;
  let d = add(mul(f64(s, o + 120), K0), BigInt(len));
  result[1] = d;
  let e = add(f64(s, o + 184), seed);
  let f = 0n;
  let g = 0n;
  let h = add(c, d);
  let x = seed;
  let y = 0n;
  let z = 0n;
  let p = o;
  let remaining = len;

  const chunk = (r: number): void => {
    // PERMUTE3(x, z, y). See the header: the rotation is (first, second, third) <- (third, first, second).
    [x, z, y] = [y, x, z];
    b = add(b, f64(s, p));
    c = add(c, f64(s, p + 8));
    d = add(d, f64(s, p + 16));
    e = add(e, f64(s, p + 24));
    f = add(f, f64(s, p + 32));
    a = add(a, b);
    h = add(h, f);
    b = add(b, c);
    f = add(f, d);
    g = add(g, e);
    e = add(e, z);
    g = add(g, x);
    z = crc32Word(z, add(b, g));
    y = crc32Word(y, add(e, h));
    x = crc32Word(x, add(f, a));
    e = ror(e, r);
    c = add(c, e);
    p += 40;
  };

  let iterations = Math.floor(remaining / 240);
  remaining -= iterations * 240;
  do {
    chunk(0);
    [a, h, c] = [c, a, h];
    chunk(33);
    [a, h, f] = [f, a, h];
    chunk(0);
    [b, h, f] = [f, b, h];
    chunk(42);
    [b, h, d] = [d, b, h];
    chunk(0);
    [b, h, e] = [e, b, h];
    chunk(33);
    [a, h, e] = [e, a, h];
  } while (--iterations > 0);

  while (remaining >= 40) {
    chunk(29);
    e ^= ror(a, 20);
    h = add(h, ror(b, 30));
    g ^= ror(c, 40);
    f = add(f, ror(d, 34));
    [c, h, g] = [g, c, h];
    remaining -= 40;
  }
  if (remaining > 0) {
    // Steps *back* to the last full 40 bytes, so the tail overlaps what the loop already read.
    p = p + remaining - 40;
    chunk(33);
    e ^= ror(a, 43);
    h = add(h, ror(b, 42));
    g ^= ror(c, 41);
    f = add(f, ror(d, 40));
  }
  result[0] = result[0]! ^ h;
  result[1] = result[1]! ^ g;
  g = add(g, h);
  a = hashLen16(a, add(g, z));
  x = add(x, (y << 32n) & MASK);
  b = add(b, x);
  c = add(hashLen16(c, z), h);
  d = hashLen16(d, add(e, result[0]!));
  g = add(g, e);
  h = add(h, hashLen16(x, f));
  e = add(hashLen16(a, d), g);
  z = add(hashLen16(b, c), a);
  y = add(hashLen16(g, h), c);
  result[0] = add(add(add(e, z), y), x);
  a = add(mul(shiftMix(mul(add(a, y), K0)), K0), b);
  result[1] = add(result[1]!, add(a, result[0]!));
  a = add(mul(shiftMix(mul(a, K0)), K0), c);
  result[2] = add(a, result[1]!);
  a = mul(shiftMix(mul(add(a, e), K0)), K0);
  result[3] = add(a, result[2]!);
}

/** CityHashCrc256: four 64-bit words. */
export function cityhashCrc256(s: Uint8Array, o = 0, len = s.length - o): bigint[] {
  const result: bigint[] = [0n, 0n, 0n, 0n];
  if (len >= 240) {
    crc256Long(s, o, len, 0n, result);
  } else {
    // Zero-padded to the loop's 240-byte minimum, seeded with ~len. See the header.
    const buffer = new Uint8Array(240);
    buffer.set(s.subarray(o, o + len));
    crc256Long(buffer, 0, 240, BigInt(~len >>> 0), result);
  }
  return result;
}

/** CityHashCrc128, as [low, high]. Below 900 bytes it *is* CityHash128. */
export function cityhashCrc128(s: Uint8Array, o = 0, len = s.length - o): [bigint, bigint] {
  if (len <= 900) return cityhash128(s, o, len);
  const result = cityhashCrc256(s, o, len);
  return [result[2]!, result[3]!];
}

/** CityHashCrc128WithSeed. Below 900 bytes it is CityHash128WithSeed. */
export function cityhashCrc128WithSeed(
  s: Uint8Array,
  o: number,
  len: number,
  seedLo: bigint,
  seedHi: bigint,
): [bigint, bigint] {
  if (len <= 900) return cityhash128WithSeed(s, o, len, seedLo, seedHi);
  const result = cityhashCrc256(s, o, len);
  const u = add(seedHi, result[0]!);
  const v = add(seedLo, result[1]!);
  return [hashLen16(u, add(v, result[2]!)), hashLen16(ror(v, 32), add(mul(u, K0), result[3]!))];
}

export type CityCrcLength = 16 | 32;

/**
 * The tool's entry point: 16 bytes for Crc128, 32 for Crc256.
 *
 * **Little-endian words, low word first** -- deliberately identical to `cityhash()`'s convention, and
 * that consistency is the point rather than a preference: the two tools sit side by side in the same
 * category, and someone comparing CityHash128 against CityHashCrc128 on the same input must not have to
 * reverse one of them first. `cityhashCrc128` returns `[low, high]` like `cityhash128`, so this writes
 * them in that order.
 */
export function cityhashCrc(outputLen: CityCrcLength, message: Uint8Array): Uint8Array {
  const words = outputLen === 16 ? cityhashCrc128(message, 0, message.length) : cityhashCrc256(message, 0, message.length);
  const out = new Uint8Array(outputLen);
  for (let w = 0; w < words.length; w++) {
    for (let i = 0; i < 8; i++) out[8 * w + i] = Number((words[w]! >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}
