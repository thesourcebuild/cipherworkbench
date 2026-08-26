/**
 * t1ha -- "Fast Positive Hash" -- at t1ha1 (64-bit) and t1ha2 (64- and 128-bit). Non-cryptographic.
 *
 * Leonid Yuriev's family. Three registered functions from one file, because t1ha1 and t1ha2 share the
 * same seven primes, the same `mux64` primitive and the same four-word tail dispatch, and t1ha2's two
 * widths differ only in their tail pairing and their finaliser.
 *
 * Four things to preserve.
 *
 * **`mix64` and `mux64` are different, and confusing them is invisible at every length but zero.**
 * `mux64(v, p)` is the low and high halves of the full 128-bit product XORed; `mix64(v, p)` is
 * `x = v * p; x ^ rotr(x, 41)` -- an xor-mul-xor, no 128-bit product at all. t1ha1's finaliser uses
 * one of each. Substituting a mux for the mix gave a hash that failed all 81 reference values, and the
 * one that pointed at the cause was the empty message with a zero seed: the reference publishes 0 for
 * it, which only the real mix64 produces.
 *
 * **The 32-byte loop condition is `<` against `len - 31`, not `<=` against `len - 32`.** Both are the
 * same for lengths that are multiples of 32 and differ by one iteration otherwise. The reference walks
 * a `detent` pointer at `data + len - 31`.
 *
 * **`tail64` reads `len & 7` bytes -- or all eight when that is zero.** So a tail of exactly 8 reads a
 * whole word, and a tail of 9 to 16 reads one whole word plus `(len & 7)` bytes. The `len` handed to it
 * is the masked length, not the number of bytes left, which happens to give the right answer only
 * because the preceding fetches consumed whole words.
 *
 * **t1ha0 is deliberately not here.** It is a *dispatcher*: on a 64-bit machine without AES-NI it is
 * t1ha1, with AES-NI it is one of two different functions, and on 32-bit it is `t1ha0_32le`. A tool
 * whose answer depends on the CPU it ran on is the wrong thing to offer, which is the same reason
 * FarmHash is absent from this repo.
 *
 * No oracle: t1ha is in no dependency here. What stands behind it is the reference's own selfcheck --
 * 81 values per function over a fully specified schedule of (data, length, seed) triples: the empty
 * message at two seeds, a 64-byte pattern, then every length from 1 to 63 with a walking one-bit seed,
 * seven misaligned offsets, and eight long inputs from 128 to 247 bytes. 243 values in all.
 *
 * One coverage limit is worth naming: the reference checks only the *first* word of `t1ha2_atonce128`.
 * A fault confined to `*h = c + d` in the 128-bit finaliser would not show, since the low word is
 * `a ^ b`.
 */

const MASK = (1n << 64n) - 1n;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const sub = (a: bigint, b: bigint): bigint => (a - b) & MASK;
const mul = (a: bigint, b: bigint): bigint => (a * b) & MASK;
const not = (a: bigint): bigint => a ^ MASK;
const ror = (x: bigint, n: number): bigint => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK;

/** The seven primes both versions share. */
const P = [
  0xec99bf0d8372caabn, 0x82434fe90edcef39n, 0xd4f06db99d67be4bn, 0xbd9cacc22c6e9571n,
  0x9c06faf4d023e3abn, 0xc060724a8424f345n, 0xcb5af53ae3aaac31n,
] as const;

/** The low and high halves of the full 128-bit product, XORed together. */
const mux64 = (v: bigint, prime: bigint): bigint => {
  const r = v * prime;
  return (r & MASK) ^ (r >> 64n);
};
/** An xor-mul-xor mixer. NOT a mux64 -- see the header. */
const mix64 = (v: bigint, prime: bigint): bigint => {
  const x = mul(v, prime);
  return x ^ ror(x, 41);
};

const fetch64 = (b: Uint8Array, o: number): bigint => {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]!);
  return v;
};
/** The last `len & 7` bytes, little-endian -- or all eight when that is zero. */
const tail64 = (b: Uint8Array, o: number, len: number): bigint => {
  const n = (len & 7) === 0 ? 8 : len & 7;
  let v = 0n;
  for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]!);
  return v;
};

/** t1ha1, 64-bit. */
export function t1ha1(message: Uint8Array, seed = 0n): bigint {
  const len = message.length;
  let a = seed & MASK;
  let b = BigInt(len);
  let p = 0;
  let remaining = len;
  if (len > 32) {
    let c = add(ror(BigInt(len), 17), seed & MASK);
    let d = BigInt(len) ^ ror(seed & MASK, 17);
    do {
      const w0 = fetch64(message, p);
      const w1 = fetch64(message, p + 8);
      const w2 = fetch64(message, p + 16);
      const w3 = fetch64(message, p + 24);
      p += 32;
      const d02 = w0 ^ ror(add(w2, d), 17);
      const c13 = w1 ^ ror(add(w3, c), 17);
      d = sub(d, b ^ ror(w1, 31));
      c = add(c, a ^ ror(w0, 41));
      b ^= mul(P[0], add(c13, w2));
      a ^= mul(P[1], add(d02, w3));
    } while (p < len - 31);
    a ^= mul(P[6], add(ror(c, 17), d));
    b ^= mul(P[5], add(c, ror(d, 17)));
    remaining = len & 31;
  }
  const n = remaining;
  if (n >= 25) { b = add(b, mux64(fetch64(message, p), P[4])); p += 8; }
  if (n >= 17) { a = add(a, mux64(fetch64(message, p), P[3])); p += 8; }
  if (n >= 9) { b = add(b, mux64(fetch64(message, p), P[2])); p += 8; }
  if (n >= 1) a = add(a, mux64(tail64(message, p, n), P[1]));
  return add(mux64(ror(add(a, b), 17), P[4]), mix64(a ^ b, P[0]));
}

/** `*a ^= low((*b + v) * prime); *b += high(...)` -- the one primitive t1ha2 is built from. */
const mixup64 = (s: bigint[], ai: number, bi: number, v: bigint, prime: bigint): void => {
  const r = add(s[bi]!, v) * prime;
  s[ai] = s[ai]! ^ (r & MASK);
  s[bi] = add(s[bi]!, r >> 64n);
};

/** t1ha2's finaliser for the 64-bit form: two multiplies and a mux. */
const final64 = (a: bigint, b: bigint): bigint =>
  mux64(mul(add(a, ror(b, 41)), P[0]) ^ mul(add(ror(a, 23), b), P[6]), P[5]);

/** t1ha2's atonce and atonce128 share everything but their tail pairing and their finaliser. */
function t1ha2Core(message: Uint8Array, seed: bigint, wide: boolean): [bigint, bigint] {
  const len = message.length;
  const s = [seed & MASK, BigInt(len), 0n, 0n];
  if (wide || len > 32) {
    s[2] = add(ror(BigInt(len), 23), not(seed & MASK));
    s[3] = add(not(BigInt(len)), ror(seed & MASK, 19));
  }
  let p = 0;
  let remaining = len;
  if (len > 32) {
    do {
      const w0 = fetch64(message, p);
      const w1 = fetch64(message, p + 8);
      const w2 = fetch64(message, p + 16);
      const w3 = fetch64(message, p + 24);
      p += 32;
      const d02 = add(w0, ror(add(w2, s[3]!), 56));
      const c13 = add(w1, ror(add(w3, s[2]!), 19));
      s[3] = s[3]! ^ add(s[1]!, ror(w1, 38));
      s[2] = s[2]! ^ add(s[0]!, ror(w0, 57));
      s[1] = s[1]! ^ mul(P[6], add(c13, w2));
      s[0] = s[0]! ^ mul(P[5], add(d02, w3));
    } while (p < len - 31);
    if (!wide) {
      // The 64-bit form squashes c and d back into a and b; the 128-bit form keeps all four.
      s[0] = s[0]! ^ mul(P[6], add(s[2]!, ror(s[3]!, 23)));
      s[1] = s[1]! ^ mul(P[5], add(ror(s[2]!, 19), s[3]!));
    }
    remaining = len & 31;
  }
  const n = remaining;
  const pairs: readonly (readonly [number, number])[] = wide
    ? [[0, 3], [1, 0], [2, 1], [3, 2]]
    : [[0, 1], [1, 0], [0, 1], [1, 0]];
  if (n >= 25) { mixup64(s, pairs[0]![0], pairs[0]![1], fetch64(message, p), P[4]); p += 8; }
  if (n >= 17) { mixup64(s, pairs[1]![0], pairs[1]![1], fetch64(message, p), P[3]); p += 8; }
  if (n >= 9) { mixup64(s, pairs[2]![0], pairs[2]![1], fetch64(message, p), P[2]); p += 8; }
  if (n >= 1) mixup64(s, pairs[3]![0], pairs[3]![1], tail64(message, p, n), P[1]);

  if (!wide) return [final64(s[0]!, s[1]!), 0n];
  mixup64(s, 0, 1, ror(s[2]!, 41) ^ s[3]!, P[0]);
  mixup64(s, 1, 2, ror(s[3]!, 23) ^ s[0]!, P[6]);
  mixup64(s, 2, 3, ror(s[0]!, 19) ^ s[1]!, P[5]);
  mixup64(s, 3, 0, ror(s[1]!, 31) ^ s[2]!, P[4]);
  return [s[0]! ^ s[1]!, add(s[2]!, s[3]!)];
}

/** t1ha2, 64-bit (`t1ha2_atonce`). */
export const t1ha2 = (message: Uint8Array, seed = 0n): bigint => t1ha2Core(message, seed, false)[0];
/** t1ha2, 128-bit (`t1ha2_atonce128`). The low word first. */
export const t1ha2_128 = (message: Uint8Array, seed = 0n): [bigint, bigint] =>
  t1ha2Core(message, seed, true);

export type T1haVariant = "t1ha1" | "t1ha2" | "t1ha2-128";

/** t1ha at any of the three registered variants, little-endian. */
export function t1ha(variant: T1haVariant, message: Uint8Array, seed = 0n): Uint8Array {
  const words = variant === "t1ha2-128" ? t1ha2_128(message, seed)
    : [variant === "t1ha1" ? t1ha1(message, seed) : t1ha2(message, seed)];
  const out = new Uint8Array(words.length * 8);
  for (let w = 0; w < words.length; w++) {
    for (let i = 0; i < 8; i++) out[8 * w + i] = Number((words[w]! >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}
