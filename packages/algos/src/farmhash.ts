/**
 * FarmHash, at the three 64-bit namespaces its public entry point dispatches between: `na`, `uo` and
 * `xo` (Geoff Pike, Google, 2014). CityHash's successor, by CityHash's author.
 *
 * `not-a-mac`. The seed is not a key.
 *
 * ## The public `Hash64` is deliberately *not* offered, and that is the whole point of this file
 *
 * `farmhash::Hash64` **dispatches on CPU features**: on x86-64 with SSE4.2 and AES-NI it is one
 * function, without them another, and on 32-bit a third. So two machines hashing the same bytes with
 * the same library print different values. A tool whose purpose is reproducing a value somebody else
 * printed cannot be built on that -- which is why this repo left FarmHash out entirely for a long time.
 *
 * The resolution is that **the namespaces themselves are deterministic**, and FarmHash's own self-test
 * knows it: `farmhash.cc` checks `farmhashnaTest`, `farmhashuoTest`, `farmhashxoTest` and six others
 * individually rather than checking `Hash64`. Naming the namespace is therefore both reproducible and
 * what the reference itself verifies. `t1ha0` is absent from this repo for the identical reason and has
 * no equivalent escape, because its variants are not separately named in its API.
 *
 * ## The three, and how they relate
 *
 * - **`na`** is the direct CityHash64 descendant: a 64-byte main loop over five words, plus a
 *   *separate* final 64-byte block with its own multiplier. That trailing block is the difference from
 *   CityHash64, whose loop is uniform.
 * - **`uo`** ("optimised for unaligned"?) replaces the loop with one that reads all eight words up
 *   front and swaps `u` into `y` and then `z` mid-round -- two swaps per iteration, which is what makes
 *   it awkward to read and impossible to shorten. Under 64 bytes it delegates to `na`.
 * - **`xo`** is a dispatcher over length rather than CPU: `na`'s short paths up to 32, its own 33-to-64
 *   and 65-to-96 paths, `na` up to 256, and `uo` above that. So it is deterministic, unlike `Hash64`.
 *
 * ## What is shared with CityHash, and why that matters
 *
 * `HashLen0to16`, `HashLen17to32`, `ShiftMix`, `HashLen16` and `WeakHashLen32WithSeeds` are
 * byte-for-byte CityHash's, so they are imported from `cityhash.ts` rather than restated -- which means
 * CityHash's 300 published self-test values already pin them here. What differs and therefore what a
 * FarmHash failure would point at: `na`'s 33-to-64 path, its trailing block, all of `uo`'s loop, and
 * `xo`'s two middle paths.
 *
 * ## What stands behind it
 *
 * The reference's own self-test, reproduced exactly: 362 cases per namespace, each checking two or
 * three hash calls split into 32-bit halves -- 2172 values for `na` and `xo`, 1448 for `uo`, so 5,792
 * assertions in total. The harness is CityHash's 1 MB pseudorandom buffer, which this repo already
 * regenerates for CityHash, plus FarmHash's own `CreateSeed` and its **three-loop** driver: 299
 * quadratic cases, then a growth loop stepping `i += i / 7` to a megabyte, then the whole buffer. The
 * three-loop shape is why the count is 362 rather than CityHash's 300, and getting it wrong is the one
 * thing that would make every value line up against the wrong case.
 */

import {
  CITY_K0,
  CITY_K1,
  CITY_K2,
  cityHashLen0to16,
  cityHashLen16,
  cityHashLen16Mul,
  cityHashLen17to32,
  cityShiftMix,
  cityWeakHashLen32WithSeeds,
} from "./cityhash";

const MASK = (1n << 64n) - 1n;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const sub = (a: bigint, b: bigint): bigint => (a - b) & MASK;
const mul = (a: bigint, b: bigint): bigint => (a * b) & MASK;
const ror = (x: bigint, n: number): bigint =>
  n === 0 ? x : ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK;

const f64 = (s: Uint8Array, o: number): bigint => {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(s[o + i]!);
  return v;
};

export type FarmhashVariant = "na" | "uo" | "xo";

export const FARMHASH_VARIANTS: readonly { readonly id: FarmhashVariant; readonly label: string }[] = [
  { id: "na", label: "farmhashna" },
  { id: "uo", label: "farmhashuo" },
  { id: "xo", label: "farmhashxo" },
];

/** `na`'s 33-to-64 path, which is where it first departs from CityHash64. */
function naLen33to64(s: Uint8Array, o: number, len: number): bigint {
  const m = add(CITY_K2, BigInt(len) * 2n);
  const a = mul(f64(s, o), CITY_K2);
  const b = f64(s, o + 8);
  const c = mul(f64(s, o + len - 8), m);
  const d = mul(f64(s, o + len - 16), CITY_K2);
  const y = add(add(ror(add(a, b), 43), ror(c, 30)), d);
  const z = cityHashLen16Mul(y, add(add(a, ror(add(b, CITY_K2), 18)), c), m);
  const e = mul(f64(s, o + 16), m);
  const f = f64(s, o + 24);
  const g = mul(add(y, f64(s, o + len - 32)), m);
  const h = mul(add(z, f64(s, o + len - 24)), m);
  return cityHashLen16Mul(
    add(add(ror(add(e, f), 43), ror(g, 30)), h),
    add(add(e, ror(add(f, a), 18)), g),
    m,
  );
}

export function farmhashna(s: Uint8Array, o = 0, len = s.length - o): bigint {
  const seed = 81n;
  if (len <= 32) return len <= 16 ? cityHashLen0to16(s, o, len) : cityHashLen17to32(s, o, len);
  if (len <= 64) return naLen33to64(s, o, len);

  let x = seed;
  let y = add(mul(seed, CITY_K1), 113n);
  let z = mul(cityShiftMix(add(mul(y, CITY_K2), 113n)), CITY_K2);
  let v: [bigint, bigint] = [0n, 0n];
  let w: [bigint, bigint] = [0n, 0n];
  x = add(mul(x, CITY_K2), f64(s, o));

  const end = o + Math.floor((len - 1) / 64) * 64;
  const last64 = end + ((len - 1) & 63) - 63;
  let p = o;
  do {
    x = mul(ror(add(add(add(x, y), v[0]), f64(s, p + 8)), 37), CITY_K1);
    y = mul(ror(add(add(y, v[1]), f64(s, p + 48)), 42), CITY_K1);
    x ^= w[1];
    y = add(y, add(v[0], f64(s, p + 40)));
    z = mul(ror(add(z, w[0]), 33), CITY_K1);
    v = cityWeakHashLen32WithSeeds(s, p, mul(v[1], CITY_K1), add(x, w[0]));
    w = cityWeakHashLen32WithSeeds(s, p + 32, add(z, w[1]), add(y, f64(s, p + 16)));
    [z, x] = [x, z];
    p += 64;
  } while (p !== end);

  /**
   * The trailing block, which CityHash64 does not have.
   *
   * It re-reads the last 64 bytes -- overlapping whatever the loop already consumed -- under a
   * multiplier derived from the low byte of `z`, and folds the residual length into `w[0]`. Omitting it
   * gives a function that looks like CityHash64 and is neither.
   */
  const m = add(CITY_K1, (z & 0xffn) << 1n);
  p = last64;
  w[0] = add(w[0], BigInt((len - 1) & 63));
  v[0] = add(v[0], w[0]);
  w[0] = add(w[0], v[0]);
  x = mul(ror(add(add(add(x, y), v[0]), f64(s, p + 8)), 37), m);
  y = mul(ror(add(add(y, v[1]), f64(s, p + 48)), 42), m);
  x ^= mul(w[1], 9n);
  y = add(y, add(mul(v[0], 9n), f64(s, p + 40)));
  z = mul(ror(add(z, w[0]), 33), m);
  v = cityWeakHashLen32WithSeeds(s, p, mul(v[1], m), add(x, w[0]));
  w = cityWeakHashLen32WithSeeds(s, p + 32, add(z, w[1]), add(y, f64(s, p + 16)));
  [z, x] = [x, z];
  return cityHashLen16Mul(
    add(add(cityHashLen16Mul(v[0], w[0], m), mul(cityShiftMix(y), CITY_K0)), z),
    add(cityHashLen16Mul(v[1], w[1], m), x),
    m,
  );
}

export const farmhashnaWithSeeds = (
  s: Uint8Array,
  o: number,
  len: number,
  seed0: bigint,
  seed1: bigint,
): bigint => cityHashLen16(sub(farmhashna(s, o, len), seed0), seed1);

export const farmhashnaWithSeed = (s: Uint8Array, o: number, len: number, seed: bigint): bigint =>
  farmhashnaWithSeeds(s, o, len, CITY_K2, seed);

/** `uo`'s finaliser, which is a rotate-then-multiply rather than CityHash's shift-mix. */
const uoH = (x: bigint, y: bigint, m: bigint, r: number): bigint => {
  let a = mul(x ^ y, m);
  a ^= a >> 47n;
  const b = mul(y ^ a, m);
  return mul(ror(b, r), m);
};

export function farmhashuoWithSeeds(
  s: Uint8Array,
  o: number,
  len: number,
  seed0: bigint,
  seed1: bigint,
): bigint {
  if (len <= 64) return farmhashnaWithSeeds(s, o, len, seed0, seed1);

  let x = seed0;
  let y = add(mul(seed1, CITY_K2), 113n);
  let z = mul(cityShiftMix(mul(y, CITY_K2)), CITY_K2);
  let v: [bigint, bigint] = [seed0, seed1];
  let w: [bigint, bigint] = [0n, 0n];
  let u = sub(x, z);
  x = mul(x, CITY_K2);
  // The multiplier is fixed for the whole message here, unlike `na`, and `u & 0x82` is not a typo.
  const m = add(CITY_K2, u & 0x82n);

  const end = o + Math.floor((len - 1) / 64) * 64;
  const last64 = end + ((len - 1) & 63) - 63;
  let p = o;
  do {
    const a0 = f64(s, p);
    const a1 = f64(s, p + 8);
    const a2 = f64(s, p + 16);
    const a3 = f64(s, p + 24);
    const a4 = f64(s, p + 32);
    const a5 = f64(s, p + 40);
    const a6 = f64(s, p + 48);
    const a7 = f64(s, p + 56);
    x = add(x, add(a0, a1));
    y = add(y, a2);
    z = add(z, a3);
    v[0] = add(v[0], a4);
    v[1] = add(v[1], add(a5, a1));
    w[0] = add(w[0], a6);
    w[1] = add(w[1], a7);

    x = mul(ror(x, 26), 9n);
    y = ror(y, 29);
    z = mul(z, m);
    v[0] = ror(v[0], 33);
    v[1] = ror(v[1], 30);
    w[0] = mul(w[0] ^ x, 9n);
    z = add(ror(z, 32), w[1]);
    w[1] = add(w[1], z);
    z = mul(z, 9n);
    // Two swaps per iteration, on different variables. This is the first.
    [u, y] = [y, u];

    z = add(z, add(a0, a6));
    v[0] = add(v[0], a2);
    v[1] = add(v[1], a3);
    w[0] = add(w[0], a4);
    w[1] = add(w[1], add(a5, a6));
    x = add(x, a1);
    y = add(y, a7);

    y = add(y, v[0]);
    v[0] = add(v[0], sub(x, y));
    v[1] = add(v[1], w[0]);
    w[0] = add(w[0], v[1]);
    w[1] = add(w[1], sub(x, y));
    x = add(x, w[1]);
    w[1] = ror(w[1], 34);
    // And the second, on `z` rather than `y`.
    [u, z] = [z, u];
    p += 64;
  } while (p !== end);

  p = last64;
  u = mul(u, 9n);
  v[1] = ror(v[1], 28);
  v[0] = ror(v[0], 20);
  w[0] = add(w[0], BigInt((len - 1) & 63));
  u = add(u, y);
  y = add(y, u);
  x = mul(ror(add(add(sub(y, x), v[0]), f64(s, p + 8)), 37), m);
  y = mul(ror(y ^ v[1] ^ f64(s, p + 48), 42), m);
  x ^= mul(w[1], 9n);
  y = add(y, add(v[0], f64(s, p + 40)));
  z = mul(ror(add(z, w[0]), 33), m);
  v = cityWeakHashLen32WithSeeds(s, p, mul(v[1], m), add(x, w[0]));
  w = cityWeakHashLen32WithSeeds(s, p + 32, add(z, w[1]), add(y, f64(s, p + 16)));
  return uoH(
    sub(add(cityHashLen16Mul(add(v[0], x), w[0] ^ y, m), z), u),
    uoH(add(v[1], y), add(w[1], z), CITY_K2, 30) ^ x,
    CITY_K2,
    31,
  );
}

export const farmhashuoWithSeed = (s: Uint8Array, o: number, len: number, seed: bigint): bigint =>
  len <= 64 ? farmhashnaWithSeed(s, o, len, seed) : farmhashuoWithSeeds(s, o, len, 0n, seed);

export const farmhashuo = (s: Uint8Array, o = 0, len = s.length - o): bigint =>
  len <= 64 ? farmhashna(s, o, len) : farmhashuoWithSeeds(s, o, len, 81n, 0n);

/** `xo`'s 32-byte core, shared by its two middle paths. Note it ends on a shift-mix, not a multiply. */
function xoH32(
  s: Uint8Array,
  o: number,
  len: number,
  m: bigint,
  seed0 = 0n,
  seed1 = 0n,
): bigint {
  const a = mul(f64(s, o), CITY_K1);
  const b = f64(s, o + 8);
  const c = mul(f64(s, o + len - 8), m);
  const d = mul(f64(s, o + len - 16), CITY_K2);
  const u = add(add(add(ror(add(a, b), 43), ror(c, 30)), d), seed0);
  const v = add(add(add(a, ror(add(b, CITY_K2), 18)), c), seed1);
  const a2 = cityShiftMix(mul(u ^ v, m));
  return cityShiftMix(mul(v ^ a2, m));
}

export function farmhashxo(s: Uint8Array, o = 0, len = s.length - o): bigint {
  if (len <= 32) return len <= 16 ? cityHashLen0to16(s, o, len) : cityHashLen17to32(s, o, len);
  if (len <= 64) {
    // The two multipliers are `k2 - 30` and `k2 - 30 + 2 * len`. The 30 and the 114 below are the
    // only two magic offsets in the family and they are not derived from anything.
    const mul0 = sub(CITY_K2, 30n);
    const mul1 = add(sub(CITY_K2, 30n), BigInt(2 * len));
    const h0 = xoH32(s, o, 32, mul0);
    const h1 = xoH32(s, o + len - 32, 32, mul1);
    return mul(add(mul(h1, mul1), h0), mul1);
  }
  if (len <= 96) {
    const mul0 = sub(CITY_K2, 114n);
    const mul1 = add(sub(CITY_K2, 114n), BigInt(2 * len));
    const h0 = xoH32(s, o, 32, mul0);
    const h1 = xoH32(s, o + 32, 32, mul1);
    const h2 = xoH32(s, o + len - 32, 32, mul1, h0, h1);
    return mul(add(add(mul(h2, 9n), h0 >> 17n), h1 >> 21n), mul1);
  }
  if (len <= 256) return farmhashna(s, o, len);
  return farmhashuo(s, o, len);
}

export const farmhashxoWithSeeds = (
  s: Uint8Array,
  o: number,
  len: number,
  seed0: bigint,
  seed1: bigint,
): bigint => farmhashuoWithSeeds(s, o, len, seed0, seed1);

export const farmhashxoWithSeed = (s: Uint8Array, o: number, len: number, seed: bigint): bigint =>
  farmhashuoWithSeed(s, o, len, seed);

/**
 * The one entry point the tool uses: pick a namespace, optionally seed it.
 *
 * An **absent** seed means the namespace's unseeded `Hash64`, which is not the same function as
 * `Hash64WithSeed(0)` -- `na`'s seeded form is `HashLen16(Hash64 - k2, seed)`, so a zero seed still
 * folds `k2` in. The hash family's option layer leaves `seed64` undefined for an empty field precisely
 * so this distinction survives to here.
 */
export function farmhash(
  message: Uint8Array,
  variant: FarmhashVariant = "na",
  seed?: bigint,
): bigint {
  const len = message.length;
  switch (variant) {
    case "na":
      return seed === undefined ? farmhashna(message, 0, len) : farmhashnaWithSeed(message, 0, len, seed);
    case "uo":
      return seed === undefined ? farmhashuo(message, 0, len) : farmhashuoWithSeed(message, 0, len, seed);
    case "xo":
      return seed === undefined ? farmhashxo(message, 0, len) : farmhashxoWithSeed(message, 0, len, seed);
    default: {
      const never: never = variant;
      throw new Error(`FarmHash: unknown namespace "${String(never)}"`);
    }
  }
}

/** Eight bytes, most significant first. */
export function farmhashBytes(
  message: Uint8Array,
  variant: FarmhashVariant = "na",
  seed?: bigint,
): Uint8Array {
  const out = new Uint8Array(8);
  let value = farmhash(message, variant, seed);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}
