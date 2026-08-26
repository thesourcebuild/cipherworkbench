/**
 * CityHash, at 32, 64 and 128 bits. Non-cryptographic.
 *
 * Google's 2011 family, and the one whose *structure* is least like anything else here: rather than a
 * single loop over blocks it is a decision tree over the input length, with a separate hand-tuned
 * function for 0-16, 17-32, 33-64 and 65+ bytes. That is the point of the design -- short strings are
 * the common case in a hash table -- and it is also why the 300-case fixture matters so much: every one
 * of those length bands is a different function, and only a sweep reaches them all.
 *
 * Five things to preserve.
 *
 * **CityHash32 is entirely 32-bit arithmetic and needs `Math.imul` throughout.** Its multiplies are
 * `imul`, its byte swaps are 32-bit, and `Hash32Len0to4` reads each byte as a **signed** char before
 * widening -- so a byte of 0x80 contributes -128, not 128. Reading it unsigned is correct for every
 * ASCII input and wrong for binary, which is exactly the kind of bug a fixture over pseudorandom bytes
 * catches and a fixture over strings does not.
 *
 * **The 64- and 128-bit forms read from the *end* of the message as well as the start.** `x` comes from
 * `len - 40`, `y` from `len - 16` plus `len - 56`, and so on. Nothing here can stream: the tool buffers.
 *
 * **CityHash128's main loop runs two 64-byte halves per iteration and consumes 128 bytes.** Writing it
 * as a 64-byte loop over `len / 64` iterations gives the same answer only when the block count is even.
 *
 * **CityHash128's tail loop indexes backwards from the end** (`s + len - tail_done`), stepping 32 bytes
 * at a time while `len` here is the *residue* after the 128-byte loop, not the original length.
 *
 * **`CityHash128` of a message under 16 bytes seeds from constants; at 16 and above it consumes the
 * first sixteen bytes as the seed and hashes the rest.** So it is not `CityHash128WithSeed` of the whole
 * message under any seed.
 *
 * No oracle: CityHash is in no dependency here and OpenSSL never had it. What stands behind it is the
 * reference's own 300-case self-test -- a deterministic 1 MB pseudorandom buffer, hashed at offset
 * `i * i` for length `i` across `i = 0..298` and then once over the whole megabyte, checked at seven
 * values per case. 2,400 assertions.
 *
 * The `CityHashCrc*` variants are deliberately absent: they use the SSE4.2 CRC-32C instruction as a
 * mixing primitive, so they are different functions rather than faster ones -- the same reason
 * `metrohash128crc` is absent. FarmHash, CityHash's successor, is absent for a different and stronger
 * reason: its public `Hash64` dispatches on CPU features, so two machines give different answers for
 * the same input.
 */

const MASK = (1n << 64n) - 1n;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const sub = (a: bigint, b: bigint): bigint => (a - b) & MASK;
const mul = (a: bigint, b: bigint): bigint => (a * b) & MASK;
const ror = (x: bigint, n: number): bigint =>
  n === 0 ? x : ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK;
const bswap64 = (x: bigint): bigint => {
  let r = 0n;
  for (let i = 0; i < 8; i++) r = (r << 8n) | ((x >> BigInt(8 * i)) & 0xffn);
  return r;
};

const K0 = 0xc3a5c85c97cb3127n;
const K1 = 0xb492b66fbe98f273n;
const K2 = 0x9ae16a3b2f90404fn;
const C1 = 0xcc9e2d51;
const C2 = 0x1b873593;
const KMUL = 0x9ddfea08eb382d69n;

const f64 = (s: Uint8Array, o: number): bigint => {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(s[o + i]!);
  return v;
};
const f32 = (s: Uint8Array, o: number): number =>
  (s[o]! | (s[o + 1]! << 8) | (s[o + 2]! << 16) | (s[o + 3]! << 24)) >>> 0;

const shiftMix = (v: bigint): bigint => v ^ (v >> 47n);

const hashLen16 = (u: bigint, v: bigint): bigint => {
  let a = mul(u ^ v, KMUL);
  a ^= a >> 47n;
  let b = mul(v ^ a, KMUL);
  b ^= b >> 47n;
  return mul(b, KMUL);
};
const hashLen16m = (u: bigint, v: bigint, m: bigint): bigint => {
  let a = mul(u ^ v, m);
  a ^= a >> 47n;
  let b = mul(v ^ a, m);
  b ^= b >> 47n;
  return mul(b, m);
};

function hashLen0to16(s: Uint8Array, o: number, len: number): bigint {
  if (len >= 8) {
    const m = add(K2, BigInt(len) * 2n);
    const a = add(f64(s, o), K2);
    const b = f64(s, o + len - 8);
    return hashLen16m(add(mul(ror(b, 37), m), a), mul(add(ror(a, 25), b), m), m);
  }
  if (len >= 4) {
    const m = add(K2, BigInt(len) * 2n);
    const a = BigInt(f32(s, o));
    return hashLen16m(add(BigInt(len), (a << 3n) & MASK), BigInt(f32(s, o + len - 4)), m);
  }
  if (len > 0) {
    // First, middle, last -- the same three-byte gather SpookyHash and HighwayHash use.
    const y = BigInt(s[o]! + (s[o + (len >> 1)]! << 8));
    const z = BigInt(len + (s[o + len - 1]! << 2));
    return mul(shiftMix(mul(y, K2) ^ mul(z, K0)), K2);
  }
  return K2;
}

function hashLen17to32(s: Uint8Array, o: number, len: number): bigint {
  const m = add(K2, BigInt(len) * 2n);
  const a = mul(f64(s, o), K1);
  const b = f64(s, o + 8);
  const c = mul(f64(s, o + len - 8), m);
  const d = mul(f64(s, o + len - 16), K2);
  return hashLen16m(
    add(add(ror(add(a, b), 43), ror(c, 30)), d),
    add(add(a, ror(add(b, K2), 18)), c),
    m,
  );
}

function hashLen33to64(s: Uint8Array, o: number, len: number): bigint {
  const m = add(K2, BigInt(len) * 2n);
  const a0 = mul(f64(s, o), K2);
  const b = f64(s, o + 8);
  const c = f64(s, o + len - 24);
  const d = f64(s, o + len - 32);
  const e = mul(f64(s, o + 16), K2);
  const f = mul(f64(s, o + 24), 9n);
  const g = f64(s, o + len - 8);
  const h = mul(f64(s, o + len - 16), m);
  const u = add(ror(add(a0, g), 43), mul(add(ror(b, 30), c), 9n));
  const v = add(add(add(a0, g) ^ d, f), 1n);
  const w = add(bswap64(mul(add(u, v), m)), h);
  const x = add(ror(add(e, f), 42), c);
  const y = mul(add(bswap64(mul(add(v, w), m)), g), m);
  const z = add(add(e, f), c);
  const a = add(bswap64(add(mul(add(x, z), m), y)), b);
  return add(mul(shiftMix(add(add(mul(add(z, a), m), d), h)), m), x);
}

/** Four words and two seeds in, two words out. The one shared step of the long paths. */
const weak = (
  w: bigint, x: bigint, y: bigint, z: bigint, a0: bigint, b0: bigint,
): [bigint, bigint] => {
  let a = add(a0, w);
  let b = ror(add(add(b0, a), z), 21);
  const c = a;
  a = add(a, x);
  a = add(a, y);
  b = add(b, ror(a, 44));
  return [add(a, z), add(b, c)];
};
const weakAt = (s: Uint8Array, o: number, a: bigint, b: bigint): [bigint, bigint] =>
  weak(f64(s, o), f64(s, o + 8), f64(s, o + 16), f64(s, o + 24), a, b);

/**
 * The pieces FarmHash shares with CityHash **exactly**, exported for `farmhash.ts`.
 *
 * `farmhashna`'s `HashLen0to16`, `HashLen17to32`, `ShiftMix`, `HashLen16` and `WeakHashLen32WithSeeds`
 * are byte-for-byte CityHash's -- FarmHash was Geoff Pike's successor to his own CityHash and reuses
 * them verbatim. So exporting rather than re-declaring means CityHash's 300 published self-test values
 * already pin them for both, and a FarmHash failure points at what actually differs: its 33-to-64 path
 * and the extra final block in its main loop.
 *
 * Not exported: the u64 arithmetic helpers. Those are four one-line functions that FarmHash re-declares,
 * because sharing them would mean exporting `add`/`mul`/`ror` under CityHash's name from a module that
 * has nothing to do with either.
 */
export const CITY_K0 = K0;
export const CITY_K1 = K1;
export const CITY_K2 = K2;
export const cityShiftMix = shiftMix;
export const cityHashLen16 = hashLen16;
export const cityHashLen16Mul = hashLen16m;
export const cityWeakHashLen32WithSeeds = weakAt;
export const cityHashLen0to16 = (s: Uint8Array, o: number, len: number): bigint =>
  hashLen0to16(s, o, len);
export const cityHashLen17to32 = (s: Uint8Array, o: number, len: number): bigint =>
  hashLen17to32(s, o, len);

export function cityhash64(s: Uint8Array, o = 0, len = s.length - o): bigint {
  if (len <= 32) return len <= 16 ? hashLen0to16(s, o, len) : hashLen17to32(s, o, len);
  if (len <= 64) return hashLen33to64(s, o, len);
  let x = f64(s, o + len - 40);
  let y = add(f64(s, o + len - 16), f64(s, o + len - 56));
  let z = hashLen16(add(f64(s, o + len - 48), BigInt(len)), f64(s, o + len - 24));
  let v = weakAt(s, o + len - 64, BigInt(len), z);
  let w = weakAt(s, o + len - 32, add(y, K1), x);
  x = add(mul(x, K1), f64(s, o));
  let n = (len - 1) & ~63;
  let p = o;
  do {
    x = mul(ror(add(add(add(x, y), v[0]), f64(s, p + 8)), 37), K1);
    y = mul(ror(add(add(y, v[1]), f64(s, p + 48)), 42), K1);
    x ^= w[1];
    y = add(y, add(v[0], f64(s, p + 40)));
    z = mul(ror(add(z, w[0]), 33), K1);
    v = weakAt(s, p, mul(v[1], K1), add(x, w[0]));
    w = weakAt(s, p + 32, add(z, w[1]), add(y, f64(s, p + 16)));
    const t = z;
    z = x;
    x = t;
    p += 64;
    n -= 64;
  } while (n !== 0);
  return hashLen16(
    add(add(hashLen16(v[0], w[0]), mul(shiftMix(y), K1)), z),
    add(hashLen16(v[1], w[1]), x),
  );
}

export const cityhash64WithSeeds = (
  s: Uint8Array, o: number, len: number, seed0: bigint, seed1: bigint,
): bigint => hashLen16(sub(cityhash64(s, o, len), seed0), seed1);
export const cityhash64WithSeed = (s: Uint8Array, o: number, len: number, seed: bigint): bigint =>
  cityhash64WithSeeds(s, o, len, K2, seed);

function cityMurmur(
  s: Uint8Array, o: number, len: number, seedLo: bigint, seedHi: bigint,
): [bigint, bigint] {
  let a = seedLo;
  let b = seedHi;
  let c = 0n;
  let d = 0n;
  if (len <= 16) {
    a = mul(shiftMix(mul(a, K1)), K1);
    c = add(mul(b, K1), hashLen0to16(s, o, len));
    d = shiftMix(add(a, len >= 8 ? f64(s, o) : c));
  } else {
    c = hashLen16(add(f64(s, o + len - 8), K1), a);
    d = hashLen16(add(b, BigInt(len)), add(c, f64(s, o + len - 16)));
    a = add(a, d);
    let p = o;
    let n = len;
    do {
      a ^= mul(shiftMix(mul(f64(s, p), K1)), K1);
      a = mul(a, K1);
      b ^= a;
      c ^= mul(shiftMix(mul(f64(s, p + 8), K1)), K1);
      c = mul(c, K1);
      d ^= c;
      p += 16;
      n -= 16;
    } while (n > 16);
  }
  a = hashLen16(a, c);
  b = hashLen16(d, b);
  return [a ^ b, hashLen16(b, a)];
}

export function cityhash128WithSeed(
  s: Uint8Array, o: number, len: number, seedLo: bigint, seedHi: bigint,
): [bigint, bigint] {
  if (len < 128) return cityMurmur(s, o, len, seedLo, seedHi);
  let x = seedLo;
  let y = seedHi;
  let z = mul(BigInt(len), K1);
  let v: [bigint, bigint] = [0n, 0n];
  let w: [bigint, bigint] = [0n, 0n];
  v[0] = add(mul(ror(y ^ K1, 49), K1), f64(s, o));
  v[1] = add(mul(ror(v[0], 42), K1), f64(s, o + 8));
  w[0] = add(mul(ror(add(y, z), 35), K1), x);
  w[1] = mul(ror(add(x, f64(s, o + 88)), 53), K1);
  let p = o;
  let n = len;
  do {
    // Two 64-byte halves per iteration, consuming 128 bytes.
    for (let half = 0; half < 2; half++) {
      x = mul(ror(add(add(add(x, y), v[0]), f64(s, p + 8)), 37), K1);
      y = mul(ror(add(add(y, v[1]), f64(s, p + 48)), 42), K1);
      x ^= w[1];
      y = add(y, add(v[0], f64(s, p + 40)));
      z = mul(ror(add(z, w[0]), 33), K1);
      v = weakAt(s, p, mul(v[1], K1), add(x, w[0]));
      w = weakAt(s, p + 32, add(z, w[1]), add(y, f64(s, p + 16)));
      const t = z;
      z = x;
      x = t;
      p += 64;
    }
    n -= 128;
  } while (n >= 128);
  x = add(x, mul(ror(add(v[0], z), 49), K0));
  y = add(mul(y, K0), ror(w[1], 37));
  z = add(mul(z, K0), ror(w[0], 27));
  w[0] = mul(w[0], 9n);
  v[0] = mul(v[0], K0);
  // `n` is the residue, and the tail walks backwards from the end of it.
  for (let tailDone = 0; tailDone < n; ) {
    tailDone += 32;
    y = add(mul(ror(add(x, y), 42), K0), v[1]);
    w[0] = add(w[0], f64(s, p + n - tailDone + 16));
    x = add(mul(x, K0), w[0]);
    z = add(z, add(w[1], f64(s, p + n - tailDone)));
    w[1] = add(w[1], v[0]);
    v = weakAt(s, p + n - tailDone, add(v[0], z), v[1]);
    v[0] = mul(v[0], K0);
  }
  x = hashLen16(x, v[0]);
  y = hashLen16(add(y, z), w[0]);
  return [add(hashLen16(add(x, v[1]), w[1]), y), hashLen16(add(x, w[1]), add(y, v[1]))];
}

export const cityhash128 = (s: Uint8Array, o = 0, len = s.length - o): [bigint, bigint] =>
  len >= 16
    ? cityhash128WithSeed(s, o + 16, len - 16, f64(s, o), add(f64(s, o + 8), K0))
    : cityhash128WithSeed(s, o, len, K0, K1);

// ---- CityHash32: 32-bit arithmetic throughout ----

const rot32 = (v: number, n: number): number => (n === 0 ? v >>> 0 : ((v >>> n) | (v << (32 - n))) >>> 0);
const fmix = (h0: number): number => {
  let h = (h0 ^ (h0 >>> 16)) >>> 0;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h = (h ^ (h >>> 13)) >>> 0;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  return (h ^ (h >>> 16)) >>> 0;
};
const mur = (a0: number, h0: number): number => {
  let a = Math.imul(a0, C1) >>> 0;
  a = rot32(a, 17);
  a = Math.imul(a, C2) >>> 0;
  const h = rot32((h0 ^ a) >>> 0, 19);
  return (Math.imul(h, 5) + 0xe6546b64) >>> 0;
};
const bswap32 = (v: number): number =>
  (((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >>> 8) & 0xff00) | (v >>> 24)) >>> 0;

export function cityhash32(s: Uint8Array, o = 0, len = s.length - o): number {
  if (len <= 24) {
    if (len <= 4) {
      let b = 0;
      let c = 9;
      for (let i = 0; i < len; i++) {
        // The reference reads each byte as a *signed* char before widening.
        const v = (s[o + i]! << 24) >> 24;
        b = (Math.imul(b, C1) + v) >>> 0;
        c = (c ^ b) >>> 0;
      }
      return fmix(mur(b, mur(len, c)));
    }
    if (len <= 12) {
      let a = len >>> 0;
      let b = Math.imul(a, 5) >>> 0;
      const d = b;
      a = (a + f32(s, o)) >>> 0;
      b = (b + f32(s, o + len - 4)) >>> 0;
      const c = (9 + f32(s, o + ((len >> 1) & 4))) >>> 0;
      return fmix(mur(c, mur(b, mur(a, d))));
    }
    const a = f32(s, o - 4 + (len >> 1));
    const b = f32(s, o + 4);
    const c = f32(s, o + len - 8);
    const d = f32(s, o + (len >> 1));
    const e = f32(s, o);
    const f0 = f32(s, o + len - 4);
    return fmix(mur(f0, mur(e, mur(d, mur(c, mur(b, mur(a, len >>> 0)))))));
  }
  let h = len >>> 0;
  let g = Math.imul(C1, h) >>> 0;
  let f = g;
  const t = (x: number): number => Math.imul(rot32(Math.imul(x, C1) >>> 0, 17), C2) >>> 0;
  const step = (x: number): number => (Math.imul(rot32(x, 19), 5) + 0xe6546b64) >>> 0;
  h = step((h ^ t(f32(s, o + len - 4))) >>> 0);
  h = step((h ^ t(f32(s, o + len - 16))) >>> 0);
  g = step((g ^ t(f32(s, o + len - 8))) >>> 0);
  g = step((g ^ t(f32(s, o + len - 12))) >>> 0);
  f = step((f + t(f32(s, o + len - 20))) >>> 0);
  let iters = Math.floor((len - 1) / 20);
  let p = o;
  do {
    const b0 = t(f32(s, p));
    const b1 = f32(s, p + 4);
    const b2 = t(f32(s, p + 8));
    const b3 = t(f32(s, p + 12));
    const b4 = f32(s, p + 16);
    h = (h ^ b0) >>> 0;
    h = (Math.imul(rot32(h, 18), 5) + 0xe6546b64) >>> 0;
    f = (f + b1) >>> 0;
    f = Math.imul(rot32(f, 19), C1) >>> 0;
    g = (g + b2) >>> 0;
    g = (Math.imul(rot32(g, 18), 5) + 0xe6546b64) >>> 0;
    h = (h ^ ((b3 + b1) >>> 0)) >>> 0;
    h = (Math.imul(rot32(h, 19), 5) + 0xe6546b64) >>> 0;
    g = (g ^ b4) >>> 0;
    g = Math.imul(bswap32(g), 5) >>> 0;
    h = (h + (Math.imul(b4, 5) >>> 0)) >>> 0;
    h = bswap32(h);
    f = (f + b0) >>> 0;
    // PERMUTE3(f, h, g): swap(f, h) then swap(f, g).
    let tmp = f;
    f = h;
    h = tmp;
    tmp = f;
    f = g;
    g = tmp;
    p += 20;
  } while (--iters !== 0);
  g = Math.imul(rot32(g, 11), C1) >>> 0;
  g = Math.imul(rot32(g, 17), C1) >>> 0;
  f = Math.imul(rot32(f, 11), C1) >>> 0;
  f = Math.imul(rot32(f, 17), C1) >>> 0;
  h = rot32((h + g) >>> 0, 19);
  h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
  h = Math.imul(rot32(h, 17), C1) >>> 0;
  h = rot32((h + f) >>> 0, 19);
  h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
  return Math.imul(rot32(h, 17), C1) >>> 0;
}

export type CityLength = 4 | 8 | 16;

/** CityHash at 4, 8 or 16 bytes, little-endian. The three are unrelated functions. */
export function cityhash(outputLen: CityLength, message: Uint8Array): Uint8Array {
  if (outputLen === 4) {
    const v = cityhash32(message);
    return Uint8Array.from([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]);
  }
  const words = outputLen === 8 ? [cityhash64(message)] : cityhash128(message);
  const out = new Uint8Array(outputLen);
  for (let w = 0; w < words.length; w++) {
    for (let i = 0; i < 8; i++) out[8 * w + i] = Number((words[w]! >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}
