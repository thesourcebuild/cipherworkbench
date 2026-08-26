/**
 * HighwayHash, at 64, 128 and 256 bits. A keyed hash, not a MAC this repo will vouch for.
 *
 * Google's design: four 64-bit lanes, two of state and two of multiplier, updated per 32-byte packet by
 * a 32x32 multiply and a byte-permuting "zipper merge". It takes a **required 32-byte key**, which is
 * why it lives in the MAC family beside SipHash rather than with the non-cryptographic hashes -- and
 * why it carries the same `not-a-mac` posture: the authors present it as a strong PRF, no standards body
 * has adopted it, and this repo does not upgrade a claim on a designer's confidence alone.
 *
 * Four things to preserve.
 *
 * **The three widths differ in permutation rounds *and* in how the lanes are combined.** 64 bits is
 * four rounds and one sum; 128 is six rounds and two sums crossing v0 with v1; 256 is ten rounds and a
 * modular reduction over GF(2^256). They are not truncations of each other in any direction.
 *
 * **`UpdateRemainder` does three separate things before its final packet**, and dropping any one leaves
 * every length that is a multiple of 32 correct. It adds `(size_mod32 << 32) + size_mod32` into all
 * four v0 lanes; it rotates each of v1's eight *32-bit halves* left by `size_mod32`; and it assembles a
 * padded packet whose tail bytes go to offset 28 for remainders of 16 to 31 and offset 16 below that.
 *
 * **The under-16 tail is three bytes gathered out of order** -- first, middle, last -- exactly as
 * SpookyHash's short tail is, so a two-byte tail counts one byte twice. The 16-to-31 case is different
 * again: it reads the four bytes *ending* at the tail, which for a one-byte tail means three bytes from
 * before it.
 *
 * **Rotating by zero is not reachable, and would be undefined if it were.** `UpdateRemainder` is called
 * only when the remainder is non-zero, so `x >> (32 - count)` never shifts by 32. The guard is kept
 * anyway because in JavaScript that expression would silently produce a shift by zero rather than
 * failing.
 *
 * No oracle: HighwayHash is in no dependency here, and its reference is C++ with SIMD paths. What stands
 * behind it is the reference's own golden values, which its test file marks "HighwayHash is frozen, so
 * the golden values must not change" -- 65 per width, over the inputs `""`, `00`, `00 01`, ... up to 64
 * bytes, under the key `0x0706050403020100, 0x0F0E0D0C0B0A0908, 0x1716151413121110, 0x1F1E1D1C1B1A1918`.
 * 195 values covering both the packet boundary at 32 and every remainder.
 */

const MASK = (1n << 64n) - 1n;
const MASK32 = 0xffffffffn;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const rot64by32 = (x: bigint): bigint => ((x >> 32n) | (x << 32n)) & MASK;

/** The first 256 bits of pi's fractional part, in two halves -- the same constants Blowfish uses. */
const INIT0 = [0xdbe6d5d5fe4cce2fn, 0xa4093822299f31d0n, 0x13198a2e03707344n, 0x243f6a8885a308d3n];
const INIT1 = [0x3bd39e10cb0ef593n, 0xc0acf169b5f18a8cn, 0xbe5466cf34e90c6cn, 0x452821e638d01377n];

const byteAt = (v: bigint, index: number): bigint => v & (0xffn << BigInt(index * 8));

export type HighwayBits = 64 | 128 | 256;

/** The 32-byte key as four little-endian 64-bit words. */
export function highwayKeyWords(key: Uint8Array): bigint[] {
  if (key.length !== 32) throw new Error(`HighwayHash needs a 32-byte key, got ${key.length}`);
  const words: bigint[] = [];
  for (let w = 0; w < 4; w++) {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(key[8 * w + i]!);
    words.push(v);
  }
  return words;
}

/** An incremental HighwayHash at one width. */
export function createHighwayHash(
  key: Uint8Array,
  bits: HighwayBits,
): { update(chunk: Uint8Array): void; digest(): Uint8Array } {
  const k = highwayKeyWords(key);
  const v0: bigint[] = [];
  const v1: bigint[] = [];
  const mul0: bigint[] = [];
  const mul1: bigint[] = [];
  for (let i = 0; i < 4; i++) {
    mul0.push(INIT0[i]!);
    mul1.push(INIT1[i]!);
    v0.push(INIT0[i]! ^ k[i]!);
    v1.push(INIT1[i]! ^ rot64by32(k[i]!));
  }

  /** The zipper merge: a fixed byte permutation of two lanes, added into two others. */
  const zipperMergeAndAdd = (w1: bigint, w0: bigint, target: bigint[], i0: number, i1: number): void => {
    target[i1] = add(
      target[i1]!,
      ((byteAt(w1, 3) + byteAt(w0, 4)) >> 24n) +
        byteAt(w1, 2) +
        (byteAt(w1, 5) >> 16n) +
        ((byteAt(w1, 1) << 24n) & MASK) +
        (byteAt(w0, 6) >> 8n) +
        ((byteAt(w1, 0) << 48n) & MASK) +
        byteAt(w0, 7),
    );
    target[i0] = add(
      target[i0]!,
      ((byteAt(w0, 3) + byteAt(w1, 4)) >> 24n) +
        ((byteAt(w0, 5) + byteAt(w1, 6)) >> 16n) +
        byteAt(w0, 2) +
        ((byteAt(w0, 1) << 32n) & MASK) +
        (byteAt(w1, 7) >> 8n) +
        ((w0 << 56n) & MASK),
    );
  };

  const update = (lanes: readonly bigint[]): void => {
    for (let i = 0; i < 4; i++) v1[i] = add(add(v1[i]!, lanes[i]!), mul0[i]!);
    for (let i = 0; i < 4; i++) {
      mul0[i] = mul0[i]! ^ (((v1[i]! & MASK32) * (v0[i]! >> 32n)) & MASK);
      v0[i] = add(v0[i]!, mul1[i]!);
      mul1[i] = mul1[i]! ^ (((v0[i]! & MASK32) * (v1[i]! >> 32n)) & MASK);
    }
    // The merges read a snapshot: both pairs of a lane array are read before either is written.
    const a0 = v1[0]!, a1 = v1[1]!, a2 = v1[2]!, a3 = v1[3]!;
    zipperMergeAndAdd(a1, a0, v0, 0, 1);
    zipperMergeAndAdd(a3, a2, v0, 2, 3);
    const b0 = v0[0]!, b1 = v0[1]!, b2 = v0[2]!, b3 = v0[3]!;
    zipperMergeAndAdd(b1, b0, v1, 0, 1);
    zipperMergeAndAdd(b3, b2, v1, 2, 3);
  };

  const rd64 = (b: Uint8Array, o: number): bigint => {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]!);
    return v;
  };

  const updatePacket = (bytes: Uint8Array, off: number): void => {
    update([rd64(bytes, off), rd64(bytes, off + 8), rd64(bytes, off + 16), rd64(bytes, off + 24)]);
  };

  const updateRemainder = (bytes: Uint8Array, off: number, sizeMod32: number): void => {
    const pair = (BigInt(sizeMod32) << 32n) + BigInt(sizeMod32);
    for (let i = 0; i < 4; i++) v0[i] = add(v0[i]!, pair);
    const n = BigInt(sizeMod32);
    for (let i = 0; i < 4; i++) {
      const lo = v1[i]! & MASK32;
      const hi = v1[i]! >> 32n;
      const r = (x: bigint): bigint =>
        sizeMod32 === 0 ? x : ((x << n) | (x >> (32n - n))) & MASK32;
      v1[i] = (r(hi) << 32n) | r(lo);
    }
    const sizeMod4 = sizeMod32 & 3;
    const rem = off + (sizeMod32 & ~3);
    const packet = new Uint8Array(32);
    for (let i = 0; i < (sizeMod32 & ~3); i++) packet[i] = bytes[off + i]!;
    if (sizeMod32 & 16) {
      // 16..31 bytes left: the four bytes *ending* at the tail, placed at offset 28.
      let last4 = 0;
      for (let i = 3; i >= 0; i--) last4 = ((last4 << 8) | bytes[rem + sizeMod4 - 4 + i]!) >>> 0;
      for (let i = 0; i < 4; i++) packet[28 + i] = (last4 >>> (8 * i)) & 0xff;
    } else {
      // Under 16: three bytes gathered first-middle-last, placed at offset 16.
      let last3 = 0n;
      if (sizeMod4 !== 0) {
        last3 =
          BigInt(bytes[rem]!) +
          (BigInt(bytes[rem + (sizeMod4 >> 1)]!) << 8n) +
          (BigInt(bytes[rem + sizeMod4 - 1]!) << 16n);
      }
      for (let i = 0; i < 8; i++) packet[16 + i] = Number((last3 >> BigInt(8 * i)) & 0xffn);
    }
    updatePacket(packet, 0);
  };

  const permuteAndUpdate = (): void => {
    update([rot64by32(v0[2]!), rot64by32(v0[3]!), rot64by32(v0[0]!), rot64by32(v0[1]!)]);
  };

  const shift128Left = (a1: bigint, a0: bigint, shift: number): [bigint, bigint] => {
    const b = BigInt(shift);
    return [((a1 << b) | (a0 >> (64n - b))) & MASK, (a0 << b) & MASK];
  };

  /** Reduction modulo the GF(2^256) polynomial `x^256 + x^2 + x + 1`, for the 256-bit output. */
  const modularReduction = (a3u: bigint, a2: bigint, a1: bigint, a0: bigint): [bigint, bigint] => {
    const a3 = a3u & 0x3fffffffffffffffn;
    const [s1a, s1b] = shift128Left(a3, a2, 1);
    const [s2a, s2b] = shift128Left(a3, a2, 2);
    return [a0 ^ s1b ^ s2b, a1 ^ s1a ^ s2a];
  };

  const buf = new Uint8Array(32);
  let ptr = 0;

  return {
    update: (chunk) => {
      let off = 0;
      while (off < chunk.length) {
        const take = Math.min(32 - ptr, chunk.length - off);
        buf.set(chunk.subarray(off, off + take), ptr);
        off += take;
        ptr += take;
        if (ptr === 32) {
          updatePacket(buf, 0);
          ptr = 0;
        }
      }
    },
    digest: () => {
      if (ptr !== 0) updateRemainder(buf, 0, ptr);
      const rounds = bits === 64 ? 4 : bits === 128 ? 6 : 10;
      for (let n = 0; n < rounds; n++) permuteAndUpdate();
      let words: bigint[];
      if (bits === 64) {
        words = [add(add(v0[0]!, v1[0]!), add(mul0[0]!, mul1[0]!))];
      } else if (bits === 128) {
        words = [
          add(add(v0[0]!, mul0[0]!), add(v1[2]!, mul1[2]!)),
          add(add(v0[1]!, mul0[1]!), add(v1[3]!, mul1[3]!)),
        ];
      } else {
        const [m0, m1] = modularReduction(
          add(v1[1]!, mul1[1]!), add(v1[0]!, mul1[0]!),
          add(v0[1]!, mul0[1]!), add(v0[0]!, mul0[0]!),
        );
        const [m2, m3] = modularReduction(
          add(v1[3]!, mul1[3]!), add(v1[2]!, mul1[2]!),
          add(v0[3]!, mul0[3]!), add(v0[2]!, mul0[2]!),
        );
        words = [m0, m1, m2, m3];
      }
      const out = new Uint8Array(bits / 8);
      for (let w = 0; w < words.length; w++) {
        for (let i = 0; i < 8; i++) out[8 * w + i] = Number((words[w]! >> BigInt(8 * i)) & 0xffn);
      }
      return out;
    },
  };
}

/** HighwayHash of a whole message. */
export function highwayhash(key: Uint8Array, bits: HighwayBits, message: Uint8Array): Uint8Array {
  const h = createHighwayHash(key, bits);
  h.update(message);
  return h.digest();
}
